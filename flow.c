// flow.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct flow_key {
    __u32 src;
    __u32 dst;
};

struct flow_stats {
    __u64 packets_rx;
    __u64 packets_tx;
    __u64 bytes_rx;
    __u64 bytes_tx;
    __u64 last_seen;
    __u8 src_monitored;
    __u8 dst_monitored;
    __u8 pad[6];
};

struct network {
    __u32 addr;
    __u32 mask;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flow_cnt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);  // Support up to 32 networks
    __type(key, __u32);
    __type(value, struct network);
} monitored_networks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);  // Number of configured networks (0 = disabled)
} network_count SEC(".maps");

static __always_inline __u32 get_network_count(void)
{
    __u32 count_key = 0;
    __u32 *count_ptr = bpf_map_lookup_elem(&network_count, &count_key);
    if (!count_ptr)
        return 0;

    __u32 count = *count_ptr;
    if (count > 32)
        count = 32;
    return count;
}

static __always_inline void match_ips_to_networks(__u32 src_ip, __u32 dst_ip,
                                                 __u32 count,
                                                 int *src_monitored,
                                                 int *dst_monitored)
{
    int src_match = 0;
    int dst_match = 0;

#define CHECK_NETWORK(idx)                                                     \
    do {                                                                       \
        if ((src_match == 0 || dst_match == 0) && count > (idx)) {              \
            __u32 key = (idx);                                                 \
            struct network *net = bpf_map_lookup_elem(&monitored_networks, &key); \
            if (net) {                                                         \
                __u32 mask = net->mask;                                        \
                __u32 addr = net->addr;                                        \
                if (!src_match && (src_ip & mask) == addr)                     \
                    src_match = 1;                                             \
                if (!dst_match && (dst_ip & mask) == addr)                     \
                    dst_match = 1;                                             \
            }                                                                  \
        }                                                                      \
    } while (0)

    CHECK_NETWORK(0);
    CHECK_NETWORK(1);
    CHECK_NETWORK(2);
    CHECK_NETWORK(3);
    CHECK_NETWORK(4);
    CHECK_NETWORK(5);
    CHECK_NETWORK(6);
    CHECK_NETWORK(7);
    CHECK_NETWORK(8);
    CHECK_NETWORK(9);
    CHECK_NETWORK(10);
    CHECK_NETWORK(11);
    CHECK_NETWORK(12);
    CHECK_NETWORK(13);
    CHECK_NETWORK(14);
    CHECK_NETWORK(15);
    CHECK_NETWORK(16);
    CHECK_NETWORK(17);
    CHECK_NETWORK(18);
    CHECK_NETWORK(19);
    CHECK_NETWORK(20);
    CHECK_NETWORK(21);
    CHECK_NETWORK(22);
    CHECK_NETWORK(23);
    CHECK_NETWORK(24);
    CHECK_NETWORK(25);
    CHECK_NETWORK(26);
    CHECK_NETWORK(27);
    CHECK_NETWORK(28);
    CHECK_NETWORK(29);
    CHECK_NETWORK(30);
    CHECK_NETWORK(31);

#undef CHECK_NETWORK

    *src_monitored = src_match;
    *dst_monitored = dst_match;
}

static __always_inline int handle_ipv4(void *data, void *data_end, int is_egress)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;

    __u16 tot_len = __builtin_bswap16(iph->tot_len);

    __u64 now = bpf_ktime_get_ns();

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u32 src_ip_host = bpf_ntohl(src_ip);
    __u32 dst_ip_host = bpf_ntohl(dst_ip);

    __u32 monitored_count = get_network_count();
    int src_monitored = 1;
    int dst_monitored = 1;

    if (monitored_count != 0) {
        src_monitored = 0;
        dst_monitored = 0;
        match_ips_to_networks(src_ip_host, dst_ip_host, monitored_count,
                              &src_monitored, &dst_monitored);
        if (!src_monitored && !dst_monitored)
            return 0; // Ignore flows outside configured networks
    }

    struct flow_key k = {
        .src = src_ip,
        .dst = dst_ip,
    };

    struct flow_stats *stats = bpf_map_lookup_elem(&flow_cnt, &k);
    if (!stats) {
        struct flow_stats new_stats = {0};

        // Persist network membership flags for user space consumers
        new_stats.src_monitored = (__u8)src_monitored;
        new_stats.dst_monitored = (__u8)dst_monitored;

        // Determine correct RX/TX based on monitored network perspective
        if (src_monitored && !dst_monitored) {
            // Internal->External: TX from internal perspective
            new_stats.packets_tx = 1;
            new_stats.bytes_tx = tot_len;
        } else if (!src_monitored && dst_monitored) {
            // External->Internal: RX to internal perspective
            new_stats.packets_rx = 1;
            new_stats.bytes_rx = tot_len;
        } else {
            // Default: use interface direction
            if (is_egress) {
                new_stats.packets_tx = 1;
                new_stats.bytes_tx = tot_len;
            } else {
                new_stats.packets_rx = 1;
                new_stats.bytes_rx = tot_len;
            }
        }
        new_stats.last_seen = now;
        bpf_map_update_elem(&flow_cnt, &k, &new_stats, BPF_ANY);
    } else {
        // Update existing flow and refresh membership flags in case configuration changed
        stats->src_monitored = (__u8)src_monitored;
        stats->dst_monitored = (__u8)dst_monitored;
        if (src_monitored && !dst_monitored) {
            // Internal->External: TX
            __sync_fetch_and_add(&stats->packets_tx, 1);
            __sync_fetch_and_add(&stats->bytes_tx, tot_len);
        } else if (!src_monitored && dst_monitored) {
            // External->Internal: RX
            __sync_fetch_and_add(&stats->packets_rx, 1);
            __sync_fetch_and_add(&stats->bytes_rx, tot_len);
        } else {
            // Default: use interface direction
            if (is_egress) {
                __sync_fetch_and_add(&stats->packets_tx, 1);
                __sync_fetch_and_add(&stats->bytes_tx, tot_len);
            } else {
                __sync_fetch_and_add(&stats->packets_rx, 1);
                __sync_fetch_and_add(&stats->bytes_rx, tot_len);
            }
        }
        stats->last_seen = now;
    }

    return 0;
}

SEC("classifier")
int count_flows_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    handle_ipv4(data, data_end, 0);

    return BPF_OK; // TC_ACT_OK (0)
}

SEC("classifier")
int count_flows_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    handle_ipv4(data, data_end, 1);

    return BPF_OK; // TC_ACT_OK (0)
}

char _license[] SEC("license") = "GPL";
