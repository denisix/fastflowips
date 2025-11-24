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

static __always_inline int is_ip_in_networks(__u32 ip)
{
    __u32 count_key = 0;
    __u32 *count_ptr = bpf_map_lookup_elem(&network_count, &count_key);
    if (!count_ptr)
        return 0;

    __u32 count = *count_ptr;
    if (count == 0)
        return 1; // No networks configured = monitor all traffic
    if (count > 32)
        count = 32;

    int matched = 0;

#pragma unroll
    for (__u32 i = 0; i < 32; i++) {
        if (i >= count || matched)
            continue;

        struct network *net = bpf_map_lookup_elem(&monitored_networks, &i);
        if (net && (ip & net->mask) == net->addr)
            matched = 1;
    }
    return matched;
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

    int src_monitored = is_ip_in_networks(src_ip_host);
    int dst_monitored = is_ip_in_networks(dst_ip_host);

    if (!src_monitored && !dst_monitored)
        return 0; // Ignore flows outside configured networks

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
