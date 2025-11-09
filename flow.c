// flow.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
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
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flow_cnt SEC(".maps");

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

    struct flow_key k = {
        .src = iph->saddr,
        .dst = iph->daddr,
    };

    struct flow_stats *stats = bpf_map_lookup_elem(&flow_cnt, &k);
    if (!stats) {
        struct flow_stats new_stats = {0};
        if (is_egress) {
            new_stats.packets_tx = 1;
            new_stats.bytes_tx = tot_len;
        } else {
            new_stats.packets_rx = 1;
            new_stats.bytes_rx = tot_len;
        }
        new_stats.last_seen = now;
        bpf_map_update_elem(&flow_cnt, &k, &new_stats, BPF_ANY);
    } else {
        if (is_egress) {
            __sync_fetch_and_add(&stats->packets_tx, 1);
            __sync_fetch_and_add(&stats->bytes_tx, tot_len);
        } else {
            __sync_fetch_and_add(&stats->packets_rx, 1);
            __sync_fetch_and_add(&stats->bytes_rx, tot_len);
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

