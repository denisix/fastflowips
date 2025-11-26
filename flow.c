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

struct prefix_key {
    __u32 prefix;
    __u8 mask_bits;
    __u8 pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flow_cnt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct prefix_key);
    __type(value, __u8);
} monitored_prefixes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);  // Number of configured networks (0 = disabled)
} network_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);  // Bitmap of mask lengths in use
} mask_bitmap SEC(".maps");

#define BLOOM_WORDS 64
#define BLOOM_BITS  (BLOOM_WORDS * 32)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, BLOOM_WORDS);
    __type(key, __u32);
    __type(value, __u32);
} monitored_bloom SEC(".maps");

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

static __always_inline __u32 get_mask_bitmap(void)
{
    __u32 key = 0;
    __u32 *bitmap = bpf_map_lookup_elem(&mask_bitmap, &key);
    return bitmap ? *bitmap : 0;
}

static __always_inline __u32 mix_hash(__u32 value)
{
    value ^= value >> 16;
    value *= 0x7feb352d;
    value ^= value >> 15;
    value *= 0x846ca68b;
    value ^= value >> 16;
    return value;
}

static __always_inline int bloom_bit_set(__u32 bit_index)
{
    __u32 word_index = bit_index >> 5;
    __u32 bit_mask = 1u << (bit_index & 31);
    __u32 *word = bpf_map_lookup_elem(&monitored_bloom, &word_index);
    return word && (*word & bit_mask);
}

static __always_inline int bloom_might_contain(__u32 prefix, __u8 mask_bits)
{
    __u32 seed = ((__u32)mask_bits << 26) ^ prefix;
    __u32 h1 = mix_hash(seed ^ 0x9747b28c);
    __u32 h2 = mix_hash(seed ^ 0x9e3779b9);
    __u32 bit1 = h1 & (BLOOM_BITS - 1);
    __u32 bit2 = h2 & (BLOOM_BITS - 1);
    return bloom_bit_set(bit1) && bloom_bit_set(bit2);
}

static __always_inline __u32 mask_from_bits(__u32 bits)
{
    if (bits == 32)
        return 0xffffffff;
    return bits == 0 ? 0 : (~0u << (32 - bits));
}

static __always_inline int is_ip_monitored(__u32 ip_host)
{
    __u32 count = get_network_count();
    if (count == 0)
        return 1;

    __u32 bitmap = get_mask_bitmap();
    if (!bitmap)
        return 0;

#pragma unroll
    for (int i = 0; i < 32; i++) {
        if (!(bitmap & (1u << i)))
            continue;

        __u32 mask_bits = i + 1;
        __u32 mask = mask_from_bits(mask_bits);
        __u32 prefix = ip_host & mask;

        if (!bloom_might_contain(prefix, mask_bits))
            continue;

        struct prefix_key key = {
            .prefix = prefix,
            .mask_bits = (__u8)mask_bits,
        };

        __u8 *match = bpf_map_lookup_elem(&monitored_prefixes, &key);
        if (match)
            return 1;
    }

    return 0;
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

    int src_monitored = is_ip_monitored(src_ip_host);
    int dst_monitored = is_ip_monitored(dst_ip_host);

    if (!src_monitored && !dst_monitored)
        return 0;

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
