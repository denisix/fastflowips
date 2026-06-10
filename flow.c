//go:build ignore

// flow.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

// Unified flow key: IPv6 addresses as-is, IPv4 as IPv4-mapped (::ffff:a.b.c.d).
// Network byte order, matching Go's net.IP layout.
struct flow_key {
    __u32 src[4];
    __u32 dst[4];
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

struct lpm_key6 {
    __u32 prefixlen;
    __u8 addr[16];
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
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 32768);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key6);
    __type(value, __u8);
} monitored_prefixes6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);  // Total configured networks v4+v6 (0 = disabled)
} network_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);  // Bitmap of IPv4 mask lengths in use
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
    return count_ptr ? *count_ptr : 0;
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

static __always_inline int is_ip6_monitored(const struct in6_addr *addr)
{
    __u32 count = get_network_count();
    if (count == 0)
        return 1;

    struct lpm_key6 key;
    key.prefixlen = 128;
    __builtin_memcpy(key.addr, addr, 16);

    __u8 *match = bpf_map_lookup_elem(&monitored_prefixes6, &key);
    return match != 0;
}

static __always_inline void update_flow(struct flow_key *k, int src_monitored,
                                        int dst_monitored, __u16 tot_len,
                                        int is_egress, __u64 now)
{
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_cnt, k);
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
        bpf_map_update_elem(&flow_cnt, k, &new_stats, BPF_ANY);
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
}

static __always_inline void set_v4_mapped(__u32 out[4], __u32 addr_be)
{
    out[0] = 0;
    out[1] = 0;
    out[2] = bpf_htonl(0x0000ffff);
    out[3] = addr_be;
}

static __always_inline int handle_ipv4(void *l3, void *data_end, int is_egress)
{
    struct iphdr *iph = l3;
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

    struct flow_key k;
    set_v4_mapped(k.src, src_ip);
    set_v4_mapped(k.dst, dst_ip);

    update_flow(&k, src_monitored, dst_monitored, tot_len, is_egress, now);

    return 0;
}

static __always_inline int handle_ipv6(void *l3, void *data_end, int is_egress)
{
    struct ipv6hdr *ip6h = l3;
    if ((void *)(ip6h + 1) > data_end)
        return 0;

    __u16 tot_len = __builtin_bswap16(ip6h->payload_len) + sizeof(struct ipv6hdr);

    __u64 now = bpf_ktime_get_ns();

    int src_monitored = is_ip6_monitored(&ip6h->saddr);
    int dst_monitored = is_ip6_monitored(&ip6h->daddr);

    if (!src_monitored && !dst_monitored)
        return 0;

    struct flow_key k;
    __builtin_memcpy(k.src, &ip6h->saddr, 16);
    __builtin_memcpy(k.dst, &ip6h->daddr, 16);

    update_flow(&k, src_monitored, dst_monitored, tot_len, is_egress, now);

    return 0;
}

static __always_inline int handle_frame(void *data, void *data_end, int is_egress)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto == __constant_htons(ETH_P_IP))
        return handle_ipv4((void *)(eth + 1), data_end, is_egress);
    if (eth->h_proto == __constant_htons(ETH_P_IPV6))
        return handle_ipv6((void *)(eth + 1), data_end, is_egress);

    return 0;
}

SEC("classifier")
int count_flows_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    handle_frame(data, data_end, 0);

    return BPF_OK; // TC_ACT_OK (0)
}

SEC("classifier")
int count_flows_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    handle_frame(data, data_end, 1);

    return BPF_OK; // TC_ACT_OK (0)
}

char _license[] SEC("license") = "GPL";
