/* Observation only: every packet is returned as XDP_PASS. */
#ifdef BCC_BUILD
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#else
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#endif

struct flow_key {
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;
    __u8 protocol, pad[3];
};
struct flow_stats {
    __u64 pkt_cnt, byte_cnt, syn_cnt, first_seen_ns, last_seen_ns, last_export_ns;
    __u16 dst_ports[16];
    __u8 port_cnt, pad[7];
};
struct flow_event {
    struct flow_key key;
    struct flow_stats stats;
    __u64 export_ts_ns;
};
struct vlan_header { __u16 tci, proto; };
_Static_assert(sizeof(struct flow_event) == 112, "Python/C event ABI must match");

#ifdef BCC_BUILD
BPF_TABLE("lru_hash", struct flow_key, struct flow_stats, flow_stats_map, 65536);
BPF_RINGBUF_OUTPUT(events, 1024);
BPF_ARRAY(config_map, __u64, 8);
static __always_inline struct flow_stats *LOOKUP(struct flow_key *key) {
    return flow_stats_map.lookup(key);
}
static __always_inline void INSERT(struct flow_key *key, struct flow_stats *value) {
    flow_stats_map.insert(key, value);
}
static __always_inline __u64 *CONFIG(__u32 *key) { return config_map.lookup(key); }
static __always_inline struct flow_event *RESERVE(void) {
    return events.ringbuf_reserve(sizeof(struct flow_event));
}
static __always_inline void SUBMIT(struct flow_event *event) {
    events.ringbuf_submit(event, 0);
}
#else
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536);
    __type(key, struct flow_key); __type(value, struct flow_stats);
} flow_stats_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 8);
    __type(key, __u32); __type(value, __u64);
} config_map SEC(".maps");
#define LOOKUP(key) bpf_map_lookup_elem(&flow_stats_map, key)
#define INSERT(key, value) bpf_map_update_elem(&flow_stats_map, key, value, BPF_NOEXIST)
#define CONFIG(key) bpf_map_lookup_elem(&config_map, key)
#define RESERVE() bpf_ringbuf_reserve(&events, sizeof(struct flow_event), 0)
#define SUBMIT(event) bpf_ringbuf_submit(event, 0)
SEC("xdp")
#endif
int xdp_packet_handler(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    __u16 proto = __builtin_bswap16(eth->h_proto);
    void *cursor = eth + 1;
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto == 0x8100 || proto == 0x88a8) {
            struct vlan_header *vlan = cursor;
            if ((void *)(vlan + 1) > end) return XDP_PASS;
            proto = __builtin_bswap16(vlan->proto);
            cursor = vlan + 1;
        }
    }
    if (proto != ETH_P_IP) return XDP_PASS;
    struct iphdr *ip = cursor;
    if ((void *)(ip + 1) > end || ip->version != 4 || ip->ihl < 5) return XDP_PASS;
    if (__builtin_bswap16(ip->frag_off) & 0x3fff) return XDP_PASS;
    cursor = (void *)ip + ip->ihl * 4;
    if (cursor > end) return XDP_PASS;
    struct flow_key key = {};
    key.src_ip = ip->saddr; key.dst_ip = ip->daddr; key.protocol = ip->protocol;
    __u64 syn = 0;
    if (ip->protocol == 6) {
        struct tcphdr *tcp = cursor;
        if ((void *)(tcp + 1) > end || tcp->doff < 5) return XDP_PASS;
        if ((void *)tcp + tcp->doff * 4 > end) return XDP_PASS;
        key.src_port = __builtin_bswap16(tcp->source);
        key.dst_port = __builtin_bswap16(tcp->dest);
        syn = tcp->syn && !tcp->ack;
    } else if (ip->protocol == 17) {
        struct udphdr *udp = cursor;
        if ((void *)(udp + 1) > end) return XDP_PASS;
        key.src_port = __builtin_bswap16(udp->source);
        key.dst_port = __builtin_bswap16(udp->dest);
    } else return XDP_PASS;
    __u64 now = bpf_ktime_get_ns();
    struct flow_stats *stats = LOOKUP(&key);
    if (!stats) {
        struct flow_stats initial = {};
        initial.first_seen_ns = now;
        initial.dst_ports[0] = key.dst_port;
        initial.port_cnt = 1; /* 5-tuple has one destination port; source entropy lives in Collector. */
        INSERT(&key, &initial);
        stats = LOOKUP(&key);
        if (!stats) return XDP_PASS;
    }
    __sync_fetch_and_add(&stats->pkt_cnt, 1);
    __sync_fetch_and_add(&stats->byte_cnt, (__u64)(end - data));
    if (syn) __sync_fetch_and_add(&stats->syn_cnt, 1);
    stats->last_seen_ns = now;
    __u32 zero = 0;
    __u64 *configured = CONFIG(&zero);
    __u64 interval = configured && *configured ? *configured : 100000000;
    if (!stats->last_export_ns || now - stats->last_export_ns >= interval) {
        struct flow_event *event = RESERVE();
        if (event) {
            event->key = key; event->stats = *stats; event->export_ts_ns = now;
            SUBMIT(event);
            stats->last_export_ns = now;
        }
    }
    return XDP_PASS;
}
#ifndef BCC_BUILD
char LICENSE[] SEC("license") = "GPL";
#endif
