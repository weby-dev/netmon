// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_monitor.bpf.c - XDP flow-monitoring data path.
 *
 * Responsibilities (all in the kernel fast path):
 *   - Parse Ethernet (+ up to 2 VLAN tags) / IPv4 / IPv6 / TCP / UDP / ICMP.
 *   - Maintain a 5-tuple flow table (LRU hash) with packet/byte counters,
 *     first/last timestamps and accumulated TCP flags.
 *   - Maintain per-interface and global counters (interface utilisation).
 *   - Sample the first few packets of L7-interesting flows (HTTP/TLS/DNS/SMTP/
 *     DB ports) into a ring buffer for userspace deep-packet-inspection.
 *   - Optional inline DDoS mitigation: drop sources present in blocklist_map.
 *
 * The program returns XDP_PASS for everything (pure monitoring) except for
 * sources explicitly blocklisted by userspace, which are XDP_DROP'd.
 *
 * Build target: Linux kernel >= 5.18 (needs ring buffer + bpf_xdp_load_bytes).
 * Proxmox VE 8 ships 6.x kernels, which satisfy this.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#define NETMON_BPF 1          /* tell common.h not to pull <linux/types.h> */
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* ------------------------------------------------------------------ maps -- */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct nm_flow_stats);
} flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, __STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} global_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IFACES);
    __type(key, __u32);              /* ifindex */
    __type(value, struct if_stats);
} if_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, L7_RINGBUF_SIZE);
} l7_events SEC(".maps");

/* Userspace inserts a source IPv4 here (value 1) to have it dropped inline. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BLOCKLIST_MAX);
    __type(key, __u32);              /* source IPv4, network byte order */
    __type(value, __u8);
} blocklist_map SEC(".maps");

/* ------------------------------------------------------------- helpers --- */

static __always_inline void stat_inc(__u32 slot, __u64 delta)
{
    __u64 *v = bpf_map_lookup_elem(&global_stats, &slot);
    if (v)
        *v += delta;          /* per-CPU: no atomics needed */
}

static __always_inline void if_account(__u32 ifindex, __u64 bytes)
{
    struct if_stats *st = bpf_map_lookup_elem(&if_stats_map, &ifindex);
    if (st) {
        __sync_fetch_and_add(&st->rx_packets, 1);
        __sync_fetch_and_add(&st->rx_bytes, bytes);
    } else {
        struct if_stats init = { .rx_packets = 1, .rx_bytes = bytes };
        bpf_map_update_elem(&if_stats_map, &ifindex, &init, BPF_NOEXIST);
    }
}

/* Returns 1 if the port pair looks like an L7 protocol we want to sample. */
static __always_inline __u8 l7_hint_for(__u8 proto, __u16 sport, __u16 dport)
{
    __u16 s = bpf_ntohs(sport);
    __u16 d = bpf_ntohs(dport);

    if (proto == IPPROTO_UDP) {
        if (s == 53 || d == 53)
            return L7_DNS;
        return L7_UNKNOWN;
    }
    if (proto != IPPROTO_TCP)
        return L7_UNKNOWN;

    if (s == 80 || d == 80 || s == 8080 || d == 8080)
        return L7_HTTP;
    if (s == 443 || d == 443 || s == 8443 || d == 8443)
        return L7_TLS;
    if (s == 53 || d == 53)
        return L7_DNS;
    if (s == 25 || d == 25 || s == 587 || d == 587 || s == 465 || d == 465)
        return L7_SMTP;
    /* mysql 3306, postgres 5432, mongo 27017, redis 6379, mssql 1433 */
    if (d == 3306 || s == 3306 || d == 5432 || s == 5432 ||
        d == 27017 || s == 27017 || d == 6379 || s == 6379 ||
        d == 1433 || s == 1433)
        return L7_DB;

    return L7_UNKNOWN;
}

/*
 * Sample up to L7_SNAP_LEN payload bytes from the packet into the ring buffer.
 * `l4_off` is the byte offset of the L4 header from the start of the packet;
 * `l4_hdr_len` is the L4 header length (so payload begins at l4_off+l4_hdr_len).
 */
static __always_inline void
sample_l7(struct xdp_md *ctx, const struct flow_key *key, __u8 hint,
          __u32 l4_off, __u32 l4_hdr_len, __u64 now)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    __u32 payload_off = l4_off + l4_hdr_len;
    __u64 total       = (__u64)(data_end - data);
    if (payload_off >= total)
        return;                                 /* no payload */

    /* Compute the capture length, clamped to [1, L7_SNAP_LEN-1], in a form the
     * verifier accepts as the size arg to bpf_xdp_load_bytes(), which requires
     * smin >= 0 AND umin >= 1 AND umax <= the destination size.
     *
     * The naive forms both fail: a bitmask leaves the value as a tnum
     * (0; 0xff) whose umin stays 0 ("invalid zero-sized read"), and a plain
     * `if (len == 0) return;` does NOT raise umin for such a value (the
     * verifier only tightens umin/umax on unsigned >/< against a constant, and
     * the compiler folds `>= 1` into `!= 0`). So we bound (len - 1) against a
     * NON-zero constant (kept as JGT, honored by the verifier), then add 1
     * back: the +1 shifts the tracked minimum from 0 to 1. payload_off < total
     * here, so avail >= 1 at runtime and the (avail - 1) underflow branch is
     * never actually taken. */
    __u64 avail = total - (__u64)payload_off;        /* >= 1 at runtime       */
    __u64 capm1 = avail - 1;                          /* capture length - 1    */
    if (capm1 > (L7_SNAP_LEN - 2))                    /* JGT 254 -> [0, 254]   */
        capm1 = (L7_SNAP_LEN - 2);
    __u32 caplen = (__u32)capm1 + 1;                  /* [1, L7_SNAP_LEN-1]    */

    struct l7_event *e = bpf_ringbuf_reserve(&l7_events, sizeof(*e), 0);
    if (!e)
        return;

    e->ts_ns    = now;
    __builtin_memcpy(e->src_addr, key->src_addr, 16);
    __builtin_memcpy(e->dst_addr, key->dst_addr, 16);
    e->src_port = key->src_port;
    e->dst_port = key->dst_port;
    e->ifindex  = key->ifindex;
    e->family   = key->family;
    e->protocol = key->protocol;
    e->l7_hint  = hint;
    e->_pad     = 0;

    if (bpf_xdp_load_bytes(ctx, payload_off, e->payload, caplen) != 0) {
        bpf_ringbuf_discard(e, 0);
        return;
    }
    e->payload_len = (__u16)caplen;
    bpf_ringbuf_submit(e, 0);
    stat_inc(STAT_L7_SAMPLED, 1);
}

/* ------------------------------------------------------------- program --- */

SEC("xdp")
int xdp_monitor(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now      = bpf_ktime_get_ns();
    __u32 ifindex  = ctx->ingress_ifindex;
    __u64 pkt_len  = (__u64)(data_end - data);

    stat_inc(STAT_TOTAL_PKTS, 1);
    stat_inc(STAT_TOTAL_BYTES, pkt_len);
    if_account(ifindex, pkt_len);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    void *cursor  = (void *)(eth + 1);

    /* Strip up to two VLAN tags (QinQ). */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) ||
            h_proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr {
                __be16 h_vlan_TCI;
                __be16 h_vlan_encapsulated_proto;
            } *vh = cursor;
            if ((void *)(vh + 1) > data_end)
                return XDP_PASS;
            h_proto = vh->h_vlan_encapsulated_proto;
            cursor  = (void *)(vh + 1);
        }
    }

    struct flow_key key = {};
    key.ifindex = (__u16)ifindex;

    __u8 protocol = 0;
    __u32 l4_off  = 0;          /* offset of L4 header from packet start    */
    void *l4      = NULL;       /* L4 header kept as a tracked packet ptr   */

    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = cursor;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        if (ip->ihl < 5)
            return XDP_PASS;
        __u32 ihl = (__u32)ip->ihl * 4;
        /* Keep the L4 header as a packet pointer derived straight from the
         * validated `ip` pointer. Do NOT reconstruct it later as
         * `data + scalar_offset`: pointer subtraction yields an unbounded
         * scalar, which the verifier then refuses to read through. */
        l4 = (__u8 *)ip + ihl;
        if (l4 > data_end)
            return XDP_PASS;

        key.family = AF_INET;
        __builtin_memcpy(key.src_addr, &ip->saddr, 4);
        __builtin_memcpy(key.dst_addr, &ip->daddr, 4);
        protocol = ip->protocol;
        l4_off   = (__u32)((__u8 *)ip - (__u8 *)data) + ihl;
        stat_inc(STAT_IPV4, 1);
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = cursor;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        l4 = (void *)(ip6 + 1);
        key.family = AF_INET6;
        __builtin_memcpy(key.src_addr, &ip6->saddr, 16);
        __builtin_memcpy(key.dst_addr, &ip6->daddr, 16);
        /* Note: IPv6 extension headers are not walked (kept fast/simple). */
        protocol = ip6->nexthdr;
        l4_off   = (__u32)((__u8 *)(ip6 + 1) - (__u8 *)data);
        stat_inc(STAT_IPV6, 1);
    } else {
        return XDP_PASS;                 /* ARP / other: counted globally */
    }

    key.protocol = protocol;

    __u32 tcp_flags = 0;
    __u32 l4_hdr_len = 0;
    int   is_syn = 0, is_rst = 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;

        __u8 flags = *((__u8 *)tcp + 13);   /* flags byte */
        tcp_flags  = flags;
        is_syn = (flags & TCP_SYN) && !(flags & TCP_ACK);
        is_rst = !!(flags & TCP_RST);

        l4_hdr_len = (__u32)tcp->doff * 4;
        if (l4_hdr_len < sizeof(*tcp))
            l4_hdr_len = sizeof(*tcp);
        stat_inc(STAT_TCP, 1);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
        l4_hdr_len   = sizeof(*udp);
        stat_inc(STAT_UDP, 1);
    } else if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) {
        stat_inc(STAT_ICMP, 1);
    } else {
        stat_inc(STAT_OTHER, 1);
    }

    /* Inline DDoS mitigation: drop blocklisted IPv4 sources. */
    if (key.family == AF_INET) {
        __u32 src4;
        __builtin_memcpy(&src4, key.src_addr, 4);
        __u8 *blocked = bpf_map_lookup_elem(&blocklist_map, &src4);
        if (blocked && *blocked) {
            stat_inc(STAT_DROPPED, 1);
            return XDP_DROP;
        }
    }

    /* Update (or create) the flow record. */
    __u64 pkt_index;
    struct nm_flow_stats *fs = bpf_map_lookup_elem(&flow_map, &key);
    if (fs) {
        pkt_index = __sync_fetch_and_add(&fs->packets, 1) + 1;
        __sync_fetch_and_add(&fs->bytes, pkt_len);
        fs->last_seen_ns = now;
        fs->tcp_flags |= tcp_flags;
        if (is_syn) __sync_fetch_and_add(&fs->syn_count, 1);
        if (is_rst) __sync_fetch_and_add(&fs->rst_count, 1);
    } else {
        struct nm_flow_stats nf = {};
        nf.packets       = 1;
        nf.bytes         = pkt_len;
        nf.first_seen_ns = now;
        nf.last_seen_ns  = now;
        nf.tcp_flags     = tcp_flags;
        nf.syn_count     = is_syn ? 1 : 0;
        nf.rst_count     = is_rst ? 1 : 0;
        bpf_map_update_elem(&flow_map, &key, &nf, BPF_ANY);
        pkt_index = 1;
    }

    /* L7 sampling: only the first few packets of an interesting flow carry
     * the headers we care about (HTTP request line / Host, TLS SNI, DNS qname,
     * SMTP banner, DB handshake). */
    if (pkt_index <= L7_SAMPLE_MAX_PKTS &&
        (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)) {
        __u8 hint = l7_hint_for(protocol, key.src_port, key.dst_port);
        if (hint != L7_UNKNOWN)
            sample_l7(ctx, &key, hint, l4_off, l4_hdr_len, now);
    }

    return XDP_PASS;
}
