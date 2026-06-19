/* SPDX-License-Identifier: GPL-2.0 */
/*
 * common.h - Types shared between the XDP/eBPF kernel program and the
 *            C++ userspace collector.
 *
 * IMPORTANT: This header is compiled both by clang (BPF target) and by g++.
 * Only use fixed-width kernel types (__u8/__u16/__u32/__u64) which are
 * available in vmlinux.h (kernel side) and via <linux/types.h> (user side).
 * Keep all structs naturally aligned and padded so the layout is identical
 * on both sides (no implicit compiler padding surprises).
 */
#ifndef __NETMON_COMMON_H
#define __NETMON_COMMON_H

/*
 * When compiled as part of the BPF program, vmlinux.h has already defined the
 * __u8/__u16/__u32/__u64 fixed-width types (the BPF translation unit defines
 * NETMON_BPF before including us). For the C++ userspace build, pull them in
 * from <linux/types.h>.
 *
 * We also pull in the system networking headers here (userspace only) BEFORE
 * the protocol/address-family fallback macros below. glibc defines IPPROTO_*
 * and AF_* both as enum values AND as self-referential macros
 * (e.g. `#define IPPROTO_ICMP IPPROTO_ICMP`), so the `#ifndef` guards below
 * then correctly skip and never clobber those enums. The fallback macros only
 * take effect on the BPF side, where vmlinux.h does not provide them.
 */
#ifndef NETMON_BPF
#include <linux/types.h>
#include <netinet/in.h>   /* IPPROTO_* (enum + macros) */
#include <sys/socket.h>   /* AF_INET / AF_INET6 (macros) */
#endif

/* ---- EtherTypes --------------------------------------------------------- */
#define ETH_P_IP      0x0800
#define ETH_P_IPV6    0x86DD
#define ETH_P_8021Q   0x8100
#define ETH_P_8021AD  0x88A8
#define ETH_P_ARP     0x0806

/* ---- L4 protocols ------------------------------------------------------- */
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP   1
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP    6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP    17
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/* ---- Address families --------------------------------------------------- */
#ifndef AF_INET
#define AF_INET   2
#endif
#ifndef AF_INET6
#define AF_INET6  10
#endif

/* ---- TCP flag bits (byte 13 of the TCP header) -------------------------- */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

/* ---- Sizing knobs ------------------------------------------------------- */
#define MAX_FLOWS              1048576   /* flow_map capacity (LRU)          */
#define MAX_IFACES             256
#define BLOCKLIST_MAX          65536
#define L7_SNAP_LEN            256       /* payload bytes captured for DPI   */
#define L7_SAMPLE_MAX_PKTS     6         /* sample only first N pkts of flow */
#define L7_RINGBUF_SIZE        (1 << 24) /* 16 MiB                           */

/* ---- L7 application guess (kernel sets a hint from the port) ------------ */
enum l7_proto {
    L7_UNKNOWN = 0,
    L7_HTTP,
    L7_TLS,
    L7_DNS,
    L7_SMTP,
    L7_DB,        /* generic database (mysql/pgsql/mongo/redis)            */
};

/* ---- Global counter slots (PERCPU_ARRAY, summed in userspace) ----------- */
enum global_stat {
    STAT_TOTAL_PKTS = 0,
    STAT_TOTAL_BYTES,
    STAT_TCP,
    STAT_UDP,
    STAT_ICMP,
    STAT_OTHER,
    STAT_IPV4,
    STAT_IPV6,
    STAT_DROPPED,
    STAT_L7_SAMPLED,
    __STAT_MAX,
};

/* ---- Flow key (bidirectional flows are normalised in userspace) --------- */
struct flow_key {
    __u8  src_addr[16];   /* IPv4 stored in first 4 bytes, rest zero        */
    __u8  dst_addr[16];
    __u16 src_port;       /* network byte order                             */
    __u16 dst_port;       /* network byte order                             */
    __u8  protocol;
    __u8  family;         /* AF_INET / AF_INET6                             */
    __u16 ifindex;
} __attribute__((packed));

/* ---- Per-flow statistics ------------------------------------------------ */
/* Prefixed nm_ to avoid colliding with the kernel's own `struct flow_stats`
 * pulled in via vmlinux.h on recent kernels. */
struct nm_flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen_ns;  /* bpf_ktime_get_ns() of first packet             */
    __u64 last_seen_ns;   /* bpf_ktime_get_ns() of most recent packet       */
    __u32 tcp_flags;      /* OR-accumulation of all TCP flag bytes seen     */
    __u32 syn_count;      /* SYN-without-ACK count (scan / flood signal)    */
    __u32 rst_count;      /* RST count (refused conns / scan signal)        */
    __u32 _pad;
};

/* ---- Per-interface counters -------------------------------------------- */
struct if_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 dropped;
};

/* ---- L7 payload sample exported over the ring buffer -------------------- */
struct l7_event {
    __u64 ts_ns;
    __u8  src_addr[16];
    __u8  dst_addr[16];
    __u16 src_port;
    __u16 dst_port;
    __u16 ifindex;
    __u8  family;
    __u8  protocol;
    __u8  l7_hint;        /* enum l7_proto, port-based guess                 */
    __u8  _pad;
    __u16 payload_len;    /* number of valid bytes in payload[]             */
    __u8  payload[L7_SNAP_LEN];
};

#endif /* __NETMON_COMMON_H */
