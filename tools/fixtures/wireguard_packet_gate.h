#ifndef YONIK_WIREGUARD_PACKET_GATE_H
#define YONIK_WIREGUARD_PACKET_GATE_H

#include <linux/bpf.h>

struct yonik_wg_packet {
    __u64 cookie;
    __u32 mark;
    __u32 ifindex;
    __u8 source[16];
    __u8 destination[16];
    __be16 source_port;
    __be16 destination_port;
    __u32 family;
    __u8 next_hop[16];
    __u64 generation;
};

struct yonik_wg_session {
    struct bpf_spin_lock lock;
    __u32 reserved;
    __u64 generation;
    __u64 active;
};

enum yonik_wg_verdict {
    YONIK_WG_ALLOWED,
    YONIK_WG_UNSUPPORTED_PACKET,
    YONIK_WG_MISSING_LEASE,
    YONIK_WG_EXPIRED,
    YONIK_WG_INACTIVE_SESSION,
    YONIK_WG_VERDICTS,
};

#endif
