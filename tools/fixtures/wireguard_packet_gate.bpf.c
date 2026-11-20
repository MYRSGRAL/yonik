#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "wireguard_packet_gate.h"

#define CORE __attribute__((preserve_access_index))

typedef struct { long long counter; } atomic64_t;
struct sock_common { atomic64_t skc_cookie; } CORE;
struct sock { struct sock_common __sk_common; } CORE;
struct net_device { int ifindex; } CORE;
struct sk_buff { __u32 mark; } CORE;
struct nf_hook_state {
    struct sock *sk;
    struct net_device *out;
    __u8 pf;
} CORE;
struct bpf_nf_ctx { const struct nf_hook_state *state; struct sk_buff *skb; } CORE;

extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags, struct bpf_dynptr *ptr) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} wg_mark SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct yonik_wg_packet);
    __type(value, __u64);
} wg_leases SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, YONIK_WG_VERDICTS);
    __type(key, __u32);
    __type(value, __u64);
} wg_verdicts SEC(".maps");

static __always_inline int verdict(__u32 value)
{
    __u64 *counter = bpf_map_lookup_elem(&wg_verdicts, &value);
    if (counter)
        __sync_fetch_and_add(counter, 1);
    return value == YONIK_WG_ALLOWED;
}

static __always_inline int read_packet(struct sk_buff *skb, struct yonik_wg_packet *packet)
{
    struct bpf_dynptr ptr;
    __u8 header[48] = {};
    if (bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &ptr))
        return -1;
    if (packet->family == 2) {
        // Внешний WireGuard UDP/IPv4 создаётся без IP options до фрагментации.
        if (bpf_dynptr_read(header, 28, &ptr, 0, 0) || header[0] != 0x45
            || header[9] != 17 || (header[6] & 0x3f) || header[7])
            return -1;
        __builtin_memcpy(packet->source, header + 12, 4);
        __builtin_memcpy(packet->destination, header + 16, 4);
        __builtin_memcpy(&packet->source_port, header + 20, 2);
        __builtin_memcpy(&packet->destination_port, header + 22, 2);
        return 0;
    }
    if (packet->family != 10)
        return -1;
    // WireGuard UDP/IPv6 без заголовков расширения.
    if (bpf_dynptr_read(header, 48, &ptr, 0, 0)
        || (header[0] >> 4) != 6 || header[6] != 17)
        return -1;
    __builtin_memcpy(packet->source, header + 8, 16);
    __builtin_memcpy(packet->destination, header + 24, 16);
    __builtin_memcpy(&packet->source_port, header + 40, 2);
    __builtin_memcpy(&packet->destination_port, header + 42, 2);
    return 0;
}

SEC("netfilter")
int wireguard_gate(struct bpf_nf_ctx *ctx)
{
    const __u32 zero = 0;
    const __u32 *mark = bpf_map_lookup_elem(&wg_mark, &zero);
    if (!mark || !*mark || ctx->skb->mark != *mark)
        return 1;

    struct sock *socket = ctx->state->sk;
    struct net_device *out = ctx->state->out;
    if (!socket || !out)
        return verdict(YONIK_WG_UNSUPPORTED_PACKET);

    struct yonik_wg_packet packet = {
        .cookie = socket->__sk_common.skc_cookie.counter,
        .mark = ctx->skb->mark,
        .ifindex = out->ifindex,
        .family = ctx->state->pf,
    };
    if (!packet.cookie || !packet.ifindex || read_packet(ctx->skb, &packet))
        return verdict(YONIK_WG_UNSUPPORTED_PACKET);

    const __u64 *expires = bpf_map_lookup_elem(&wg_leases, &packet);
    if (!expires)
        return verdict(YONIK_WG_MISSING_LEASE);
    if (bpf_ktime_get_boot_ns() >= *expires)
        return verdict(YONIK_WG_EXPIRED);
    return verdict(YONIK_WG_ALLOWED);
}

char LICENSE[] SEC("license") = "GPL";
