#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "wireguard_packet_gate.h"

#define CORE __attribute__((preserve_access_index))

typedef struct { long long counter; } atomic64_t;
struct sock_common { atomic64_t skc_cookie; } CORE;
struct sock { struct sock_common __sk_common; } CORE;
struct net_device { int ifindex; } CORE;
struct sk_buff { __u32 mark; unsigned long _skb_refdst; } CORE;
struct dst_ops { unsigned short family; } CORE;
struct lwtunnel_state;
struct xfrm_state;
struct dst_entry {
    struct net_device *dev;
    struct dst_ops *ops;
    struct lwtunnel_state *lwtstate;
    struct xfrm_state *xfrm;
    unsigned short flags;
    short obsolete;
    short error;
} CORE;
struct rtable {
    struct dst_entry dst;
    __u8 rt_gw_family;
    __be32 rt_gw4;
} CORE;
struct in6_addr { __u8 bytes[16]; };
struct rt6key { struct in6_addr addr; } CORE;
struct rt6_info {
    struct dst_entry dst;
    struct rt6key rt6i_dst;
    struct in6_addr rt6i_gateway;
    __u32 rt6i_flags;
} CORE;
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

// Отдельный кадр стека не даёт компилятору переиспользовать место dynptr
// для временных полей маршрута, что запрещает BPF verifier.
static __noinline int read_packet(struct sk_buff *skb, struct yonik_wg_packet *packet)
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

static __always_inline int read_next_hop(const struct sk_buff *skb,
                                         const struct net_device *out,
                                         struct yonik_wg_packet *packet)
{
    // skb_dst() снимает бит NOREF. Netfilter вызывает этот хук под RCU.
    unsigned long refdst = skb->_skb_refdst;
    const struct dst_entry *route = (const void *)(refdst & ~1UL);
    struct net_device *device;
    struct dst_ops *ops;
    struct lwtunnel_state *lwtstate;
    unsigned short family, flags;
    short obsolete, error;

    if (!route || bpf_core_read(&device, sizeof(device), &route->dev) || device != out
        || bpf_core_read(&ops, sizeof(ops), &route->ops) || !ops
        || bpf_core_read(&family, sizeof(family), &ops->family) || family != packet->family
        || bpf_core_read(&lwtstate, sizeof(lwtstate), &route->lwtstate) || lwtstate
        || bpf_core_read(&obsolete, sizeof(obsolete), &route->obsolete) || obsolete > 0
        || bpf_core_read(&error, sizeof(error), &route->error) || error
        || bpf_core_read(&flags, sizeof(flags), &route->flags)
        || (flags & (0x10 | 0x20 | 0x40 | 0x80))) /* FAKE_RTABLE, XFRM_TUNNEL/QUEUE, METADATA */
        return -1;
    if (bpf_core_field_exists(route->xfrm)) {
        struct xfrm_state *xfrm;
        if (bpf_core_read(&xfrm, sizeof(xfrm), &route->xfrm) || xfrm)
            return -1;
    }

    // Как в IPv4 ip_neigh_for_gw, без преобразований адреса в другой стек.
    if (packet->family == 2) {
        const struct rtable *v4 = (const void *)route;
        __u8 gateway_family;
        if (bpf_core_read(&gateway_family, sizeof(gateway_family), &v4->rt_gw_family))
            return -1;
        if (gateway_family == 2)
            return bpf_core_read(packet->next_hop, 4, &v4->rt_gw4);
        if (gateway_family != 0)
            return -1;
    } else {
        const struct rt6_info *v6 = (const void *)route;
        __u32 route_flags;
        if (bpf_core_read(&route_flags, sizeof(route_flags), &v6->rt6i_flags))
            return -1;
        // Воспроизводим rt6_nexthop: gateway, кэшированный адрес или IP пакета.
        if (route_flags & 0x2) /* RTF_GATEWAY */
            return bpf_core_read(packet->next_hop, 16, &v6->rt6i_gateway);
        if (route_flags & 0x01000000) /* RTF_CACHE */
            return bpf_core_read(packet->next_hop, 16, &v6->rt6i_dst.addr);
    }
    __builtin_memcpy(packet->next_hop, packet->destination, sizeof(packet->next_hop));
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
    if (!packet.cookie || !packet.ifindex || read_packet(ctx->skb, &packet)
        || read_next_hop(ctx->skb, out, &packet))
        return verdict(YONIK_WG_UNSUPPORTED_PACKET);

    const __u64 *expires = bpf_map_lookup_elem(&wg_leases, &packet);
    if (!expires)
        return verdict(YONIK_WG_MISSING_LEASE);
    if (bpf_ktime_get_boot_ns() >= *expires)
        return verdict(YONIK_WG_EXPIRED);
    return verdict(YONIK_WG_ALLOWED);
}

char LICENSE[] SEC("license") = "GPL";
