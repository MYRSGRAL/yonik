#!/usr/bin/bash
set -Eeuo pipefail
trap 'echo "YONIK_WIREGUARD_PROOF_EXIT=$?"' EXIT

marker=/etc/yonik-production-helper-vm
test "$(id -u)" = 0
test ! -L "$marker"
test "$(cat "$marker")" = yonik-production-helper-disposable-v1
test "$(cat /sys/class/dmi/id/sys_vendor)" = QEMU

wg=/opt/yonik-gate/wg
interface=yonik-wg-proof
target=yonik-wg-netns
port=24291
namespace_created=false
interface_created=false

cleanup() {
    local status=$?
    trap - EXIT
    if "$interface_created" && ip link show dev "$interface" >/dev/null 2>&1; then
        ip link del dev "$interface" || status=1
    fi
    if "$namespace_created"; then
        ip netns del "$target" || status=1
    fi
    echo "YONIK_WIREGUARD_PROOF_EXIT=$status"
    exit "$status"
}
trap cleanup EXIT

resolver_state() {
    stat -c '%i %a %u %g %F %N' /etc/resolv.conf
    stat -L -c '%i %a %u %g %F' /etc/resolv.conf
    sha256sum /etc/resolv.conf
}

sockets() {
    "$@" ss -H -a -u -n -e --cgroup "( sport = :$port )"
}

cookies() {
    awk -F ' sk:' 'NF > 1 { split($2, fields, " "); print fields[1] }' | sort -u
}

before=$(resolver_state)
uname -r
test -z "$(sockets env)"
ip netns add "$target"
namespace_created=true
ip -n "$target" link set dev lo up
ip link add dev "$interface" type wireguard
interface_created=true
"$wg" set "$interface" listen-port "$port" fwmark "$port"
ip link set dev "$interface" up
original=$(sockets env)
echo "YONIK_WIREGUARD_ORIGIN=$(readlink /proc/self/ns/net)"
printf '%s\n' "$original"
test "$(cookies <<< "$original" | wc -l)" -eq 2

ip link set dev "$interface" netns "$target"
ip -n "$target" link set dev "$interface" up
test "$(ip netns exec "$target" "$wg" show "$interface" listen-port)" = "$port"
echo "YONIK_WIREGUARD_TARGET=$(ip netns exec "$target" readlink /proc/self/ns/net)"
ip -n "$target" -details -json link show dev "$interface"
test -z "$(sockets ip netns exec "$target")"
moved=$(sockets env)
printf '%s\n' "$moved"
test "$(cookies <<< "$moved" | wc -l)" -eq 2
test -z "$(comm -12 <(cookies <<< "$original") <(cookies <<< "$moved"))"

ip -n "$target" link add dev yonik-vx-proof4 type vxlan id 27400 local 127.0.0.1 dstport "$port" nolearning
ip -n "$target" link add dev yonik-vx-proof6 type vxlan id 27401 local ::1 dstport "$port" nolearning
ip -n "$target" link set dev yonik-vx-proof4 up
ip -n "$target" link set dev yonik-vx-proof6 up
other=$(sockets ip netns exec "$target")
printf '%s\n' "$other"
test "$(cookies <<< "$other" | wc -l)" -eq 2
test "$(sockets env | cookies)" = "$(cookies <<< "$moved")"
echo YONIK_WIREGUARD_SAME_PORT_IN_TWO_NAMESPACES

ip -n "$target" link del dev "$interface"
interface_created=false
test -z "$(sockets env)"
test "$(sockets ip netns exec "$target" | cookies)" = "$(cookies <<< "$other")"
ip netns del "$target"
namespace_created=false
test "$before" = "$(resolver_state)"
echo YONIK_RESOLV_CONF_UNCHANGED
