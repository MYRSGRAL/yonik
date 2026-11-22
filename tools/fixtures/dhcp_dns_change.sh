#!/usr/bin/bash
set -euo pipefail

test "$(cat /sys/class/dmi/id/sys_vendor)" = QEMU
test "$(cat /etc/yonik-production-helper-vm)" = yonik-production-helper-disposable-v1
test "$(id -u)" = 0

client=yonik-dhcp
server=yonik-dhcp-peer
peer=yonik-peer
subnet=10.203.2
domain='~real.test'
publish_dns=yes
case "${YONIK_DHCP_FIXTURE:-primary}" in
    primary) ;;
    second)
        client=yonik-dhcp2
        server=yonik-dhcp2-srv
        subnet=10.203.3
        domain=
        publish_dns=no
        ;;
    *) exit 2 ;;
esac
service_type=${YONIK_DHCP_SERVICE_TYPE:-CS6}
case "$service_type" in
    none|CS4|CS6) ;;
    *) exit 2 ;;
esac
unit="$client-fixture.service"
state="/run/$client-fixture"

start_server() {
    local dns=$1
    case "$dns" in
        "$subnet.1"|"$subnet.2") ;;
        *) return 1 ;;
    esac
    cat > "$state/udhcpd.conf" <<EOF
interface $server
start $subnet.10
end $subnet.10
max_leases 1
pidfile $state/udhcpd.pid
lease_file $state/udhcpd.leases
option subnet 255.255.255.0
option lease 300
option dns $dns
EOF
    systemctl stop "$unit" 2>/dev/null || true
    systemd-run --quiet --unit="$unit" --property="NetworkNamespacePath=/run/netns/$peer" \
        /opt/yonik-gate/busybox udhcpd -f "$state/udhcpd.conf"
    systemctl is-active --quiet "$unit"
}

case "${1:-}" in
    prepare)
        install -d -m 0700 "$state"
        install -d -m 0755 /run/systemd/network
        cat > "/run/systemd/network/00-$client.network" <<EOF
[Match]
Name=$client
[Link]
RequiredForOnline=no
[Network]
DHCP=ipv4
Domains=$domain
DNSDefaultRoute=no
LinkLocalAddressing=no
IPv6AcceptRA=no
[DHCPv4]
IPServiceType=$service_type
ClientIdentifier=mac
UseDNS=$publish_dns
RoutesToDNS=no
UseRoutes=no
UseGateway=no
UseNTP=no
EOF
        ip link add "$client" type veth peer name "$server"
        ip link set "$server" netns "$peer"
        nsenter --net="/run/netns/$peer" -- ip address add "$subnet.1/24" dev "$server"
        nsenter --net="/run/netns/$peer" -- ip address add "$subnet.2/24" dev "$server"
        nsenter --net="/run/netns/$peer" -- ip link set "$server" up
        start_server "$subnet.1"
        systemctl start systemd-networkd.service
        networkctl reload
        ip link set "$client" up
        ;;
    disconnect)
        ip -4 route get "$subnet.1" from "$subnet.10" uid "$(id -u systemd-network)" \
            ipproto udp sport 68 dport 67 || true
        nsenter --net="/run/netns/$peer" -- ip link set "$server" down
        ;;
    "$subnet.1"|"$subnet.2")
        start_server "$1"
        nsenter --net="/run/netns/$peer" -- ip link set "$server" up
        ;;
    *) exit 2 ;;
esac
