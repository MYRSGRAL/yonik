#!/usr/bin/bash
set -euo pipefail

test "$(cat /sys/class/dmi/id/sys_vendor)" = QEMU
test "$(cat /etc/yonik-production-helper-vm)" = yonik-production-helper-disposable-v1
test "$(id -u)" = 0

client=yonik-dhcp
server=yonik-dhcp-peer
peer=yonik-peer
unit=yonik-dhcp-fixture.service
state=/run/yonik-dhcp-fixture

start_server() {
    local dns=$1
    case "$dns" in
        10.203.2.1|10.203.2.2) ;;
        *) return 1 ;;
    esac
    cat > "$state/udhcpd.conf" <<EOF
interface $server
start 10.203.2.10
end 10.203.2.10
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
        cat > /run/systemd/network/00-yonik-dhcp.network <<EOF
[Match]
Name=$client
[Link]
RequiredForOnline=no
[Network]
DHCP=ipv4
Domains=~real.test
DNSDefaultRoute=no
LinkLocalAddressing=no
IPv6AcceptRA=no
[DHCPv4]
ClientIdentifier=mac
UseDNS=yes
RoutesToDNS=no
UseRoutes=no
UseGateway=no
UseNTP=no
EOF
        ip link add "$client" type veth peer name "$server"
        ip link set "$server" netns "$peer"
        ip -n "$peer" address add 10.203.2.1/24 dev "$server"
        ip -n "$peer" address add 10.203.2.2/24 dev "$server"
        ip -n "$peer" link set "$server" up
        start_server 10.203.2.1
        systemctl start systemd-networkd.service
        networkctl reload
        ip link set "$client" up
        ;;
    disconnect)
        ip -4 route get 10.203.2.1 from 10.203.2.10 uid "$(id -u systemd-network)" \
            ipproto udp sport 68 dport 67 || true
        ip -n "$peer" link set "$server" down
        ;;
    10.203.2.1|10.203.2.2)
        start_server "$1"
        ip -n "$peer" link set "$server" up
        ;;
    *) exit 2 ;;
esac
