#!/usr/bin/bash
set -euo pipefail

test "$(cat /sys/class/dmi/id/sys_vendor)" = QEMU
test "$(cat /proc/1/comm)" = systemd
test "$(cat /etc/yonik-production-helper-vm)" = yonik-production-helper-disposable-v1
test "$(id -u)" = 0
systemctl is-active --quiet NetworkManager.service
/usr/bin/busybox --list | grep -x udhcpd

client=yonik-nm-lease
server=ynk-nm-dhcp
state=/run/yonik-nm-lease
unit=yonik-nm-lease-server.service
install -d -m0700 "$state"

ip netns add "$client"
ip link add "$client" type veth peer name "$server"
ip link set "$server" netns "$client"
ip -n "$client" addr add 10.233.53.1/24 dev "$server"
ip -n "$client" link set "$server" up
cat >"$state/server.conf" <<CONF
interface $server
start 10.233.53.10
end 10.233.53.10
max_leases 1
min_lease 10
pidfile $state/server.pid
lease_file $state/server.leases
option subnet 255.255.255.0
option lease 46
CONF
systemd-run --quiet --unit="$unit" \
    --property="NetworkNamespacePath=/run/netns/$client" \
    /usr/bin/busybox udhcpd -f "$state/server.conf"
systemctl is-active --quiet "$unit"
nmcli connection add type ethernet ifname "$client" con-name "$client" \
    connection.autoconnect no ipv4.method auto ipv4.never-default yes \
    ipv4.ignore-auto-dns yes ipv6.method disabled
nmcli --wait 15 connection up "$client"
ip -4 -o addr show dev "$client" | grep -F '10.233.53.10/24'
