#!/usr/bin/bash
set -euo pipefail

test "$(cat /sys/class/dmi/id/sys_vendor)" = QEMU
test "$(cat /proc/1/comm)" = systemd
test "$(cat /etc/yonik-production-helper-vm)" = yonik-production-helper-disposable-v1
test "$(id -u)" = 0
systemctl is-active --quiet NetworkManager.service
/usr/bin/busybox --list | grep -x udhcpd

mode=${1:-renewal}
case "$mode" in
    renewal) autoconnect=no ;;
    s3) autoconnect=yes ;;
    *) exit 2 ;;
esac

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
    connection.autoconnect "$autoconnect" ipv4.method auto ipv4.never-default yes \
    ipv4.ignore-auto-dns yes ipv6.method disabled
nmcli --wait 15 connection up "$client"
ip -4 -o addr show dev "$client" | grep -F '10.233.53.10/24'

if [[ "$mode" == s3 ]]; then
    printf '%s\n' deep >/sys/power/mem_sleep
    install -d -m0755 /usr/lib/systemd/system-sleep
    cat >/usr/lib/systemd/system-sleep/90-yonik-nm-fixture <<'HOOK'
#!/usr/bin/bash
set -euo pipefail
case "$1" in
    pre)
        state=$(/usr/sbin/nft -j list ruleset | python3 -c '
import json
import sys

sets = [
    entry["set"]
    for entry in json.load(sys.stdin)["nftables"]
    if entry.get("set", {}).get("name") == "dhcp_renewal_leases"
]
if not sets:
    print("absent")
elif len(sets) == 1 and not sets[0].get("elem"):
    print("empty")
else:
    print("active")
')
        printf '%s\n' "$state" >/run/yonik-dhcp-sleep-pre
        printf 'YONIK_NM_S3_PRE=%s\n' "$state" >/dev/ttyS0
        ;;
    post)
        printf 'YONIK_NM_S3_POST\n' >/dev/ttyS0
        touch /run/yonik-dhcp-sleep-post
        ;;
esac
HOOK
    chmod 0755 /usr/lib/systemd/system-sleep/90-yonik-nm-fixture
fi
