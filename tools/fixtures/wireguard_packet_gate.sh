#!/usr/bin/bash
set -Eeuo pipefail
trap 'echo "YONIK_WIREGUARD_PROOF_EXIT=$?"' EXIT
test "$(cat /sys/class/dmi/id/sys_vendor)" = QEMU
test "$(cat /etc/yonik-production-helper-vm)" = yonik-production-helper-disposable-v1
test "$(cat /proc/1/comm)" = systemd
before=$(stat -c '%i %a %u %g %F %N' /etc/resolv.conf; stat -L -c '%i %a %u %g' /etc/resolv.conf; sha256sum /etc/resolv.conf)
. /etc/os-release
echo "$PRETTY_NAME"
uname -r
nft --version
systemctl stop yonik-helper.service
systemctl start systemd-resolved.service
ip netns add yonik-peer
ip link add yonik-outer type veth peer name yonik-inner
ip link set yonik-inner netns yonik-peer
ip address add 10.203.0.1/30 dev yonik-outer
ip -6 address add 2001:db8:7470::1/126 dev yonik-outer nodad
ip link set yonik-outer up
ip -n yonik-peer link set lo up
ip -n yonik-peer address add 10.203.0.2/30 dev yonik-inner
ip -n yonik-peer -6 address add 2001:db8:7470::2/126 dev yonik-inner nodad
ip -n yonik-peer link set yonik-inner up
wg=/opt/yonik-gate/wg
fixture=/opt/yonik-gate/tools/fixtures/wireguard_vm.py
python3 "$fixture" connect
python3 "$fixture" split-dns

case "$1" in
    4)
        endpoint=10.203.0.2; host=10.203.0.1; cidr="$endpoint/32"
        gateway_a=10.203.0.4; gateway_b=10.203.0.5; gateway_prefix=32
        ip -n yonik-peer -4 address add "$gateway_a/$gateway_prefix" dev yonik-inner
        ip -n yonik-peer -4 address add "$gateway_b/$gateway_prefix" dev yonik-inner
        ;;
    6)
        endpoint=2001:db8:7470::2; host=2001:db8:7470::1; cidr="$endpoint/128"
        gateway_a=2001:db8:7470::4; gateway_b=2001:db8:7470::5; gateway_prefix=128
        ip -n yonik-peer -6 address add "$gateway_a/$gateway_prefix" dev yonik-inner nodad
        ip -n yonik-peer -6 address add "$gateway_b/$gateway_prefix" dev yonik-inner nodad
        "$wg" set yonik-wg peer "$("$wg" show yonik-wg peers)" endpoint "[$endpoint]:24177"
        ip netns exec yonik-peer "$wg" set yonik-wg peer "$(ip netns exec yonik-peer "$wg" show yonik-wg peers)" endpoint "[$host]:24177"
        ;;
    *) exit 2 ;;
esac
mark=24177
port=24177
family_switch="-$1"
ifindex=$(cat /sys/class/net/yonik-outer/ifindex)
gate_exec=/opt/yonik-gate/wg-observe
gate=gate_command
gate_command() {
    case "$1" in
        allow|revoke)
            "$gate_exec" "${@:1:12}" "$("$gate_exec" revision "$2")" "${@:13}" ;;
        replace)
            "$gate_exec" "${@:1:3}" "$("$gate_exec" revision "$2")" "${@:4}" ;;
        *)
            "$gate_exec" "$@" ;;
    esac
}
pins=/sys/fs/bpf/yonik-wg-packet-gate
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
mkdir "$pins"
clear_gate() {
    for entry in post4 post6 v4 v6 wg_active wg_leases wg_verdicts; do
        if [[ -e "$pins/$entry" ]]; then unlink "$pins/$entry"; fi
    done
}
cleanup() {
    rc=$?
    if [[ "${2:-}" = nft-order ]]; then
        nft delete table inet yonik_order_matrix || true
    fi
    clear_gate
    rmdir "$pins"
    echo "YONIK_WIREGUARD_PROOF_EXIT=$rc"
}
trap 'cleanup "$@"' EXIT
systemd-run --wait --pipe --collect --unit=yonik-wg-packet-load \
    --property=NoNewPrivileges=yes --property='CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_PERFMON' \
    "$gate_exec" load /run/yonik-wg-socket.bpf.o "$pins" "$mark"
echo YONIK_WG_PACKET_LOAD_LIMITED_CAPS
generation=1
"$gate" start "$pins" "$generation"
cookie_for() {
    local cookie
    cookie=$(ss "$family_switch" -H -a -u -n -e "( sport = :$1 )" | sed -n 's/.* sk:\([0-9a-f]*\) .*/\1/p')
    [[ "$cookie" =~ ^[0-9a-f]+$ ]]
    printf '%s\n' "$cookie"
}
cookie=$(cookie_for "$port")
lease=("$1" "$host" "$endpoint" "$port" "$port" "$ifindex" "$mark" "$cookie" - "$generation")
echo_over_vpn() {
    python3 - <<'PYVM'
import socket

payload = b"wireguard-transport-witness".ljust(32, b"0")
response = b"yonik-tun:" + payload
for family, address in ((socket.AF_INET, "10.42.1.2"), (socket.AF_INET6, "fd42:1::2")):
    with socket.socket(family, socket.SOCK_STREAM) as tcp:
        tcp.settimeout(3)
        tcp.connect((address, 40000))
        tcp.sendall(payload)
        with tcp.makefile("rb") as reply:
            assert reply.read(len(response)) == response
    with socket.socket(family, socket.SOCK_DGRAM) as udp:
        udp.settimeout(3)
        udp.connect((address, 40000))
        udp.send(payload)
        assert udp.recv(256) == response
PYVM
}
probe() {
    if [[ "$1" = 1 ]]; then
        echo_over_vpn
    else
        if echo_over_vpn > /run/yonik-wg-blocked.log 2>&1; then
            echo "Ожидался отказ: $2"
            exit 1
        fi
    fi
}
count() {
    local counters
    read -ra counters <<< "$("$gate" counters "$pins")"
    printf '%s\n' "${counters[$1]}"
}
check() {
    expected=$1
    label=$2
    before_counter=$(count "$expected")
    if [[ "$expected" = 0 ]]; then probe 1 "$label"; else probe 0 "$label"; fi
    after_counter=$(count "$expected")
    test "$after_counter" -gt "$before_counter"
    echo "YONIK_WG_PACKET_GATE $label verdict=$expected count=$before_counter/$after_counter"
}
expect_status() {
    local expected_status=$1 status=0
    shift
    "$@" || status=$?
    if [[ "$status" != "$expected_status" ]]; then
        printf 'Ожидался код %s, получен %s\n' "$expected_status" "$status" >&2
        exit 1
    fi
}
snapshot_id() {
    local id
    id=$("$gate" snapshot "$pins") || return
    [[ "$id" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
    printf '%s\n' "$id"
}
if [[ "${2:-}" = nft-order ]]; then
    nft_family=ip
    packet_header='ip version 4 ip hdrlength 5 ip frag-off & 0x3fff == 0 ip protocol udp'
    if [[ "$1" = 6 ]]; then
        nft_family=ip6
        packet_header='ip6 version 6 ip6 nexthdr udp'
    fi
    rewrite_mark=24178
    nft -f - <<NFT
add table inet yonik_order_matrix
add chain inet yonik_order_matrix foreign_pre { type filter hook output priority -50; policy accept; }
add chain inet yonik_order_matrix managed { type filter hook output priority 0; policy accept; }
add chain inet yonik_order_matrix foreign_post { type filter hook output priority 50; policy accept; }
add rule inet yonik_order_matrix managed $packet_header $nft_family saddr $host $nft_family daddr $endpoint udp sport $port udp dport $port meta oifname "yonik-outer" meta mark $mark accept
add rule inet yonik_order_matrix managed $nft_family daddr $endpoint udp dport $port drop
NFT
    load_late_gate() {
        local mode=$1
        shift
        systemd-run --wait --pipe --collect --unit="yonik-wg-$mode" \
            --property=NoNewPrivileges=yes --property='CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_PERFMON' \
            "$gate_exec" "$mode" /run/yonik-wg-socket.bpf.o "$pins" "$@"
        "$gate" start "$pins" "$generation"
    }
    rewrite_late_mark() {
        nft add rule inet yonik_order_matrix foreign_post "$nft_family" daddr "$endpoint" udp dport "$port" meta mark set "$rewrite_mark"
    }
    "$wg" set yonik-wg fwmark "$rewrite_mark"
    nft add rule inet yonik_order_matrix foreign_pre "$nft_family" daddr "$endpoint" udp dport "$port" meta mark set "$mark"
    probe 1 early_mark_only_control
    test "$(count 0)" = 0
    test "$(count 2)" = 0
    echo YONIK_WG_ORDER_EARLY_MARK_ONLY_CONTROL
    clear_gate

    load_late_gate load-late "$mark"
    check 2 late_after_nft_sets_mark
    rewrite_late_mark
    probe 1 late_mark_only_control
    echo YONIK_WG_ORDER_LATE_MARK_ONLY_CONTROL
    clear_gate

    # Проверяем отбор по конечной точке отдельно от отбора по cookie.
    other_cookie=fffffffffffffffe
    test "$cookie" != "$other_cookie"
    load_late_gate load-guarded "$1" "$endpoint" "$port" "$port" "$other_cookie"
    check 2 endpoint_selected_after_mark_rewrite
    clear_gate

    # Эта цепочка OUTPUT работает уже после максимально позднего BPF OUTPUT.
    nft flush chain inet yonik_order_matrix foreign_post
    nft delete chain inet yonik_order_matrix foreign_post
    nft add chain inet yonik_order_matrix foreign_post '{ type filter hook output priority 2147483647; policy accept; }'
    rewrite_late_mark
    # Переписанный поток не совпадёт и с портом, указанным в списке.
    load_late_gate load-guarded "$1" "$endpoint" "$port" 24179 "$cookie"
    check 2 cookie_selected_after_mark_rewrite
    "$gate" replace "$pins" "$generation" "${lease[@]:0:9}" 15000
    before_allowed=$(count 0)
    check 2 postrouting_rejects_rewrite_after_output_lease
    test "$(count 0)" -gt "$before_allowed"
    nft flush chain inet yonik_order_matrix foreign_post
    check 0 guarded_current_lease
    # Сторонний сокет с такой же меткой вне перечня остаётся доступен.
    python3 - "$mark" <<'PY'
import socket
import sys

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, int(sys.argv[1]))
        sender.sendto(b"yonik-unrelated", receiver.getsockname())
    assert receiver.recv(32) == b"yonik-unrelated"
PY
    echo YONIK_WG_ORDER_UNRELATED_SOCKET_UNCHANGED

    # Проверяем тот же интерфейс с другим реальным следующим узлом.
    "$wg" set yonik-wg fwmark "$mark"
    ip "$family_switch" rule add pref 300 fwmark "$mark" table 219
    ip "$family_switch" route replace "$cidr" via "$gateway_a" dev yonik-outer onlink src "$host" table 219
    guarded_lease=("${lease[@]:0:9}")
    guarded_lease[8]=$gateway_a
    "$gate" replace "$pins" "$generation" "${guarded_lease[@]}" 15000
    check 0 guarded_first_gateway
    ip "$family_switch" route replace "$cidr" via "$gateway_b" dev yonik-outer onlink src "$host" table 219
    ip "$family_switch" route get "$endpoint" from "$host" mark "$mark" |
        grep -F "via $gateway_b dev yonik-outer table 219"
    check 2 guarded_gateway_changed
    ip "$family_switch" rule del pref 300
    ip "$family_switch" route del "$cidr" table 219

    "$gate" replace "$pins" "$generation" "${lease[@]:0:9}" 500
    sleep 1
    check 3 guarded_expired_lease
    "$gate" stop "$pins" "$generation"
    rewrite_late_mark
    check 4 guarded_stop_after_mark_rewrite
    test "$before" = "$(stat -c '%i %a %u %g %F %N' /etc/resolv.conf; stat -L -c '%i %a %u %g' /etc/resolv.conf; sha256sum /etc/resolv.conf)"
    echo YONIK_WG_ORDER_RESOLVCONF_OK
    exit 0
fi

binary_lease() {
    python3 - "$@" <<'PYVM'
import ipaddress
import socket
import struct
import sys
import time

family, source, endpoint, sport, dport, index, mark, cookie, _, generation = sys.argv[1:11]
deadline_delta = int(sys.argv[11])
family = socket.AF_INET if family == "4" else socket.AF_INET6
source = ipaddress.ip_address(source).packed
endpoint = ipaddress.ip_address(endpoint).packed
key = struct.pack("=QII16s16s", int(cookie, 16), int(mark), int(index), source, endpoint)
key += struct.pack("!HH", int(sport), int(dport))
expiry = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + deadline_delta
key += struct.pack("=I16sQQ", family, endpoint, int(generation), expiry)
sys.stdout.buffer.write(key)
PYVM
}
revision=$("$gate" revision "$pins")
binary_lease "${lease[@]}" -1000000000 | expect_status 2 "$gate" replace-binary "$pins" "$generation" "$revision"
binary_lease "${lease[@]}" 3000000000 | expect_status 2 "$gate" replace-binary "$pins" "$generation" "$revision"
printf '%s' short | expect_status 2 "$gate" replace-binary "$pins" "$generation" "$revision"
{ binary_lease "${lease[@]}" 500000000; sleep 1; } |
    expect_status 3 "$gate" replace-binary "$pins" "$generation" "$revision"
test "$("$gate" revision "$pins")" = "$revision"
binary_lease "${lease[@]}" 1800000000 | "$gate" replace-binary "$pins" "$generation" "$revision"
check 0 binary_snapshot_current
binary_lease "${lease[@]}" 1800000000 | expect_status 3 "$gate" replace-binary "$pins" "$generation" "$revision"
sleep 2
check 3 binary_snapshot_absolute_deadline

"$gate" allow "$pins" "${lease[@]}" 15000
check 0 after_loader_exit
timeout 4 getent ahostsv4 active.wg.test | grep -q '^10\.42\.1\.2 '
echo YONIK_WG_PACKET_GATE split_dns_allowed
"$gate" revoke "$pins" "${lease[@]}"
check 2 explicitly_revoked
if timeout 4 getent ahostsv4 after.wg.test; then
    echo 'Приватный DNS ответил после отзыва допуска' >&2
    exit 1
fi
echo YONIK_WG_PACKET_GATE split_dns_revoked

if [[ "$1" = 4 ]]; then alt_host=10.203.0.9; alt_peer=10.203.0.10; else alt_host=2001:db8:7470::9; alt_peer=2001:db8:7470::a; fi
wrong_cookie=1
if [[ "$cookie" = 1 ]]; then wrong_cookie=2; fi
for pair in "1:$alt_host:source" "2:$alt_peer:destination" "3:24179:source_port" "4:24179:destination_port" "5:1:ifindex" "7:$wrong_cookie:cookie"; do
    index=${pair%%:*}
    label=${pair##*:}
    value=${pair#*:}
    value=${value%:*}
    wrong=("${lease[@]}")
    wrong[$index]=$value
    "$gate" allow "$pins" "${wrong[@]}" 15000
    check 2 "$label"
    "$gate" revoke "$pins" "${wrong[@]}"
done
"$gate" allow "$pins" "${lease[@]}" 500
sleep 1
check 3 expired_after_publisher_exit
"$gate" allow "$pins" "${lease[@]}" 15000
check 0 restored
ip link add yonik-wrong type dummy
ip link set yonik-wrong up
ip "$family_switch" route add "$cidr" dev yonik-wrong src "$host" table 219
ip "$family_switch" rule add pref 300 fwmark "$mark" table 219
ip "$family_switch" route get "$endpoint" from "$host" mark "$mark" | grep -F 'dev yonik-wrong'
check 2 changed_output_route
ip "$family_switch" rule del pref 300
ip link del yonik-wrong
"$gate" allow "$pins" "${lease[@]}" 15000
check 0 restored_output_route
"$gate" revoke "$pins" "${lease[@]}"
# Оба шлюза отвечают на одном интерфейсе, адреса и порты пакета сохраняются.
select_gateway() {
    ip "$family_switch" route replace "$cidr" via "$1" dev yonik-outer onlink src "$host" table 219
}
check_gateway_route() {
    ip "$family_switch" route get "$endpoint" from "$host" mark "$mark" \
        | grep -F "via $1 dev yonik-outer table 219"
}
select_gateway "$gateway_a"
ip "$family_switch" rule add pref 300 fwmark "$mark" table 219
check_gateway_route "$gateway_a"
via_gateway=("${lease[@]}")
via_gateway[8]=$gateway_a
"$gate" allow "$pins" "${via_gateway[@]}" 15000
check 0 via_first_gateway
select_gateway "$gateway_b"
check_gateway_route "$gateway_b"
check 2 changed_gateway_same_interface
"$gate" revoke "$pins" "${via_gateway[@]}"
via_gateway[8]=$gateway_b
"$gate" allow "$pins" "${via_gateway[@]}" 15000
check 0 via_republished_gateway
"$gate" revoke "$pins" "${via_gateway[@]}"
ip "$family_switch" rule del pref 300
ip "$family_switch" route del "$cidr" table 219
ip -n yonik-peer "$family_switch" address del "$gateway_a/$gateway_prefix" dev yonik-inner
ip -n yonik-peer "$family_switch" address del "$gateway_b/$gateway_prefix" dev yonik-inner
"$gate" allow "$pins" "${lease[@]}" 15000
check 0 restored_direct_gateway
"$wg" set yonik-wg listen-port 24178
new_cookie=$(cookie_for 24178)
test "$cookie" != "$new_cookie"
check 2 socket_replaced
"$gate" revoke "$pins" "${lease[@]}"
lease[3]=24178
lease[7]=$new_cookie
"$gate" allow "$pins" "${lease[@]}" 15000
check 0 republished_socket

"$gate" stop "$pins" "$generation"
test "$(snapshot_id)" = 0
check 4 stopped_generation
# Запоздавший отправитель пытается продлить допуск для прежнего поколения.
expect_status 3 "$gate" allow "$pins" "${lease[@]}" 60000
expect_status 3 "$gate" replace "$pins" "$generation" "${lease[@]:0:9}" 60000
test "$(snapshot_id)" = 0
check 4 stale_publication_while_stopped
expect_status 3 "$gate" start "$pins" "$generation"
echo YONIK_WG_PACKET_GATE stopped_generation_reuse_rejected

next_generation=$((generation + 1))
"$gate" start "$pins" "$next_generation"
test "$(snapshot_id)" = 0
check 2 new_generation_without_lease
next_lease=("${lease[@]}")
next_lease[9]=$next_generation
wrong_route=("${next_lease[@]:0:9}")
wrong_route[3]=24179
"$gate" replace "$pins" "$next_generation" \
    "${next_lease[@]:0:9}" 15000 "${wrong_route[@]}" 15000
current_snapshot=$(snapshot_id)
test "$current_snapshot" != 0
check 0 new_generation_published

# Разный срок не делает вторую запись с тем же ключом допустимой.
if "$gate" replace "$pins" "$next_generation" \
    "${next_lease[@]:0:9}" 15000 "${next_lease[@]:0:9}" 60000; then
    echo 'Снимок с дублирующимся ключом принят' >&2
    exit 1
fi
test "$(snapshot_id)" = "$current_snapshot"
check 0 snapshot_after_rejected_duplicate

"$gate" replace "$pins" "$next_generation"
empty_snapshot=$(snapshot_id)
test "$empty_snapshot" != "$current_snapshot"
check 2 empty_snapshot

# При накоплении строк в одной карте этот цикл превысил бы 64 записи.
current_snapshot=$empty_snapshot
for ((iteration = 0; iteration < 70; iteration++)); do
    wrong_route[3]=$((24200 + iteration))
    "$gate" replace "$pins" "$next_generation" \
        "${next_lease[@]:0:9}" 15000 "${wrong_route[@]}" 15000
    replacement=$(snapshot_id)
    test "$replacement" != 0
    test "$replacement" != "$current_snapshot"
    current_snapshot=$replacement
done
check 0 snapshot_after_70_replacements

saved_revision=$("$gate_exec" revision "$pins")
"$gate" revoke "$pins" "${next_lease[@]}"
current_snapshot=$(snapshot_id)
expect_status 3 "$gate_exec" replace "$pins" "$next_generation" "$saved_revision" \
    "${next_lease[@]:0:9}" 60000
expect_status 3 "$gate_exec" allow "$pins" "${next_lease[@]}" "$saved_revision" 60000
test "$(snapshot_id)" = "$current_snapshot"
check 2 stale_revision_after_revoke
"$gate" replace "$pins" "$next_generation" "${next_lease[@]:0:9}" 15000
current_snapshot=$(snapshot_id)
check 0 restored_with_current_revision

expect_status 3 "$gate" allow "$pins" "${lease[@]}" 60000
expect_status 3 "$gate" replace "$pins" "$generation" "${lease[@]:0:9}" 60000
test "$(snapshot_id)" = "$current_snapshot"
check 0 new_generation_after_stale_publication
expect_status 3 "$gate" revoke "$pins" "${lease[@]}"
test "$(snapshot_id)" = "$current_snapshot"
check 0 new_generation_after_stale_revocation
expect_status 3 "$gate" stop "$pins" "$generation"
test "$(snapshot_id)" = "$current_snapshot"
check 0 new_generation_after_stale_stop
"$gate" stop "$pins" "$next_generation"
test "$(snapshot_id)" = 0
check 4 stopped_new_generation

after=$(stat -c '%i %a %u %g %F %N' /etc/resolv.conf; stat -L -c '%i %a %u %g' /etc/resolv.conf; sha256sum /etc/resolv.conf)
test "$before" = "$after"
echo YONIK_RESOLV_CONF_UNCHANGED
