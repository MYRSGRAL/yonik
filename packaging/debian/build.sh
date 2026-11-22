#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
umask 022

if (( $# != 3 )); then
    printf '%s\n' 'Применение: bash packaging/debian/build.sh <каталог ELF> <версия deb> <выходной каталог>' >&2
    exit 2
fi

binary_dir=$1
version=$2
output_dir=$(realpath -e -- "$3")
[[ -d "$output_dir" ]]
dpkg --validate-version "$version"

packaging_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
helper="$binary_dir/yonik-helper"
worker="$binary_dir/yonik-worker"

helper_headers=$(readelf -hW -- "$helper")
worker_headers=$(readelf -hW -- "$worker")
elf_class() { awk '/^[[:space:]]*Class:/ {print $2}'; }
elf_machine() { sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p'; }

if [[ $helper_headers != *"little endian"* || $worker_headers != *"little endian"* ||
      $(elf_class <<< "$helper_headers") != ELF64 ||
      $(elf_class <<< "$worker_headers") != ELF64 ||
      $(elf_machine <<< "$helper_headers") != "$(elf_machine <<< "$worker_headers")" ]]; then
    printf '%s\n' 'Helper и worker должны быть ELF64 одной архитектуры с порядком байтов little endian.' >&2
    exit 2
fi
case "$(elf_machine <<< "$helper_headers")" in
    'Advanced Micro Devices X86-64') arch=amd64 ;;
    AArch64) arch=arm64 ;;
    *)
        printf '%s\n' 'Поддерживаются архитектуры amd64 и arm64.' >&2
        exit 2
        ;;
esac

glibc=$(readelf -VW -- "$helper" "$worker" |
    awk '/Name: GLIBC_[0-9]/ {for (i = 1; i <= NF; i++) if ($i ~ /^GLIBC_[0-9]/) print substr($i, 7)}' |
    sort -V | tail -n 1)
if [[ ! $glibc =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
    printf '%s\n' 'Не удалось определить минимальную версию glibc по ELF.' >&2
    exit 2
fi

output="$output_dir/yonik-helper_${version##*:}_$arch.deb"
stage=$(mktemp -d -- "$output_dir/.yonik-deb.XXXXXXXX")
trap 'find "$stage" -depth -delete' EXIT

root="$stage/root"
units="$root/usr/lib/systemd/system"
install -d -m0755 "$root/DEBIAN" "$root/usr/lib/yonik" "$units" \
    "$root/usr/lib/sysusers.d" "$root/usr/share/dbus-1/system.d" \
    "$root/usr/share/dbus-1/system-services" "$root/usr/share/polkit-1/actions"
install -m0755 -t "$root/usr/lib/yonik" -- "$helper" "$worker"
install -Dm644 "$packaging_dir"/systemd/*.service "$packaging_dir"/systemd/*.socket -t "$units"
install -Dm644 "$packaging_dir/systemd/sleep.target.d/50-yonik-dhcp-sleep.conf" \
    "$units/sleep.target.d/50-yonik-dhcp-sleep.conf"
install -Dm644 "$packaging_dir/debian/yonik-helper.service.d/50-package-maintenance.conf" \
    "$units/yonik-helper.service.d/50-package-maintenance.conf"
install -Dm644 "$packaging_dir/sysusers/yonik-worker.conf" -t "$root/usr/lib/sysusers.d"
install -Dm644 "$packaging_dir/dbus/cloud.highpriority.yonik.Network1.conf" -t "$root/usr/share/dbus-1/system.d"
install -Dm644 "$packaging_dir/dbus/cloud.highpriority.yonik.Network1.service" -t "$root/usr/share/dbus-1/system-services"
install -Dm644 "$packaging_dir/polkit/cloud.highpriority.yonik.policy" -t "$root/usr/share/polkit-1/actions"
install -Dm644 "$packaging_dir/../LICENSE" "$root/usr/share/doc/yonik-helper/copyright"
install -m0755 "$packaging_dir"/debian/{postinst,prerm,postrm} -t "$root/DEBIAN"

installed_size=$(find "$root/usr" -type f -printf '%s\n' | awk '{ bytes += $1 } END { print int((bytes + 1023) / 1024) }')
cat >"$root/DEBIAN/control" <<EOF
Package: yonik-helper
Version: $version
Architecture: $arch
Section: net
Priority: optional
Maintainer: Yonik <noreply@github.com>
Installed-Size: $installed_size
Depends: libc6 (>= $glibc), libgcc-s1, libsqlite3-0, dbus, iproute2, nftables, polkitd, systemd, util-linux
Homepage: https://github.com/MYRSGRAL/yonik
Description: Системный сетевой помощник Yonik
 Привилегированный помощник и изолированный worker для системного TUN.
EOF
(
    cd -- "$root"
    find usr -type f -print0 | sort -z | xargs -0 md5sum
) >"$root/DEBIAN/md5sums"

dpkg-deb --root-owner-group --build "$root" "$stage/package.deb"
ln -T -- "$stage/package.deb" "$output"
printf '%s\n' "$output"
