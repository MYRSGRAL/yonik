#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    printf '%s\n' 'Использование: stage.sh openrc|runit DESTDIR HELPER WORKER' >&2
    exit 64
fi

manager=$1
case "$manager" in
    openrc|runit) ;;
    *)
        printf '%s\n' 'Поддерживаются OpenRC и runit' >&2
        exit 64
        ;;
esac

destdir=$(CDPATH='' cd -- "$2" && pwd -P)
if [ "$destdir" = / ]; then
    printf '%s\n' 'Укажите отдельный каталог сборки пакета' >&2
    exit 64
fi

packaging=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
install -Dm755 -- "$3" "$destdir/usr/lib/yonik/yonik-helper"
install -Dm755 -- "$4" "$destdir/usr/lib/yonik/yonik-worker"
install -Dm644 -- "$packaging/dbus/cloud.highpriority.yonik.Network1.conf" \
    "$destdir/usr/share/dbus-1/system.d/cloud.highpriority.yonik.Network1.conf"
install -Dm644 -- "$packaging/polkit/cloud.highpriority.yonik.policy" \
    "$destdir/usr/share/polkit-1/actions/cloud.highpriority.yonik.policy"
install -Dm644 -- "$packaging/sysusers/yonik-worker.conf" \
    "$destdir/usr/lib/sysusers.d/yonik-worker.conf"

case "$manager" in
    openrc)
        install -Dm755 -- "$packaging/openrc/yonik-helper" "$destdir/etc/init.d/yonik-helper"
        ;;
    runit)
        install -Dm755 -- "$packaging/runit/yonik-helper/run" "$destdir/etc/sv/yonik-helper/run"
        ;;
esac
