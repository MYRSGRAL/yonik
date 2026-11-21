%{!?yonik_release:%global yonik_release 1}
%global yonik_libdir %{_prefix}/lib/yonik
%global yonik_policy_dir %{_datadir}/selinux/packages
%global yonik_policy_priority 200

# Сохраняем проверенные ELF побайтово. Отладочные пакеты здесь не собираются.
%global debug_package %{nil}
%global __strip /usr/bin/true
%global _build_id_links none

# RPM 6.1 отклоняет '/' внутри кодировки UTF-8 комментария sysusers.
# Пользователя создаёт systemd-sysusers в %%post из того же файла.
%global __provides_exclude_from ^%{_sysusersdir}/yonik-worker[.]conf$

Name:           yonik-helper
Version:        0.1.0
Release:        %{yonik_release}%{?dist}
Summary:        Системный сетевой помощник Yonik
License:        GPL-3.0-only
URL:            https://github.com/MYRSGRAL/yonik
Source0:        %{name}-%{version}.tar.gz
ExclusiveArch:  x86_64 aarch64

BuildRequires:  make
BuildRequires:  selinux-policy-devel
BuildRequires:  systemd-rpm-macros
Requires:       dbus
Requires:       iproute
Requires:       nftables
Requires:       polkit
Requires:       policycoreutils
Requires:       selinux-policy-targeted
Requires:       systemd

%description
Привилегированный помощник и изолированный worker для системного TUN Yonik.
Пакет содержит системные службы и политику SELinux для Fedora.

%prep
%autosetup -N

%build
%make_build -C packaging/fedora/selinux -f /usr/share/selinux/devel/Makefile yonik_helper.pp

%install
install -Dm755 binaries/yonik-helper %{buildroot}%{yonik_libdir}/yonik-helper
install -Dm755 binaries/yonik-worker %{buildroot}%{yonik_libdir}/yonik-worker
install -Dm644 packaging/systemd/*.service packaging/systemd/*.socket -t %{buildroot}%{_unitdir}/
install -Dm644 packaging/systemd/sleep.target.d/50-yonik-dhcp-sleep.conf \
    %{buildroot}%{_unitdir}/sleep.target.d/50-yonik-dhcp-sleep.conf
cp -a packaging/fedora/systemd/*.service.d %{buildroot}%{_unitdir}/
install -Dm644 packaging/sysusers/*.conf -t %{buildroot}%{_sysusersdir}/
install -Dm644 packaging/dbus/*.conf -t %{buildroot}%{_datadir}/dbus-1/system.d/
install -Dm644 packaging/dbus/*.service -t %{buildroot}%{_datadir}/dbus-1/system-services/
install -Dm644 packaging/polkit/*.policy -t %{buildroot}%{_datadir}/polkit-1/actions/
install -Dm644 packaging/fedora/selinux/yonik_helper.pp -t %{buildroot}%{yonik_policy_dir}/
cmp binaries/yonik-helper %{buildroot}%{yonik_libdir}/yonik-helper
cmp binaries/yonik-worker %{buildroot}%{yonik_libdir}/yonik-worker

%post
set -eu
semodule -X %{yonik_policy_priority} -i %{yonik_policy_dir}/yonik_helper.pp
restorecon -F %{yonik_libdir}/yonik-helper %{yonik_libdir}/yonik-worker \
    %{_unitdir}/yonik-worker{,-check}.{service,socket} \
    %{_unitdir}/sleep.target.d/50-yonik-dhcp-sleep.conf
restorecon -RF %{_unitdir}/yonik-worker{,-check}.service.d
for directory in /run/yonik /run/yonik-dhcp-sleep /run/yonik-worker /var/lib/yonik; do
    if [ -d "$directory" ]; then
        restorecon -RF "$directory"
    fi
done
systemd-sysusers %{_sysusersdir}/yonik-worker.conf
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi

%preun
set -eu
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    # RuntimeDirectory сохраняется между запусками и при восстановлении.
    # D-Bus авторизует остановку и разблокировку по UID владельца сессии.
    if [ -d /run/yonik ]; then
        state=$(busctl --timeout=20s call cloud.highpriority.yonik.Network1 \
            /cloud/highpriority/yonik/Network cloud.highpriority.yonik.Network1 \
            State s '{"version":1}') || state=
        if [ "$state" != 's "{\"state\":\"no_managed_policy\",\"version\":1}"' ]; then
            echo "Удаление Yonik отложено. Остановите сессию и разблокируйте сеть в Yonik." >&2
            exit 1
        fi
    fi
    systemctl stop yonik-helper.service yonik-worker.service yonik-worker-check.service \
        yonik-worker.socket yonik-worker-check.socket yonik-dhcp-sleep.service
fi

%postun
set -eu
if [ "$1" -eq 0 ]; then
    semodule -X %{yonik_policy_priority} -r yonik_helper
    # Данные StateDirectory сохраняются. Возвращаем штатную метку после удаления политики.
    for directory in /run/yonik /run/yonik-dhcp-sleep /run/yonik-worker /var/lib/yonik; do
        if [ -d "$directory" ]; then
            restorecon -RF "$directory"
        fi
    done
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload
    fi
fi

%files
%license LICENSE
%dir %{yonik_libdir}
%{yonik_libdir}/yonik-helper
%{yonik_libdir}/yonik-worker
%{_unitdir}/yonik-helper.service
%{_unitdir}/yonik-dhcp-sleep.service
%dir %{_unitdir}/sleep.target.d
%{_unitdir}/sleep.target.d/50-yonik-dhcp-sleep.conf
%{_unitdir}/yonik-worker.service
%{_unitdir}/yonik-worker.socket
%{_unitdir}/yonik-worker-check.service
%{_unitdir}/yonik-worker-check.socket
%{_unitdir}/yonik-worker.service.d/
%{_unitdir}/yonik-worker-check.service.d/
%{_sysusersdir}/yonik-worker.conf
%{_datadir}/dbus-1/system.d/cloud.highpriority.yonik.Network1.conf
%{_datadir}/dbus-1/system-services/cloud.highpriority.yonik.Network1.service
%{_datadir}/polkit-1/actions/cloud.highpriority.yonik.policy
%{yonik_policy_dir}/yonik_helper.pp

%changelog
* Wed Nov 18 2026 Yonik <noreply@github.com> - 0.1.0-1
- Первый RPM системного помощника для Fedora.
