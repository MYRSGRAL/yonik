# План переносимости TUN и Fake DNS на Linux

**Цель** — из установленного пакета подключать системный TUN с реальным или
синтетическим DNS во всех проверенных Linux-конфигурациях независимо от DE.
Текущие контракты [сети](../../specs/networking.md),
[Linux-платформы](../../specs/platforms.md) и
[приёмки](../../specs/validation-and-roadmap.md) действуют для всех этапов.

## Матрица проверенных конфигураций

| Система | Путь проверки | Результат для Xray и sing-box |
| --- | --- | --- |
| Debian 13.7, KVM, x86-64, systemd-networkd и systemd-resolved | Установленный тестовый `.deb` из `eebcca65`. По отдельному гостю на движок и способ входа в S3 | Набор DHCP пуст до и после S3 как при SIGKILL helper перед запросом через logind, так и при прямом запуске `systemd-suspend.service`. Старые Fake-IP блокировались. Штатный DNS восстановился, `/etc/resolv.conf` совпал |
| Ubuntu 24.04.5 LTS, KVM, x86-64, systemd 255, nftables 1.0.9 | Тестовый `.deb` для systemd с ELF из `eebcca65`. Xray проверен с прямым запуском `systemd-suspend.service`, sing-box — с SIGKILL helper перед запросом через logind | Оба гостя вошли в S3 и проснулись. В каждом DHCP-набор пуст до и после сна, старые Fake-IP блокировались, штатный DNS восстановился. Ссылка, метаданные и содержимое `/etc/resolv.conf` совпали |
| Fedora Cloud 45, KVM, x86-64, NetworkManager 1.58.1, SELinux Enforcing | Установленный RPM `0.1.0-911.fc45` с ELF из `eebcca65` и политикой `61fece1d`. Сверены SHA-256 пакета и ELF, до и после теста прошёл `rpm -V` | Оба движка прошли S3 через logind и получили новый DHCPACK. После пробуждения восстановились Fake A/AAAA и TCP/UDP через TUN. `/etc/resolv.conf` совпал, служба сняла маркер сна |
| Fedora Workstation 45, KVM, x86-64, GNOME Shell 51.0, Wayland, Qt 6.11.2, SELinux Enforcing | Установка с официального ISO, RPM helper `0.1.0-911.fc45` и нативная сборка Qt-клиента из `fc846c00`. Активная локальная сессия обычного пользователя и штатная политика polkit | Кнопка приложения запустила TUN на обоих движках. Прошли Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS, DoH, Stop и Unlock. Исходный DNS восстановился, RPM удалён. Ссылка, содержимое и метаданные `/etc/resolv.conf` совпали |
| Arch Linux, KVM, x86-64, ядро 7.3.5, Qt 6.12 | Нативный `.pkg.tar.zst` из `c8e016b6`. Сверены SHA-256 пакета и трёх ELF. `pacman -Qkk` подтвердил 341 файл без изменений, Qt открыл и закрыл окно в offscreen-режиме | Установленная служба отзыва DHCP запустилась и сняла маркер при остановке. Эффективные `Requires` и `After` загружены. На обоих движках просроченный CNAME отклонён, со свежим ответом прошли Fake A/AAAA и TCP/UDP. `/etc/resolv.conf` совпал |
| Arch Linux, KVM, x86-64, ядро 7.3.5, systemd-networkd 262.2 | Нативный пакет `c8e016b6`, четыре свежих гостя с двумя DHCPv4-лизингами. QMP подтвердил S3 и пробуждение в каждом госте | Xray и sing-box прошли прямой запуск `systemd-suspend.service` и SIGKILL helper перед запросом сна через logind. Набор DHCP был пуст до и сразу после сна, старые Fake-IP блокировались, штатный DNS восстановился. `/etc/resolv.conf` совпал |
| Arch Linux, KVM, x86-64, ядро 7.3.5, Qt 6.12, systemd-resolved 262 | Нативный `.pkg.tar.zst` из `8a3b93b4`, три чистых гостя. SHA-256 пакета, desktop, helper и worker совпали. `pacman -Qkk` проверил 338 файлов, установка создала `yonik-worker`, Qt открыл и штатно закрыл окно | Чужой DNS-слушатель не получил запроса. Apply отклонил просроченный CNAME, со свежим ответом прошли Fake A/AAAA и IPv4/IPv6 TCP/UDP через TLS-прокси. После перезапуска резолвера и истечения TTL старые Fake-IP остались заблокированы до свежего ответа, затем прошли HTTPS и DoH. Строгий DoT сохранился во время активной сессии, сокет с тем же UID вне cgroup был заблокирован. После Stop исходный DNS восстановился. Содержимое и метаданные `/etc/resolv.conf` совпали |
| Debian 13, KVM, x86-64, resolvconf 1.94 | Тестовый `.deb` с release-бинарниками `9af126a9` без замен после установки. DNS опубликован штатной командой `resolvconf` после удаления systemd-resolved в госте | Предыдущий пакет возвращал `Unsupported` на Prepare для прокси по имени. С новым пакетом оба движка отклонили просроченный CNAME и прошли Fake A/AAAA и TCP/UDP по свежему ответу. Подтверждён переход DNS с UDP на TCP. Ссылка, метаданные и содержимое `/etc/resolv.conf` совпали |
| Fedora Cloud 45, KVM, x86-64, NetworkManager 1.58.1, SELinux Enforcing | RPM `0.1.0-908.fc45` с release-бинарниками `9af126a9` и политикой из `b36950b1`. NetworkManager опубликовал DNS в `/run/NetworkManager/resolv.conf`. Сверены RPM и установленные ELF | По отдельности прошли оба движка. При переходе Xray → sing-box NSS вернул A/AAAA предыдущей сессии из кэша systemd-resolved. Worker sing-box продолжал работать, TCP к старому Fake-IP был сброшен. Прямой DNS-запрос к тому же имени выдал новые A/AAAA, по ним прошли IPv4/IPv6 TCP/UDP. Ссылка, метаданные и содержимое DNS-файлов совпали |
| Fedora Cloud 45, KVM, x86-64, NetworkManager 1.58.1, SELinux Enforcing | RPM `0.1.0-909.fc45` из `a03f49f0`. DNS публикует NetworkManager, NSS использует systemd-resolved. SHA-256 RPM и установленных ELF сверены | В одном госте Xray и sing-box по очереди получили свежие Fake A/AAAA для одного имени через обычный NSS. Подключения к прежним адресам блокировались по TCP и UDP. По свежим адресам прошли TCP и UDP, Stop очистил сессии. Запретов SELinux для Yonik нет. Ссылка, содержимое и метаданные обоих DNS-файлов совпали |
| Debian 13, KVM, x86-64, resolvconf 1.94 | Тестовый `.deb` с release-бинарниками `a03f49f0`. Проверены SHA-256 пакета и установленных ELF | После Xray → sing-box повторный NSS-запрос к тому же имени получил новые Fake A/AAAA. TCP и UDP прошли по свежим IPv4/IPv6, прежние адреса блокировались. Оба движка отклонили просроченный CNAME и штатно остановились. Ссылка, метаданные и содержимое `/etc/resolv.conf` совпали |
| Debian 13, KVM, x86-64, resolvconf 1.94, Fake DNS выключен | Тот же `.deb` из `a03f49f0` в отдельном госте с тестом из той же ревизии | Xray и sing-box провели TCP/UDP к реальным IPv4/IPv6. После SIGKILL helper восстановил защиту, Unlock снял её и вернул исходный DNS. Ссылка, метаданные и содержимое `/etc/resolv.conf` совпали |
| Debian 13, KVM, x86-64, systemd-resolved 257.13 | Тестовый `.deb` с release-бинарниками `8a3b93b4`, два чистых гостя. `dpkg -i` сам создал `yonik-worker`, проверены `dpkg -V` и SHA-256 установленных ELF | Чужой DNS-слушатель не получил запроса. Apply отклонил истёкший CNAME. Свежий профиль, Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS и DoH прошли. После перезапуска резолвера и истечения TTL старые Fake-IP блокировались на физическом выходе и в новой сессии до свежего DNS-ответа. После Stop штатный DNS восстановлен. Содержимое и метаданные `/etc/resolv.conf` совпали |
| Fedora Cloud 45, KVM, x86-64, SELinux Enforcing | RPM `0.1.0-905.fc45` по штатному spec с release-бинарниками `8a3b93b4`. Скрипт установки создал `yonik-worker`. SHA-256 установленных ELF совпали, `rpm -V` прошёл после установки и сетевого прогона | Штатный DNS, Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS и DoH прошли. После перезапуска systemd-resolved сессия остановилась, DNS отозван, повторное подключение подтвердилось. После Stop и Unlock сеть восстановилась. Отдельно на обоих движках подтверждён отказ Apply после истечения CNAME через stub и подключение по свежему DNS-ответу. `/etc/resolv.conf` совпал до и после |
| Arch Linux, ядро 7.2.11 | Установленные helper и worker, клиент desktop backend | Системный TUN, Fake DNS, HTTPS, Stop и Unlock |
| Arch Linux, KVM, x86-64, ядро 7.3.5 | Локальный пакет из `7b5da59`, собранный в чистой VM. Рецепт и SHA-256 всех трёх установленных ELF сверены с архивом | Установка, 143 шага UI, повторная установка и удаление прошли. Проверены сохранность пользовательских данных, чужой таблицы nftables и интерфейса. На Xray и sing-box прошли системный TUN, Fake A/AAAA, TCP/UDP IPv4/IPv6, HTTPS с проверкой сертификата, DoH через TUN и возврат к FallbackDNS после Stop. Прежние Fake-IP заблокированы. В прогоне Xray защита восстановилась после удаления таблицы nftables. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux, KVM, x86-64, ядро 7.3.5, Qt 6.12 | Локальный `.pkg.tar.zst` из `4658ace3`, собранный через `makepkg` с закреплённым архивом исходников и четырьмя задачами Cargo. SHA-256 архива и трёх установленных ELF сверены | `pacman -Qkk` проверил 338 файлов, Qt открыл и штатно закрыл окно. На Xray подтверждены Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS и DoH. В двух прогонах `Stop` вернул `unavailable`. После отказа остались таблица блокировки, таблица карантина и правила выбора таблицы маршрутизации TUN. Полный цикл на Xray и прогон sing-box остаются открытыми |
| Arch Linux, KVM, x86-64, ядро 7.3.5, nftables 1.1.7, Qt 6.12 | Нативный `.pkg.tar.zst` из `54334d03`. `pacman -Qkk` проверил 338 файлов. SHA-256 архива, desktop, helper и worker сверены после установки | Qt открыл и штатно закрыл окно. Во время активной сессии nftables вернул `count: 1` в DHCP-наборе. Xray и sing-box прошли системный DNS, Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS, DoH и Stop. На Xray проверены Unlock и восстановление защиты Fake-IP после удаления таблицы nftables. Для обоих движков восстановились FallbackDNS и обычная сеть. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux, KVM, x86-64, ядро 7.3.5, nftables 1.1.7 | Тот же пакет `54334d03` в отдельной VM. SHA-256 архива и трёх установленных ELF совпали с предыдущим прогоном | После перезапуска systemd-resolved на Xray и sing-box прежние Fake-IP обоих семейств блокировались на физическом выходе после истечения DNS TTL и в новой сессии до свежего DNS-ответа. После получения нового ответа прошли TCP/UDP, HTTPS и DoH. После Stop вернулся FallbackDNS. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux, KVM, x86-64, systemd-networkd 262.2, nftables 1.1.7 | Пакет `54334d03`, совпали SHA-256 архива и трёх установленных ELF. Два DHCPv4-лизинга на тестовых линках и статическая конфигурация `eth0` в VM | Xray и sing-box продлили оба лизинга с активным TUN. На sing-box первый лизинг дополнительно продлился при недоступном втором DHCP-сервере. После продления прошли Fake A/AAAA и трафик через TUN. После Stop снялся временный DHCP-набор, на Xray прошёл Unlock. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux, KVM, x86-64, ядро 7.3.5, Qt 6.12 | Установленный пакет `54334d03`. Отдельный Qt-процесс под обычным UID для каждого движка, offscreen и временное правило polkit для этого UID. SHA-256 пакета и установленных ELF совпали с основным прогоном | Оба клиента импортировали тестовый профиль, включили Fake DNS и запустили системный TUN кнопкой. Независимый процесс подтвердил Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS с проверкой имени и DoH. Оба клиента выполнили Stop и Unlock, закрылись в `NoManagedPolicy`. Интерфейс TUN снят, обычный DNS восстановлен, ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux, KVM, x86-64, ядро 7.3.5, nftables 1.1.7 | Установленный пакет `54334d03`, SHA-256 архива и установленных ELF совпали с основным прогоном. Смена физического маршрута к VLESS peer | Xray и sing-box автоматически остановили старую сессию и отозвали DNS. Переподключение уложилось в исходный TTL, прежние Fake-IP остались заблокированы. VLESS-сервер подтвердил HTTPS через второй интерфейс для обоих движков. `/etc/resolv.conf` совпал до и после |
| Arch Linux, KVM, x86-64, ядро 7.3.5, виртуальный Wi-Fi `mac80211_hwsim` | Нативный пакет `1884ea18`, установленные ELF сверены с архивом. `hostapd` поднял две точки, `wpa_supplicant` подтвердил переход на второй BSSID и возврат к первому | Xray и sing-box остановили прежний worker, отозвали DNS и переподключились в пределах исходного TTL. Прошли новые Fake A/AAAA, TCP/UDP, HTTPS с проверкой сертификата и DoH. VLESS peer получил трафик через обе точки и ни одного пакета к VLESS по Ethernet. Ссылка, метаданные и содержимое `/etc/resolv.conf` совпали |
| Debian 13.7, KVM, x86-64, ядро 6.12.117+deb13-amd64, systemd-resolved и виртуальный Wi-Fi `mac80211_hwsim` | Установленный тестовый `.deb` из `eebcca65`, SHA-256 обоих ELF сверены с архивом, `dpkg -V` прошёл. `hostapd` и `wpa_supplicant` 2.10 подтвердили смену BSSID и возврат для каждого движка | Xray и sing-box отозвали DNS-зону, остановили прежний worker и переподключились с новыми Fake A/AAAA в пределах исходного TTL. Прошли TCP/UDP, HTTPS и DoH. Счётчики VLESS подтвердили 40 пакетов через первую точку, 104 через вторую и 0 по Ethernet. Ссылка, метаданные и содержимое `/etc/resolv.conf` совпали |
| Debian 13.7, KVM, x86-64, systemd-resolved 257.13 | Установленный `.deb` из `eebcca65`. Единственный исходный DNS-сервер остановлен и запущен заново при активном TUN. Проверены SHA-256 ELF и `dpkg -V` | Запрос без кэша к исходному DNS остался без ответа на обоих движках. IPv4/IPv6 TCP/UDP по выданным Fake-IP продолжил работать с прежним PID worker. После запуска сервера исходный DNS восстановился. Прошли Stop и Unlock при включённом kill switch. Содержание и метаданные `/etc/resolv.conf` совпали |
| Debian 13.7 и Ubuntu 24.04.5 LTS, KVM, x86-64, systemd-resolved | Тестовые `.deb` с ELF из `eebcca65`. После сетевого цикла обоих движков выполнены Stop, Unlock и `dpkg -r` | Обе сборки удалили бинарники и unit, но оставили процесс helper. После его отдельной остановки элементы карантина IPv4/IPv6 сохранили остаток TTL в 84 с и истекли в ядре. Обычный DNS ответил до и после истечения. `/etc/resolv.conf` совпал. Автоматическая остановка helper при удалении `.deb` остаётся открытой |
| Debian 13.7 и Ubuntu 24.04.5 LTS, KVM, x86-64, systemd-resolved | Отдельные тестовые `.deb` с теми же ELF из `eebcca65` и сценариями `prerm` и `postrm`. `prerm` запрашивает состояние helper и останавливает его до удаления файлов, а `postrm` перечитывает конфигурацию systemd | Для Xray и sing-box отказ удаления при активном TUN сохранил PID и IPv4/IPv6 TCP/UDP. После Stop и Unlock `dpkg -r` автоматически остановил helper. Карантин обеих семей сохранил около 84 с до истечения в ядре. Обычный DNS работал, `/etc/resolv.conf` совпал. Сценарии предстоит включить в поддерживаемый рецепт `.deb` |
| Arch Linux, KVM, x86-64, ядро 7.3.5, nftables 1.1.7, `dhcpcd 10.5.2-2` | Нативный пакет `b507e0a1`, установленный в отдельных ВМ. `pacman -Qkk` проверил 338 файлов, SHA-256 архива и трёх установленных ELF совпали | Глобальная служба `dhcpcd.service` продлила DHCPv4-лизинг в T1 при активном TUN на Xray и sing-box. Счётчик на внешнем интерфейсе подтвердил DHCP-запрос. При прежнем PID worker прошли Fake A/AAAA и TCP/UDP по IPv4 и IPv6, затем Stop и Unlock. Отдельный прогон Wi-Fi повторил смену BSSID, HTTPS и DoH на обоих движках. Содержимое и метаданные `/etc/resolv.conf` совпали |
| Arch Linux, KVM, x86-64, ядро 7.3.5, nftables 1.1.7 | Тот же пакет `b507e0a1` в отдельной ВМ. SHA-256 desktop, helper и worker совпали с архивом | После перезапуска systemd-resolved и истечения DNS TTL оба движка блокировали старые Fake IPv4 и IPv6 на физическом выходе и в новой сессии до свежего DNS-ответа. После нового ответа прошли TCP/UDP, HTTPS и DoH, после Stop восстановился исходный FallbackDNS. Содержимое и метаданные `/etc/resolv.conf` совпали |
| Arch Linux, KVM, x86-64, ядро 7.3.5, nftables 1.1.7, `dhcpcd 10.5.2-2` | Нативный пакет `08f66b21`, прошли `pacman -Qkk` и сверка SHA-256 трёх ELF с архивом | Глобальный `dhcpcd.service` и экземпляр `dhcpcd@.service` продлили DHCPv4 при активном TUN на Xray и sing-box. Внешний счётчик подтвердил запрос T1, worker сохранил PID. Прошли Fake A/AAAA, TCP/UDP по обоим семействам, Stop и Unlock. Первый глобальный прогон Xray завершился по тайм-ауту до T1 во время параллельной приёмки. Изолированный повтор с тем же пакетом прошёл. `/etc/resolv.conf` совпал до и после |
| Arch Linux, KVM, x86-64, ядро 7.3.5, systemd-resolved 262 | Тот же пакет `08f66b21`, отдельные ВМ для TTL и строгого DoT, сверены пакет и установленные ELF | На обоих движках после перезапуска резолвера старые Fake IPv4/IPv6 заблокированы на физическом выходе после TTL и в новой сессии до свежего DNS-ответа. Строгий DoT на 1853 использовал TLS 1.3, отклонил неверное имя сертификата, сохранил блок для сокета с UID резолвера вне его cgroup и восстановился после Stop. HTTPS, DoH и сверка `/etc/resolv.conf` прошли |
| Arch Linux, KVM, x86-64, LightDM и Openbox (X11), polkit 128 и lxqt-policykit 2.5.0 | Установленный пакет `54334d03`. Обычный UID в активной локальной сессии, один администратор в `wheel`, штатная политика `auth_admin`. SHA-256 архива и трёх установленных ELF сверены | Qt запустил TUN кнопкой. Для каждого движка после смены маршрута прошли Stop, Unlock и переподключение. До и после смены проверены Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS и DoH. Сервер подтвердил HTTPS через второй интерфейс. После отключения восстановились правила маршрутизации и обычный DNS, TUN снят. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux, KVM, x86-64, ядро 7.3.5, nftables 1.1.7 | Тот же пакет `54334d03` в двух отдельных ВМ, SIGKILL установленного helper при активном TUN | После автоматического перезапуска Xray сохранил kill switch до Unlock. Sing-box восстановил обычную сеть без Unlock. В обоих прогонах прежние Fake-IP фильтровались, а таблица карантина была снята после истечения срока в ядре. `/etc/resolv.conf` совпал до и после |
| Arch Linux ARM, QEMU, AArch64, ядро 7.3.5, Qt 6.12 | Нативный локальный пакет `84d48fe`, полученный штатным `makepkg` в формате `.pkg.tar.xz`. Метаданные рецепта и контрольные суммы трёх установленных ELF сверены с архивом | Qt запустился и штатно закрылся. Xray и sing-box прошли Fake A/AAAA, реальные DNS по TCP/UDP на 53, трафик IPv4/IPv6, HTTPS, DoH и Stop. Без helper карантин обоих семейств истёк в ядре через 84,7 с. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, ядро 7.3.5, Qt 6.12 | Повторная нативная сборка `4a773d8` через `makepkg` с `.pkg.tar.xz`. SHA-256 архива совпал с гостевой копией. `pacman -Qkk` проверил все 338 файлов, SHA-256 трёх ELF совпали с архивом | Установленный Qt-клиент открыл окно и штатно закрылся. Xray и sing-box прошли Fake A/AAAA, реальный DNS по UDP/TCP, трафик IPv4/IPv6, HTTPS, DoH, Stop и восстановление. Счётчик внешнего выхода Fake-IP равен нулю. Без helper карантин обоих семейств истёк в ядре через 84,5 с. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, ядро 7.3.5 | Установленные GNU helper и worker, systemd 262.2, nftables 1.1.7. Штатная ссылка `/etc/resolv.conf` на upstream-файл systemd-resolved. Отдельные прогоны с глобальным DNS и FallbackDNS | NSS и прямые DNS-запросы по TCP/UDP на порт 53, HTTPS, DoH, Stop и Unlock. Ссылка `/etc/resolv.conf` и содержимое файла совпали до и после. В сценарии с глобальным DNS systemd-resolved при Stop пересоздал свой файл в `/run` |
| Arch Linux ARM, QEMU, AArch64, systemd 262.2 | Установленный helper, uplink-файл, строгий DoT. Отдельные прогоны с глобальным DNS и FallbackDNS | Оба движка обслужили NSS, реальные и синтетические ответы при прямом подключении по TCP/UDP на порт 53, HTTPS, DoH и восстановление после Stop. Для реальных DNS-запросов стенд подтвердил TLS 1.3. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, systemd 262.2 | Установленный helper, строгий DoT в режиме uplink, тестовый CA доступен systemd-resolved, порт 53 работает по TCP и UDP | На обоих движках helper отказал прямым запросам реального DNS при недоверенном сертификате. Обычный сервер на порту 53 не получил этих запросов. NSS через systemd-resolved по TLS 1.3, Fake DNS и HTTPS продолжили работать. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, systemd 262.2 | Установленный helper, uplink-файл, строгий DoT для глобального DNS и отдельного линка с `DefaultRoute=no` и `~private.test` | Оба движка получили через NSS ответы приватного TLS-сервера. Адрес сервера отсутствовал в uplink-файле, прямые запросы Fake DNS к его порту 53 по TCP и UDP остались без синтетического ответа. Глобальный DNS и Fake DNS работали через опубликованный адрес. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, systemd 262.2 | Установленный helper, uplink-файл, глобальный DNS и opportunistic DoT, тестовый сервер обслуживает только обычный DNS | После сброса обнаруженных возможностей сервера NSS и релей прямых запросов получили ответы с переходом на обычный DNS. Fake DNS, HTTPS, DoH и восстановление прошли на обоих движках. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, systemd 262.2 и nftables 1.1.7 | Установленные ELF helper и worker, uplink-файл с обычным FallbackDNS, счётчики на обоих внешних интерфейсах | Оба движка прошли сетевой цикл. На внешних интерфейсах прошли TCP к VLESS и обычный DNS по TCP и UDP, пакетов с Fake-IP не зафиксировано. После остановки helper карантин IPv4 и IPv6 сохранился и истёк в ядре. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, systemd 262.2 | Установленный helper, отзыв DNS-зоны активного TUN через resolve1, uplink-файл | На обоих движках старый worker завершился автоматически. После повторного подключения прошли новые Fake A/AAAA, TCP/UDP и HTTPS. Старые Fake-IP остались заблокированы в пределах исходного TTL. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, systemd 262.2 | Установленный helper, uplink-файл. Перезапуск systemd-resolved при активном TUN с обычным FallbackDNS и в отдельном прогоне со строгим DoT | На обоих движках сменился владелец D-Bus и завершился прежний worker. Повторное подключение выдало новые Fake A/AAAA в пределах исходного TTL, прежние адреса остались заблокированы. После Stop штатный DNS ответил через настроенный FallbackDNS или по TLS 1.3 соответственно. HTTPS и DoH прошли. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, systemd 262.2 | Установленный helper, смена маршрута к VLESS peer на второй физический интерфейс стенда | Оба движка автоматически остановили старую сессию и подключились заново. VLESS-сервер подтвердил новое подключение с адреса второго интерфейса. Прошли новые Fake A/AAAA, TCP/UDP и HTTPS. Старые Fake-IP остались заблокированы, ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, systemd 262.2, wireguard-tools 1.0.20260223 | Установленный helper, внешний WireGuard с обоими порядками запуска и отдельный прогон с приватным split-DNS | Xray и sing-box переподключились после появления WireGuard и сохранили его интерфейс, маршруты, endpoint и AllowedIPs. Пересечение маршрута с Fake-IP отклонено. Во время активного Fake DNS приватный трафик блокировался до VLESS. Приватные DNS и TCP/UDP прошли до запуска и после Stop. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, systemd 262.2 | Установленный helper, SIGKILL и автоматический перезапуск при активном TUN, обычный FallbackDNS | Xray сохранил kill switch до Unlock. В сценарии sing-box обычная сеть восстановилась без Unlock. После перезапуска прежние Fake-IP фильтровались до истечения карантина. Системный DNS отвечал после восстановления, ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Arch Linux ARM, QEMU, AArch64, ядро 7.3.5, systemd 262.2 | Нативный пакет `4a773d87`, установлен через pacman | Хеши desktop, helper и worker совпали с архивом. Установленный desktop открыл и штатно закрыл окно в offscreen-режиме. Установленный helper прошёл сетевой сценарий на Xray и sing-box с Fake A/AAAA, DNS по TCP и UDP, HTTPS, DoH и карантином старых Fake-IP |
| Arch Linux ARM, QEMU, AArch64, ядро 7.3.5, systemd 262.2 | Кросс-собранные GNU helper и worker из `4658ace3`, установленные с файлами служб из той же ревизии. SHA-256 обоих ELF совпали с входами установки | Xray и sing-box прошли DNS по TCP/UDP, Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS, DoH и возврат к FallbackDNS после Stop. На Xray проверены Unlock и восстановление защиты Fake-IP после удаления таблицы nftables. Ссылка, содержимое и проверяемые метаданные `/etc/resolv.conf` совпали. Нативная сборка полного пакета из этой ревизии остаётся открытой |
| Arch Linux ARM, QEMU, AArch64, ядро 7.3.5, nftables 1.1.7 | Кросс-собранные GNU helper и worker из `54334d03`, установленные с файлами служб той же ревизии. SHA-256 установленных ELF совпали с входами установки | На Xray и sing-box повторно прошли системный DNS по TCP/UDP, Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS, DoH, Stop и возврат к FallbackDNS. На Xray проверены Unlock и восстановление защиты Fake-IP после удаления таблицы nftables. Ссылка и содержимое `/etc/resolv.conf` совпали |
| Arch Linux ARM, QEMU Cortex-A76, AArch64, ядро 7.3.5, Qt 6.12 | Нативный `.pkg.tar.xz` из `54334d03`, собранный через `makepkg` и установленный через `pacman`. `pacman -Qkk` проверил 338 файлов, SHA-256 архива и трёх ELF сверены | Установленный Qt-клиент открыл и штатно закрыл окно. На Xray и sing-box прошли системный DNS по TCP/UDP, Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS, DoH и восстановление. В отдельном прогоне после перезапуска systemd-resolved прежние Fake-IP обоих семейств блокировались на физическом выходе после DNS TTL и в новой сессии до свежего DNS-ответа. Ссылка и содержимое `/etc/resolv.conf` совпали в обоих прогонах |
| Debian 13.7 | Установленный helper с systemd-resolved и отдельный стенд DNS по адресу | NSS и DNS TCP/UDP, Fake DNS A/AAAA, HTTPS, DoH, восстановление и карантин Fake-IP. Отдельно проверены смена маршрута, переподключение DHCPv4, отзыв DNS-зоны и HTTP/3 в Firefox с системным DNS и строгим DoH |
| Debian 13, KVM, x86-64, ядро 6.12.117, nftables 1.1.3, `dhcpcd 10.1.0` | Тестовый `.deb` из `08f66b21`, установленный в двух свежих ВМ. SHA-256 helper и worker сверены с архивом, `dpkg -V` прошёл до и после проверки | Глобальный `dhcpcd.service` продлил лизинг через прежний управляющий сокет при активном TUN. На Xray и sing-box зафиксированы второй DHCPACK в T1, один исходящий DHCP-запрос, тот же PID worker, Fake A/AAAA, TCP/UDP по обоим семействам, Stop и Unlock. Содержимое и метаданные `/etc/resolv.conf` совпали |
| Debian 13.7, QEMU, x86-64 | Установленные helper и worker, публичный профиль Fake DNS с доменными и CIDR-условиями, явный DNS политики через VLESS | Оба движка прошли Proxy по имени без запроса к DNS политики, приоритет CIDR над младшим доменным Proxy, смешанные Block и Direct, отказ при SERVFAIL и успешный Direct при подтверждённом NODATA AAAA. Отдельное обращение к буквальному IP сохранило собственную политику. Проверены TCP/UDP, HTTPS, DoH, Stop, Unlock и неизменность `/etc/resolv.conf` |
| Debian 13.7, QEMU, x86-64 | Desktop backend с сохранённым адресом DNS политики и установленными helper и worker | Desktop передал адрес DNS и смешанную политику при подключении. Оба движка прошли HTTPS через Fake-IP, TCP/UDP по имени без запроса к DNS политики, смешанный Block, Stop и Unlock. Во время активного TUN изменение адреса отклонено. Содержимое и метаданные `/etc/resolv.conf` совпали |
| Debian 13.7, QEMU, x86-64 | Установленный стендовый helper с автономным worker, отдельным mount namespace, seccomp и системным D-Bus | Восстановление после прежнего worker, Prepare, Apply, Stop, Unlock, Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS по Fake-IP и DoH через TUN. При остановке службы с активной сессией TUN удаляется, cgroup пустеют, карантин Fake-IP сохраняется |
| Debian 13, KVM, x86-64, systemd | Тестовый `.deb` с установленными через dpkg helper и worker из `4658ace3`; сервис использует `StateDirectory=yonik` | Со строгим DoT на обоих движках подтверждены перезапуск systemd-resolved, автоматическая остановка старого worker, отзыв DNS и переподключение до истечения TTL. Новые Fake-IP работали по TCP/UDP, через HTTPS и DoH. Состояние `/etc/resolv.conf` совпало до и после |
| Debian 13, KVM, x86-64, OpenRC и runit | Тестовые `.deb` из `4658ace3`; хеши установленных ELF совпали с входами сборки. FallbackDNS systemd-resolved, системная шина, временное правило polkit для root | Оба движка прошли Fake A/AAAA, TCP/UDP IPv4/IPv6, HTTPS, DoH и остановку службы при активной сессии. Служба остановила worker и очистила сетевые ресурсы, прежние Fake-IP остались в карантине. Состояние `/etc/resolv.conf` совпало до и после |
| Debian 13, KVM, x86-64, OpenRC и runit, resolvconf 1.94 | Повторная установка тех же тестовых `.deb` из `4658ace3` в отдельных ВМ. Адрес DNS менялся через resolvconf | Оба движка прошли автоматическое завершение старой сессии и переподключение, реальные DNS по TCP/UDP, Fake A/AAAA, HTTPS и DoH. Прежние Fake-IP остались заблокированы. После восстановления настройки через resolvconf ссылка и содержимое `/etc/resolv.conf` совпали. Первый прогон OpenRC получил один `Unsupported` при повторном Prepare Xray; повтор с тем же пакетом прошёл на обоих движках |
| Debian 13.7, QEMU, AArch64, systemd 257 и nftables 1.1.3 | Установленные GNU helper и worker без `test-support`, systemd-resolved с FallbackDNS, явная политика Proxy. Xray 26.10.31 и закреплённый адаптер sing-box 1.14.4 | Fake A/AAAA, TCP/UDP по IPv4 и IPv6, HTTPS с проверкой имени, DoH, Stop, Unlock, блокировка старых Fake-IP и восстановление DNS. На Xray также проверено восстановление карантина после удаления таблицы nftables. Содержимое и метаданные `/etc/resolv.conf` совпали до и после |
| Debian 13.7, QEMU, arm64, systemd 257.13, ядро 6.12.117 | `yonik-helper_0.1.0-1_arm64.deb` из `07c2fb93`. Две сборки с одинаковыми входами совпали побитово. SHA-256 установленных helper и worker совпали с исходными ELF | Установка, обновление и откат через dpkg прошли. Во время обслуживания отклонены новый Apply и активация helper, при активном TUN отклонены обновление и удаление. На Xray и sing-box проверены повторное подключение после остановки процесса ядра, а также сохранение worker, Fake A/AAAA и трафика при недоступности исходного DNS. После Stop и Unlock удаление завершило helper, IPv4- и IPv6-карантин истёк в ядре. Содержимое и метаданные `/etc/resolv.conf` совпали до и после |
| Debian 13.7, QEMU, AArch64, OpenRC 0.56 и runit 2.2, resolvconf 1.94 | Тестовый `.deb` из дерева пакетирования, установленный через `dpkg`. Штатные helper и worker без `test-support`. Доступ root выдан правилом одноразовой VM | В обеих VM служба открыла TUN после загрузки нужного PID 1. На Xray и sing-box смена резолвера закрыла прежний worker, старые Fake-IP остались заблокированы. Прошли реальные DNS-запросы по UDP и TCP, Fake A/AAAA, HTTPS и DoH. Ссылка и содержимое `/etc/resolv.conf` совпали после возврата DNS через resolvconf |
| Debian 13.7, QEMU, x86-64 и AArch64, OpenRC 0.56 и runit 2.2 | Установленный helper, запуск штатным менеджером, systemd-resolved с обычным FallbackDNS | На обоих движках прошли загрузка TUN, Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS по Fake-IP, DoH через TUN, остановка службы и восстановление. При остановке исчез TUN, cgroup worker опустели, карантин Fake-IP сохранился. Polkit использовал временное правило стенда для root. Обычному UID вызов Prepare отклонён |
| Debian 13.7, OpenRC 0.56 и runit 2.2, resolvconf 1.94 | Установленный helper, DNS опубликован resolvconf, systemd-resolved удалён средствами пакета. Доступ root выдан правилом одноразовой VM | На обоих движках смена DNS остановила прежний worker. Новые Fake A/AAAA, реальные ответы DNS по TCP/UDP, HTTPS и DoH прошли. Старые Fake-IP остались заблокированы. Ссылка и исходное содержимое `/etc/resolv.conf` совпали после возврата настроек менеджером |
| Debian 13.7, OpenRC 0.56 и runit 2.2, elogind 255.17 и polkit 126 | Обычный UID в локальном PAM-сеансе на `seat0`, установленный helper и штатная политика `auth_admin` | В обеих VM без агента `Prepare` отклонён. После проверки пароля отдельной учётной записи администратора через `pkttyagent` helper вернул дескриптор подготовки |
| Debian 13.7, x86-64, OpenRC 0.56 и runit 2.2, Xfce 4.20 и X11 | Установленный helper, штатная политика `auth_admin`, обычный UID в локальном сеансе LightDM и elogind | В обеих VM окно `mate-polkit` запросило пароль. После проверки пароля системный D-Bus вернул дескриптор `Prepare` процессу из графической сессии |
| Debian 13.7, resolvconf 1.94, systemd-resolved неактивен | Установленный helper, отдельные прогоны с IPv4- и IPv6-адресами резолвера, опубликованными менеджером в `/etc/resolv.conf` | NSS, Fake DNS A/AAAA и реальные ответы по TCP/UDP, HTTPS, DoH, Stop, Unlock и восстановление после смены адреса через `resolvconf -a`. Истечение карантина проверено в сценарии с IPv4-резолвером |
| Debian 13.7, systemd-resolved и внешний WireGuard | Установленный helper, приватная DNS-зона и маршруты IPv4/IPv6 через WireGuard | Публичный Fake DNS работает, обнаруженные приватные префиксы блокируются во время сессии. Приватный DNS и TCP/UDP доступны до запуска и после Stop |
| Debian 13.7, Xfce 4.20 и X11, ядро 6.12.117 | Обычный UID в активной сессии LightDM и штатный диалог polkit. Отдельные прогоны с systemd-resolved и resolvconf 1.94 | Системный TUN, Fake DNS, IPv4/IPv6 TCP/UDP, HTTPS, DoH, Stop, Unlock и карантин Fake-IP |
| Ubuntu 24.04.5 LTS без графической сессии | Установленный helper, ядро 6.8.0-147, nftables 1.0.9 | TUN, Fake DNS, HTTPS, DoH и восстановление правил. Отдельно проверены смена маршрута, переподключение DHCPv4 и отзыв DNS-зоны |
| Ubuntu 24.04.5 с systemd 255 и Debian 13.7 с systemd 257 | Установленный helper, четыре обычных `FallbackDNS`, без настроенного глобального или per-link DNS | На обоих движках получены реальные ответы NSS и Fake A/AAAA. HTTPS и DoH прошли через TUN. После Stop резервный DNS ответил для нового имени |
| Debian 13.7, Ubuntu 24.04.5 и Fedora Cloud 45 с SELinux Enforcing | Установленный helper и строгий DoT при использовании только `FallbackDNS` | Реальный NSS во время активной сессии и после Stop, Fake A/AAAA, HTTPS и DoH прошли на обоих движках |
| Debian 13.7, Ubuntu 24.04.5 и Fedora Cloud 45 с SELinux Enforcing | Установленный helper и `opportunistic` DoT при использовании только `FallbackDNS` | TLS подтверждён в Ubuntu и Fedora. Переход с TLS на UDP и TCP подтверждён в Debian и Ubuntu. Fake DNS и восстановление прошли на обоих движках |
| Ubuntu 24.04.5 LTS, GNOME Shell 46 и Wayland, Qt 6.4.2 | Видимый Qt-клиент в активной сессии GDM, обычный UID и штатная политика polkit | TUN, Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS, DoH, Stop, Unlock и истечение карантина после остановки helper |
| Fedora Cloud 45, SELinux Enforcing | Установленный RPM, root-клиент на системной шине | TUN и Fake DNS, продление двух лизингов systemd-networkd 262, S3 через logind, обновление при остановленном helper и удаление с истечением карантина |
| Fedora Cloud 45, QEMU, AArch64, SELinux Enforcing | Установленный RPM, ядро 7.2.11, systemd 262.1, nftables 1.1.6, systemd-resolved с FallbackDNS. Штатный helper в `yonik_helper_t` с `NoNewPrivs=1` | Xray и закреплённый sing-box прошли Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS, DoH и восстановление DNS после Stop. Карантин старых Fake-IP сохранился. Содержимое и метаданные `/etc/resolv.conf` совпали до и после |
| Fedora Cloud 45, QEMU, AArch64, SELinux Enforcing | Обновление RPM с ревизии 1 на 2 при остановленном helper, затем удаление RPM | Удаление при активном Xray TUN отклонено. После обновления полный сетевой сценарий прошли Xray и sing-box. После удаления IPv4- и IPv6-элементы карантина остались в nftables и истекли через 82,7 с при остановленном helper. Содержимое и метаданные `/etc/resolv.conf` совпали до и после |
| Fedora Cloud 45, QEMU, AArch64, SELinux Enforcing | Локальный RPM `0.1.0-3.fc45`, код helper и worker из `3ccc527`. Обычный FallbackDNS и отдельный прогон перезапуска systemd-resolved | DNF установил локальный пакет. SHA-256 установленных ELF совпали с архивом, helper запустился в `yonik_helper_t` с `NoNewPrivs=1`. Xray и sing-box прошли Fake A/AAAA, TCP/UDP IPv4/IPv6, HTTPS, DoH, Stop, восстановление DNS и проверку карантина. Содержимое и метаданные `/etc/resolv.conf` совпали до и после. При перезапуске resolved прежний Xray worker остановился через 2,7 с после начала перезапуска. Повторное подключение превысило 30-секундное окно проверки TTL. В отдельном прогоне с трассировкой два Prepare с проверкой ядра заняли 10,5 и 11,3 с, первый завершился с `Stale`, а последующий Apply исчерпал дедлайн клиента |
| Fedora Cloud 45, QEMU, AArch64, SELinux Enforcing | Тот же установленный RPM `0.1.0-3.fc45`. Отдельный сценарий `production_helper_fake_dns_after_resolver_restart_and_ttl` ждёт истечения DNS TTL перед повторным подключением | На Xray и sing-box старые Fake-IP остались заблокированы на физическом выходе после TTL, затем проверено отсутствие доступа к старым адресам в новой сессии до свежего DNS-ответа. После нового ответа прошли TCP/UDP IPv4/IPv6, HTTPS и DoH. После Stop штатный FallbackDNS ответил на новое имя. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Fedora Cloud 45, QEMU, AArch64, SELinux Enforcing | Строгий тест перезапуска resolved с диагностической сборкой helper после изменения отмены Prepare. Пакетный worker остался из RPM `0.1.0-3.fc45` | Устаревшие Prepare с Xray и sing-box завершились за 1,9 и 3,4 с соответственно. Xray восстановился в пределах DNS TTL. Sing-box восстановил туннель, но вышел за 30-секундное окно теста. Результат ожидает проверки с пересобранным RPM |
| Fedora Cloud 45, QEMU, AArch64, SELinux Enforcing | Локальный RPM `0.1.0-4.fc45` с правкой `b4c5a23`. Хеши helper и worker совпали после сборки, в архиве и после установки | Оба движка прошли обычный сетевой цикл и восстановление после истечения TTL. Старые Fake-IP блокировались до свежего DNS-ответа. HTTPS, DoH, Stop и возврат к FallbackDNS прошли, `/etc/resolv.conf` совпал до и после. В строгом сценарии Xray восстановился в пределах TTL, Prepare sing-box вернул `Unsupported` до запуска нового Check. Строгий сценарий sing-box остаётся открытым |
| Fedora Cloud 45, QEMU, AArch64, SELinux Enforcing | Локальный RPM `0.1.0-5.fc45` из `752865e` с общим дедлайном подтверждения Check. SHA-256 артефактов сборки, RPM и установленных ELF совпали | Базовый прогон и восстановление после истечения TTL прошли на обоих движках. Старые Fake-IP блокировались на физическом выходе и до свежего DNS-ответа в новой сессии. HTTPS, DoH, Stop и возврат к FallbackDNS прошли. Ссылка и содержимое `/etc/resolv.conf` совпали до и после. В строгом прогоне Xray восстановился в пределах TTL. Sing-box завершил повторные Prepare и Apply в обоих порядках запуска, а получение новых ответов вышло за пределы 30-секундного окна теста |
| Fedora Cloud 45, QEMU, AArch64, SELinux Enforcing | Локальный RPM `0.1.0-6.fc45` из `6c0e4fb`. RPM обновил предыдущую ревизию. SHA-256 обоих ELF совпали после сборки, в RPM и после установки | На Xray и sing-box после перезапуска resolved подтверждены блокировка старых Fake-IP на физическом выходе после TTL, блокировка до свежего DNS-ответа, новые ответы, TCP/UDP, HTTPS, DoH и восстановление FallbackDNS после Stop. Ссылка и содержимое `/etc/resolv.conf` совпали до и после. Строгий прогон Xray прошёл. В обоих строгих прогонах sing-box Prepare и Apply завершились, а новое разрешение имён вышло за пределы 30-секундного окна теста. Перед успешным Prepare была отменена устаревшая попытка длительностью 3,6–3,9 с |
| Fedora Cloud 45, QEMU, AArch64, SELinux Enforcing | Локальный RPM `0.1.0-7.fc45` из `02d623a`. ELF сверены после сборки, в архиве и после обновления. В отдельном прогоне использован клиент из `c83ed847` | После переноса проверки поколения сети один устаревший Prepare sing-box занял 191 мс. В обоих строгих прогонах первые повторные сессии вышли за 30-секундное окно. С клиентом `c83ed847` Xray прошёл восстановление после TTL и повторную проверку блокировки старых Fake-IP. Следующий запуск sing-box исчерпал общий дедлайн при Apply |
| Fedora Cloud 45, QEMU, AArch64, SELinux Enforcing | Штатный RPM7 из `02d623a` с клиентом и тестом из `4911bf13`. Стенд завершил начальную настройку сети до запуска helper и сверил SHA-256 установленных ELF | На Xray и sing-box прошли отдельные прогоны восстановления до и после истечения исходного TTL. При восстановлении раньше TTL прежние Fake-IP блокировались, а новая сессия выдала другие Fake A/AAAA. После TTL проверена блокировка прежних адресов на физическом выходе и в новой сессии до свежего DNS-ответа. TCP/UDP, HTTPS, DoH, Stop и возврат к FallbackDNS прошли. Ссылка и содержимое `/etc/resolv.conf` совпали до и после обоих прогонов |
| Fedora Cloud 45, KVM, x86-64, SELinux Enforcing | Локальный RPM `0.1.0-7.fc45` из `02d623a`. ELF сверены после сборки, в архиве и после установки. Повтор Prepare проверен клиентом из `c83ed847` | Старый клиент завершил запуск после двух последовательных `Stale`. Новый клиент получил дескриптор с третьего Prepare и успешно выполнил Apply на Xray. Два ответа `Stale` отдельно покрыты воспроизводимым D-Bus-тестом. В другом прогоне Apply вернул `Unavailable`. Диагностика воспроизвела отказ проверки внешней топологии после старта worker |
| Fedora Cloud 45, KVM, x86-64, SELinux Enforcing | Диагностический helper с журналом топологии и worker из RPM7. Тест из `4911bf13` дожидается смены владельца resolve1 на D-Bus в пределах прежнего TTL | Строгий сценарий для Xray и sing-box дважды прошёл примерно за 16 с суммарно. Ссылка и содержимое `/etc/resolv.conf` совпали до и после. При повторе со штатным RPM7 Xray запустился, применил DNS и остановился до тестового перезапуска resolved, когда helper был запущен до настройки исходной сети стенда |
| Fedora Cloud 45, KVM, x86-64, SELinux Enforcing | Штатный RPM7 из `02d623a` с клиентом и тестом из `4911bf13`. Перед запуском helper стенд закончил настройку NetworkManager и проверил исходный DNS | Строгий прогон прошёл на обоих движках за 15,45 с суммарно. Каждый перезапуск resolved выполнен при активном TUN. Старый worker остановился автоматически, прежние Fake-IP блокировались, новые были выданы в пределах исходного TTL. TCP/UDP, HTTPS, DoH и обычный DNS после Stop прошли. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Fedora Cloud 45, KVM, x86-64, ядро 7.2.11, SELinux Enforcing | RPM `0.1.0-900.fc45` с helper и worker из `4658ace3`. SHA-256 установленных ELF совпали с входами сборки. Helper запущен в `yonik_helper_t` с `NoNewPrivs=1` | Xray и sing-box прошли смену DNS NetworkManager с автоматической остановкой и переподключением. Запросы split-DNS остались на локальном сервере. На обоих движках прошёл строгий DoT на 853 и отдельный прогон публичного DoT через реле при сохранённой приватной зоне. Исходный DNS ответил после Stop. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Fedora Cloud 45, KVM, x86-64, SELinux Enforcing, NetworkManager 1.58.1 | Локально собранный RPM `0.1.0-901.fc45` с политикой SELinux для проверки NetworkManager. Пакет и оба установленных ELF сверены по SHA-256. Отдельная свежая VM на каждый движок | Xray и sing-box получили второй DHCPACK от исходного сервера через 21 секунду после первого, при активном TUN и том же PID worker. Прошли системный Fake DNS, трафик IPv4/IPv6, HTTPS, DoH и штатный Stop. Содержимое и метаданные `/etc/resolv.conf` совпали до и после |
| Fedora Cloud 45, KVM, x86-64, SELinux Enforcing, NetworkManager и systemd-resolved | Установленные RPM `0.1.0-901.fc45` и `0.1.0-902.fc45` (сборка `8019e237`) проверены в отдельных VM. SHA-256 пакета и установленных ELF сверены. Сценарий `production_helper_fake_dns_after_resolver_restart_and_ttl` | После перезапуска resolved оба движка блокировали старые Fake IPv4/IPv6 на физическом выходе после истечения DNS TTL и в новой сессии до свежего ответа DNS. После ответа прошли HTTPS и DoH. После Stop обычный DNS ответил для `restored.test`. Содержимое и метаданные `/etc/resolv.conf` совпали до и после |
| Fedora Cloud 45, KVM, x86-64, SELinux Enforcing | Тот же RPM из `4658ace3`, перезапуск systemd-resolved со строгим DoT на 853, отдельные прогоны до и после исходного DNS TTL | Оба движка переподключились в пределах TTL, получили новые Fake A/AAAA и заблокировали прежние. После TTL прежние адреса блокировались на физическом выходе и в новой сессии до свежего DNS-ответа. В обоих прогонах прошли TCP/UDP, HTTPS, DoH и Stop; исходный DoT снова ответил. Ссылка и содержимое `/etc/resolv.conf` совпали до и после |
| Fedora Cloud 45 с GNOME Shell 51.1 и Wayland, SELinux Enforcing | Установленный RPM, обычный UID в активной сессии, системный D-Bus и штатный диалог polkit | TUN и Fake DNS, IPv4/IPv6 TCP/UDP, HTTPS, DoH, Stop и удаление после пользовательской сессии |
| Fedora Cloud 45, KVM, x86-64, SELinux Enforcing | RPM `0.1.0-904.fc45` из `df304810`, release-сборка helper и worker, три отдельные VM. SHA-256 RPM и установленных ELF совпали, `rpm -V` прошёл перед прогонами и после | На обоих движках ранний Proxy блокировал адреса одной защищённой сети, а ответ из двух WireGuard-сетей дал `DNS_POLICY_AMBIGUOUS`. Журнал VLESS и счётчики физического выхода подтвердили отсутствие трафика к защищённым адресам. После перезапуска resolved и истечения TTL старые Fake IPv4/IPv6 блокировались на физическом выходе и в новой сессии до свежего DNS-ответа. После него прошли HTTPS и DoH, после Stop восстановился обычный DNS. Содержимое и метаданные `/etc/resolv.conf` совпали |

В этих прогонах содержимое и метаданные `/etc/resolv.conf` совпали до и
после. В режиме uplink systemd-resolved может заменить inode собственного
файла в `/run`, сохраняя ссылку и содержимое. В матрице проверена политика
Proxy для всех адресов. Отдельный прогон
в Debian 13.7 подтвердил доменные Proxy и Block для восстановленных имён и
CIDR Proxy, Block и Direct для буквальных IPv4/IPv6 на обоих движках.
Остальные варианты перечислены ниже.

## Подходы других клиентов

- **Happ** переключает реализацию TUN между Xray и sing-box. Отдельная настройка
  TUN DNS документирована для sing-box. В Linux релизы отдельно исправляют
  установку системного сервиса и запуск TUN. [Релизы Happ](https://github.com/Happ-proxy/happ-desktop/releases)
- **INCY** добавил в Linux синтетический режим через встроенный Xray FakeDNS.
  Он сохраняет заданные резолверы и пулы и может выдавать реальные ответы для
  отдельных доменов. [Документация маршрутизации INCY](https://docs.incy.cc/routing/)
- **Clash Verge Rev** использует привилегированный системный сервис для
  запуска TUN. В Mihomo перехват DNS, синтетический диапазон, исключения и
  резолвер прокси задаются отдельно. Отдельный bootstrap исключает зависимость
  адреса сервера от уже активного перехвата. [Сервис Clash Verge Rev](https://clashvergerev.com/en/faq),
  [TUN Mihomo](https://wiki.metacubex.one/en/config/inbound/tun/),
  [DNS Mihomo](https://wiki.metacubex.one/en/config/dns/)

В Yonik TUN и правила маршрутизации принадлежат системному helper. Рабочий стол
отвечает за управление и авторизацию. DNS-адаптер выбирается по реальному пути
запросов приложений, а совместимость проверяется для конкретной версии ядра,
DNS-службы и способа установки.

## 1. Диагностика хоста

- [x] Добавить `resolver_inspect host` для чтения раскладки `/etc/resolv.conf`
  без открытия файла, запросов DNS и требований к версии systemd. Различать
  stub/uplink, известные ссылки NetworkManager и resolvconf, обычный файл,
  неизвестную ссылку, отсутствующий объект, битую ссылку и ошибку чтения.
  Известная ссылка служит подсказкой для дальнейшей проверки сервиса.
- [x] Убрать привязку ошибки Secret Service к названию рабочего стола.
- [x] Проверить точные системные пути, обычный файл, отсутствующие цели и
  формат диагностики на текущем хосте.

На текущем CachyOS команда вернула `{"resolv_conf_layout":"regular_file"}`.
Этот результат сообщает форму файла. Для выбора адаптера нужны дальнейшие
проверки того, какой DNS-службой пользуются приложения. Библиотечные тесты
`yonik-linux` на Rust 1.97.0 — 968 прошли, 38 пропущены. Форматирование и
Clippy для всех целей `yonik-linux` прошли на Rust 1.85.1 из CI.

## 2. Установленный TUN с адресной политикой

- [x] Подключить базовый [путь системной сессии](2026-11-10-system-session-integration.md)
  через существующие `system_session.rs`, `helper/service.rs`,
  worker и исполнители `managed_network`. Установленный helper проверяет
  готовность доверенного worker и фактически доступные ресурсы хоста.
  Стенд с приватным echo endpoint покрывает оба закреплённых движка.
- [x] В Arch x86-64 VM установить пакет `54334d03`. Проверить подключение
  из desktop-клиента, IPv4/IPv6 TCP/UDP независимым клиентом, Stop и Unlock
  на Xray и sing-box. Для авторизации используется временное правило polkit.
- [x] На том же пакете проверить смену маршрута к VLESS и аварийное
  завершение helper отдельно для обоих движков. Сервер подтвердил трафик
  через второй интерфейс после переподключения. После SIGKILL Xray сохраняет
  kill switch до Unlock, sing-box восстанавливает обычную сеть автоматически.
- [x] Проверить доверенный реестр ядер на установленном Arch x86-64
  пакете `54334d03`. Неверный SHA-256 для Xray и sing-box поочерёдно
  отклонён на Prepare, состояние осталось `NoManagedPolicy`, worker был
  неактивен. После восстановления реестра оба движка прошли сетевой цикл
  с Fake DNS, HTTPS и DoH. `/etc/resolv.conf` совпал до и после.
- [x] Отдельно аварийно завершить worker на установленном Arch x86-64
  пакете `54334d03` с каждым движком. После SIGKILL worker PID helper
  сохранился. Qt показал `RecoveryRequired`, выполнил Stop и Unlock и
  закрылся в `NoManagedPolicy`. Интерфейс TUN снялся, списки правил
  маршрутизации IPv4/IPv6 и `/etc/resolv.conf` совпали до и после.
- [x] Проверить системный диалог действия `manage-network` политики
  установленного пакета `54334d03` в активной локальной X11-сессии Arch
  x86-64 под обычным UID. `pkcheck` запросил `auth_admin`. Агент LXQt
  открыл диалог и разрешил действие после ввода пароля. Стенд использовал
  LightDM и Openbox.
- [x] Проверить запуск TUN из Qt со штатной авторизацией Arch и смену
  маршрута к VLESS-серверу в том же GUI-прогоне. На `54334d03` прошли
  оба движка с одним администратором в `wheel`. При двух администраторах
  отдельный прогон выявил ограничение lxqt-policykit 2.5.0. Агент начал
  PAM-сессии для обоих пользователей. После трёх отмен сессии невыбранного
  пользователя PAM временно заблокировал его, и агент отклонил следующий
  Unlock. Повторный прогон изменил только состав `wheel` в одноразовой VM.
  В журнале Arch с polkit 128 `pam_unix` сообщил `conversation failed`
  для невыбранной учётной записи. Такое превращение отмены диалога в
  неудачную попытку PAM отдельно подтверждено в проекте polkit.
  [Код агента lxqt-policykit 2.5.0](https://github.com/lxqt/lxqt-policykit/blob/2.5.0/src/policykitagent.cpp#L99-L110),
  [polkit #713](https://github.com/polkit-org/polkit/issues/713).

В Arch и Debian 13 установленные helper и worker прошли сценарий
`Prepare → ApplyOutputV1` для Xray и sing-box. Контрольный трафик TCP и UDP
прошёл по IPv4 и IPv6. Восстановление после остановки helper оставило включённый
kill switch до `Unlock`. Эта проверка охватывает D-Bus клиент desktop и
адресный TUN. На Arch x86-64 установленный Qt-клиент из `54334d03`
дополнительно прошёл подключение кнопкой, Stop и Unlock с Fake DNS и обоими
движками. Отдельный прогон со штатной авторизацией в локальной X11-сессии
подтвердил переподключение при смене маршрута к VLESS-серверу.

В сетевых прогонах нативного ARM-пакета `54334d03` с моделью CPU QEMU
`max` Xray прошёл, а sing-box получил `Unavailable` на `ApplyOutputV1`.
Трасса показала, что worker копировал и проверял sealed-образ sing-box
размером 105 МиБ. Отдельный пятисекундный таймер передачи истекал во время
копирования. При использовании общего восьмисекундного срока запуск также
прервался до готовности worker. В `dac82ec8` обычный запуск использует тот
же предел 15 секунд, что и проверка ядра. Передача и подтверждение
укладываются в один абсолютный срок. После установки кросс-собранного
helper из `dac82ec8` поверх пакета `54334d03` на CPU `max` прошли обычный
сетевой сценарий и перезапуск systemd-resolved с истечением DNS TTL на
обоих движках. Проверены хеши helper и бинарников пакета, старые Fake-IP
блокировались на физическом выходе и до свежего DNS-ответа. Ссылка и
содержимое `/etc/resolv.conf` совпали в обоих прогонах.

## 3. Реальный системный DNS

Файл `/etc/resolv.conf` используется только для чтения, включая диагностику и
проверки на хостах. Конфигурацией файла продолжает управлять DNS-менеджер ОС.
В стендах варианты раскладки создаёт настроенный DNS-менеджер либо они
проверяются на отдельных тестовых файлах.

- [x] Подтвердить путь приложений через systemd-resolved. Перед Apply
  helper проверяет DNS-listener запросом через TUN, сверяет собственный
  ifindex и состояние D-Bus. Настройки публикуются только на собственном
  интерфейсе. При частичной записи или остановке сессии уничтожение этого
  интерфейса снимает DNS-настройки вместе с ним. Неоднозначный результат
  записи требует очистки сессии. Установленные helper на Debian и Fedora
  прошли запросы NSS, Stop и восстановление с Xray и sing-box.
  [Проверка пути и публикация DNS](../../../crates/yonik-linux/src/helper/session_fake_dns.rs)
  · [Контракт очистки resolve1](../../../crates/yonik-linux/src/resolver/resolve1.rs)
- [x] Подтвердить чтение per-link DNS и доменов через свойства
  `org.freedesktop.resolve1.Manager` на systemd 257 в Debian 13.
- [x] Подтвердить DNS через штатные systemd и NSS в Debian 13.7. Установленный
  helper принимает экспериментальный режим в сборке `test-support`, проверяет
  DNS-маркер через TUN и настраивает route-only suffix после старта worker.
  Обычный UID получил A и AAAA, затем обе пары TCP и UDP достигли VLESS-сервера
  на каждом ядре. Удаление интерфейса сняло per-link DNS.
- [x] Добавить read-only проверку обычного `/etc/resolv.conf`. Команда
  `resolver_inspect plain` выводит только число адресов и поисковых доменов.
  Расхождение метаданных при обновлении DHCP закрывает снимок. Обычные
  параметры изменения порядка, таймаута, семейств и транспорта тоже входят
  в снимок. Конфигурация с `no-reload` отклоняется, поскольку приложение
  может продолжить использовать прежний резолвер.
  [Параметры resolv.conf в Linux](https://man7.org/linux/man-pages/man5/resolv.conf.5.html)
- [x] Для конфигураций с подтверждёнными адресами DNS без resolved
  перехватывать точные назначения в собственном TUN. Сопоставлять каждый
  исходный DNS-адрес с отдельным локальным портом. Правила nftables
  разрешают обратный запрос только к соответствующему реальному резолверу
  по проверенному маршруту. Прогоны ниже проверяют смену адреса DNS,
  опубликованного resolvconf, отдельно для IPv4 и IPv6.
- [x] Подтвердить смену DNS без resolved при смене маршрута приватного
  VPN. Доступ к DNS приватной зоны требует подтверждённого пути.
  При его отсутствии запрос должен завершаться ошибкой.
  В Debian 13.7 с установленными ELF из `bc987619` и штатными unit-файлами
  helper сначала сохранил WireGuard-зону `wg.test` под systemd-resolved.
  После штатного перехода на resolvconf 1.94 тест
  `production_helper_fake_dns_protects_zone_after_resolvconf_route_change`
  прошёл последовательно на Xray и sing-box. При потере IPv4-маршрута к
  приватному DNS worker завершился до смены настроек DNS. После публикации
  нового адреса через resolvconf и повторного подключения прошли обычный DNS,
  Fake A/AAAA и трафик IPv4/IPv6. Оба публичных сервера готовы были
  отвечать на приватные имена, но не получили контрольных запросов.
  В установленных сессиях приватные A и AAAA завершились отказом по TCP и
  UDP. После Stop и возврата маршрута приватный DNS снова ответил.
  На этапах работы helper содержимое и метаданные `/etc/resolv.conf`
  совпали со снимками, сделанными после публикации менеджером.
  С включённым kill switch тот же стенд проверил контрольные A и AAAA
  к прежнему публичному DNS при отзыве приватного маршрута и после
  завершения worker. После публикации нового DNS повторил проверку до
  подготовки и параллельно с Prepare/Apply. Оба движка возобновили
  работу при сохранённой блокировке, без команды Unlock между сессиями.
  Журналы прежнего и нового публичных серверов не содержали этих
  приватных запросов. Контроль с выключенным kill switch также прошёл
  на обоих движках. Прогон вызывает системный API напрямую. Отдельный
  тест Qt с имитацией helper проверяет восстановление через кнопку
  «Подключить». После `State → RecoveryRequired` кнопка доступна,
  возможность явного Unlock сохраняется. Между двумя подключениями
  desktop не отправляет Stop и Unlock. Промежуточный `Unknown` оставляет
  переподключение недоступным до подтверждения helper.
  Совместный прогон в Arch Linux x86-64 с ядром 7.3.5, systemd 262.2
  и Qt 6.12 использовал установленный пакет `54334d03`. В его штатные
  пути установлены desktop из `994357d4` и helper с worker из
  `bc987619`. SHA-256 трёх файлов совпали с входами стенда. Qt
  работал под обычным UID в offscreen-режиме с правилом polkit для ВМ.
  На Xray и sing-box после SIGKILL worker helper снял прежний TUN
  и сохранил блокировку. Из того же UID проверены отказ TCP к исходному
  DNS и недоступность прежних Fake IPv4/IPv6. Кнопка «Подключить»
  запустила другой worker, оба движка получили новые Fake A/AAAA.
  До и после смены worker прошли IPv4/IPv6 TCP/UDP, HTTPS и DoH.
  После явного Stop и Unlock восстановился обычный DNS. Ссылка,
  содержимое и проверенные метаданные `/etc/resolv.conf` совпали.
  Повторный прогон использовал полный нативный пакет `c8e016b6` в
  чистой Arch VM. Перед SIGKILL стенд сверил единственный PID в cgroup
  службы и SHA-256 его исполняемого образа с Xray или sing-box. В обеих
  сессиях worker уже выполнил `exec`, и сигнал поступил движку через
  pidfd. helper снял старый TUN и оставил kill switch. Прежние Fake-IP
  и прямой TCP к исходному DNS блокировались до переподключения.
  Кнопка Qt запустила новый процесс и выдала новые Fake A/AAAA.
  На обоих движках повторно прошли IPv4/IPv6 TCP/UDP, HTTPS, DoH,
  Stop и Unlock. `pacman -Qkk` подтвердил целостность пакета.
  SHA-256 установленных ELF совпали с архивом. `/etc/resolv.conf` совпал
  до и после прогона.
  Тест `production_helper_fake_dns_after_engine_exit` проверил тот же
  сбой через установленный helper на Debian 13.7, Ubuntu 24.04.5 LTS
  и Fedora Cloud 45 x86-64. В Debian и Ubuntu установлены тестовые
  `.deb` с ELF из `eebcca65`, а в Fedora — RPM `0.1.0-911.fc45`
  с SELinux Enforcing. Стенд сверил PID, cgroup и SHA-256 процесса
  перед SIGKILL через pidfd. На Xray с kill switch старые Fake-IP
  оставались заблокированы до Unlock. После выхода обоих движков DNS-зона
  была отозвана, а старые Fake-IP блокировались на физическом выходе
  и после переподключения. В пределах исходного TTL новая сессия выдала
  другие Fake A/AAAA. Прошли IPv4/IPv6 TCP/UDP, HTTPS, DoH, Stop и
  восстановление обычного DNS. Содержимое и метаданные
  `/etc/resolv.conf` совпали. Проверки пакетов `dpkg -V` и `rpm -V` прошли.
- [x] Прогнать системный Fake DNS в Debian 13.7 с Xfce/X11 в двух режимах.
  С systemd-resolved обычный пользователь получил Fake A/AAAA через NSS.
  С `resolvconf` и неактивным systemd-resolved NSS и отдельные запросы по
  UDP/TCP вернули те же синтетические адреса, а исходный сервер получил
  обычные запросы на обоих транспортах. В журнале исходного сервера не было
  запросов для домена Fake DNS. Стенд использовал штатную авторизацию polkit
  и проверил оба движка. Приёмка смешанных правил с приватными суффиксами и
  bootstrap остаётся в проверке G-DNS.

В Debian 13.7 оба закреплённых ядра прошли системный NSS через resolved. В
Debian 13.7 и Arch Linux 7.2.11 оба ядра прошли перехват адреса обычного DNS
по UDP и TCP. В сценарии с обычным сервером его адрес взяли из отдельного
файла стенда в `/run`. В обоих сценариях проверили `/etc/resolv.conf` после
запуска и остановки, включая содержимое, inode, режим доступа и владельца.
Отдельный прогон в Debian 13.7 на штатной сборке helper использовал
`resolvconf` 1.94. Менеджер принял адрес тестового DNS-сервера через
`resolvconf -a` и опубликовал его в `/run/resolvconf/resolv.conf`, на который
указывал `/etc/resolv.conf`. При неактивном systemd-resolved оба движка
выдали Fake A/AAAA через NSS и по TCP/UDP, а исходный DNS-сервер ответил на
обычные запросы обоими транспортами. Сервер не получил запросов к тестовому
домену Fake DNS. Содержимое и метаданные `/etc/resolv.conf` совпали до и
после сессии.

На Debian 13.7 с ядром 6.12.117 и `resolvconf` 1.94 повторили смену адреса
при работающем TUN с единственным IPv6-резолвером. На Xray и sing-box
прямые запросы UDP/TCP давали те же Fake A/AAAA, что NSS. Оба исходных
IPv6-резолвера ответили на обычные запросы по обоим транспортам. Их журналы
подтвердили отсутствие запросов к синтетическому имени. После публикации
нового адреса helper остановил старую сессию. Повторное подключение
до истечения TTL выдало новые Fake A/AAAA, старые адреса блокировались.
IPv4-сценарий с теми же проверками прошёл повторно. Запись в
`/etc/resolv.conf` выполнял `resolvconf` при публикации адресов. Между этими
событиями содержимое и идентичность файла сохранялись.
[Интеграционные тесты IPv4 и IPv6](../../../crates/yonik-linux/tests/installed_helper_session.rs)

- [x] Пройти смену обычного DNS на физическом линке NetworkManager 1.58.1 и
  systemd-resolved 262.1 в Fedora Cloud 45 с SELinux Enforcing. В отдельном
  прогоне без TUN команда `nmcli device reapply` обновила DNS на том же
  ifindex и сохранила маршрутный домен `~real.test`. Со штатным RPM и Xray
  Fake A/AAAA и контрольный TCP/UDP дошли до VLESS-peer. Запрос
  `real.test` для физического резолвера `10.233.42.2:53` также дошёл до
  изолированного VLESS-peer. Стенд прочитал DNS-вопрос на стороне peer.
  NSS завершился по таймауту до шага смены DNS.
  Исправление привязывает DNS-релей к проверенному адресу и исходному
  линку, а запросы на TCP/UDP 53 из TUN без подходящего правила блокирует
  до прокси-маршрутизации. Релей проверяет длину совпавшего DNS-суффикса
  и его scope из исходного снимка. Изменение внешней конфигурации resolved
  отзывает сессию. После установки исправленного RPM оба движка получили
  ответы от исходного и нового локальных резолверов, выдали новые Fake-IP
  до истечения TTL и заблокировали старые. VLESS-peer не получил
  соединений к локальным DNS-серверам и вопросов их зоны. Содержимое и
  идентичность `/etc/resolv.conf` сохранились. Контрольные прогоны
  Debian 13.7 и Ubuntu 24.04.5 прошли на Xray и sing-box.
  [Тест установленного helper](../../../crates/yonik-linux/tests/installed_helper_session.rs)
- [x] Проверить конфигурацию только с четырьмя обычными `FallbackDNS` без
  глобальных DNS-доменов в Ubuntu с systemd 255 и Debian с systemd 257.
  Helper читает `FallbackDNSEx`, исключает свой TUN из снимка и привязывает
  каждый сервер к проверенному физическому маршруту. На собственном TUN
  публикует исходный порядок серверов, `DefaultRoute=true` и выбранные
  Fake DNS-суффиксы. Релей выдаёт Fake A/AAAA для этих суффиксов и передаёт
  остальные запросы к исходному серверу. Установка обычного DNS на линке
  с `DefaultRoute=false` приводила к потере FallbackDNS на systemd 255.
  Оба движка прошли системный DNS, HTTPS и DoH. Терминальные проверки
  подтвердили запрос нового имени к резервному серверу после Stop и Unlock,
  неизменность `/etc/resolv.conf` и отсутствие `.local`, link-local PTR и
  Fake DNS-имён в журнале резервного сервера.
  В Ubuntu sing-box воспроизвёл прерывание `RTM_GETROUTE` при смене carrier
  собственного TUN. Повторное чтение использует тот же срок и сравнивает
  свежий маршрут с опорным маршрутом Prepare.
  Отдельный прогон Ubuntu с sing-box прошёл при четырёх адресах с именами
  сертификатов. Снимок принимает эти записи при `DNSOverTLS=no` и порте 53.
  В Ubuntu оба движка проверены также со смешанным списком, где явное
  правило IPv6 возвращало `ENETUNREACH` для одного резервного адреса.
  Helper пропустил этот адрес, сохранил порядок четырёх доступных IPv4 DNS
  и заново проверил привязку их TCP/UDP к физическим маршрутам.
- [x] Проверить `FallbackDNS` с глобальным поисковым доменом и доменом
  только для маршрутизации. Helper переносит оба на собственный TUN
  в исходном порядке и с исходными флагами. Совпадения синтетического
  суффикса с другим доменом отклоняются. Изменение глобального списка
  после `SetLinkDomains` прерывает публикацию до `SetLinkDNS`.
  В Debian 13.7 и Ubuntu 24.04.5 оба движка прошли короткие имена до,
  во время и после TUN. На внешнем линке без DNS был более специфичный
  маршрутный домен. Он не мешал системному поиску через fallback.
  Полное имя из `~route.test` разрешилось, короткое имя не получило
  этот суффикс. Содержимое и метаданные `/etc/resolv.conf` сохранились.
- [x] Проверить fallback со штатным списком DNS дистрибутива и несколькими
  линками, где суммарно больше трёх серверов.
  В Arch Linux ARM с systemd 262.2 встроенный `FallbackDNSEx` содержит
  шесть адресов IPv4/IPv6. При пустом `DNSEx` они появились в uplink-файле.
  Xray и sing-box прошли NSS, прямые реальные и синтетические запросы
  по TCP и UDP, HTTPS, DoH и восстановление. В прогоне sing-box штатный
  systemd-юнит запустил установленный worker, все шесть адресов обслуживал
  локальный DNS-стенд в изолированной VM. Штатная ссылка и содержимое
  `/etc/resolv.conf` совпали до и после прогона.
  Два интерфейса с `DefaultRoute=yes` опубликовали четыре DNS-адреса.
  Xray и sing-box прошли полный сетевой цикл, включая прямой DNS по TCP и
  UDP к четвёртому адресу. Ссылка и содержимое `/etc/resolv.conf` совпали
  до и после. С `DefaultRoute=no` у тех же двух интерфейсов четыре адреса
  остались доступны в `DNSEx`, а uplink-файл не содержал `nameserver`.
  С обоими движками NSS получил реальный ответ через встроенный fallback
  и через split-DNS отдельной зоны. Прямой запрос синтетического имени
  к DNS приватной зоны отклонён по TCP и UDP. HTTPS, DoH и восстановление
  прошли. Для успешного прогона sing-box все шесть резервных адресов
  обслуживались локальным DNS-стендом. Ссылка и содержимое `/etc/resolv.conf`
  совпали до и после.
- [x] Проверить обычный DNS с нестандартным портом из `DNSEx` и `FallbackDNSEx`.
  Helper использует фактический порт в проверке маршрута, правилах Xray и
  sing-box, DNS-релее и исключениях nftables. Собственный TUN публикует
  резервные серверы через `SetLinkDNSEx`, а helper сверяет привязку и порт.
  Debian 13.7 и Ubuntu 24.04.5 прошли реальные и синтетические запросы
  по TCP и UDP на порту 1053 на обоих движках. В Ubuntu проверены IPv6
  резервные адреса, DNS на внешнем линке и глобальная запись с `%ifindex`.
  Последняя наследовала глобальный `DNSOverTLS=no` при включённом TLS на
  внешнем линке. Имя с завершающей точкой в `DNSEx` сохранило рабочий путь.
  Контроль на порту 53, HTTPS, DoH и возврат DNS после Stop прошли.
  Содержимое и метаданные `/etc/resolv.conf` сохранились.
- [x] Проверить зашифрованный системный DNS-over-TLS. Для нестандартного
  порта открытый DNS допускается после проверки эффективного режима
  upstream. При смене конфигурации защита должна закрывать прокси-путь
  до повторной проверки.

  В Ubuntu 24.04.5 строгий `DNSOverTLS=yes` получил ответ с исходного DNS
  на порту 1853 по TLS 1.3 и отклонил неверное имя сертификата. В этой
  конфигурации в исходном прогоне установленный helper вернул
  `Unavailable` на Prepare. [Тестовый DNS-over-TLS сервер](../../../tools/fixtures/fake_dns_dot.py)

  Отдельный стенд на Ubuntu 24.04.5 и Debian 13.7 проверил точное правило
  RPDB по UID резолвера, адресу, TCP и порту. При общем маршруте в тестовый
  TUN оно сохранило исходящий интерфейс и исходный адрес сокета resolved.
  Правило nft на физическом интерфейсе разрешило исходному сервису TLS
  запрос к тестовому DNS. Процесс с тем же UID из другой cgroup получил
  блокировку, подтверждённую счётчиком nft. Содержимое и метаданные
  `/etc/resolv.conf` совпали до и после маршрутизационной проверки.
  Helper устанавливает эти правила перед захватом TUN и повторно сверяет
  маршрут и личность резолвера при проверке рабочей сессии.
  Проверка сертификата должна оставаться в resolved. На systemd 255–260
  проверка имени в TLS зависит от глобального режима. Для отдельного
  режима на линке нужна проверка реализации конкретного пакета.
  [Проверка TLS в systemd 257](https://github.com/systemd/systemd/blob/v257/src/resolve/resolved-dnstls-openssl.c#L94-L108)

  В Debian 13.7 с systemd 257, Ubuntu 24.04.5 с systemd 255 и Fedora
  Cloud 45 с systemd 262 и SELinux Enforcing адаптер resolve1 проверил
  `SetLinkDNSOverTLS("no")` на собственном тестовом TUN. После публикации
  локального DNS снимок исходных резолверов сохранился, включая строгий
  TLS и имя сервера. После удаления TUN запись линка исчезла из resolve1.
  Содержимое и метаданные `/etc/resolv.conf` совпали.
  На тех же системах процесс с `CAP_NET_ADMIN` сверил владельца D-Bus,
  PID, UID, `InvocationID` и cgroup исходного резолвера до и после чтения
  снимка. Проверка привязана к системной шине и подтверждённому процессу PID 1.
  В отдельных network namespace на тех же ядрах сетевой план установил
  точные IPv4- и IPv6-правила перед захватом TUN. Совпадающий TCP-сокет
  сохранил исходную таблицу маршрутизации. Запрос с другим UID или портом
  шёл через TUN. При остановке исходная топология восстановилась, записи
  сессии удалились из журнала. Содержимое и метаданные `/etc/resolv.conf`
  совпали.
  Executor установил и сверил правила nft для обоих семейств на Debian
  с nftables 1.1.3, Ubuntu с 1.0.9 и Fedora с 1.1.6 под SELinux Enforcing.
  Старые версии nft получили inode из дескриптора каталога cgroup,
  унаследованного только процессом nft. При сверке числовой ID из ядра
  совпал с ожидаемым, а подменённый ID был отклонён. Проверка прошла в
  изолированных network namespace с неизменным `/etc/resolv.conf`.

  В Debian 13.7 и Ubuntu 24.04.5 установленный helper прошёл Prepare,
  Apply и Stop на Xray и sing-box с глобальным строгим DoT на порту 1853.
  В Fedora Cloud 45 оба движка прошли тот же сценарий с установленным RPM,
  SELinux Enforcing и неявным портом 853.
  Штатный resolved отверг неверное имя сертификата и получил реальный
  ответ по TLS после исправления имени. При работающем TUN приложения
  получили реальный ответ через исходный резолвер и Fake A/AAAA в заданной
  зоне. Сокет с тем же UID вне cgroup резолвера заблокирован. После Stop
  исходный DoT ответил для нового имени. HTTPS, DoH и карантин Fake-IP
  прошли по сценарию установленного helper. Содержимое и метаданные
  `/etc/resolv.conf` совпали.

  Настроенный `DNSOverTLS=opportunistic` проверен с установленным helper
  на Xray и sing-box. В Ubuntu 24.04.5 доступный сервер отвечал по TLS 1.3.
  В Debian 13.7 и Ubuntu 24.04.5 стенд отклонял TLS. При активной сессии
  resolved повторял попытку TLS, затем получал усечённый ответ по UDP и
  полный ответ по TCP. В Debian оба транспорта сохраняли явный порт
  1853. В Ubuntu с неявным портом переход шёл с TLS 853 на DNS 53.
  Fake A/AAAA, восстановление после Stop и неизменность `/etc/resolv.conf`
  подтверждены.
  [Выбор порта в systemd](https://github.com/systemd/systemd/blob/v255/src/resolve/resolved-dns-transaction.c#L600-L606)

  В двух чистых Arch x86-64 VM с systemd 262.2 и установленным нативным
  пакетом из `c8e016b6` режим DNS на внешнем линке изменили по D-Bus
  при активном TUN. Xray прошёл переход с `yes` на `opportunistic`,
  sing-box прошёл обратный переход. Helper сам остановил прежние worker
  и отозвал их зоны Fake DNS. Старые Fake IPv4/IPv6 остались
  заблокированы. После повторного подключения прошли Fake A/AAAA,
  TCP/UDP, HTTPS и DoH. Сервер исходного DNS подтвердил TLS 1.3 на
  порту 1853 до смены и после восстановления. Содержимое и метаданные
  `/etc/resolv.conf` совпали. Первому прогону Xray не хватило 10 секунд
  для завершения worker. В отдельных прогонах с дедлайном остановки
  25 секунд полные сценарии заняли 27,05 и 27,82 секунды.

- [x] Проверить строгий DoT в конфигурации только с `FallbackDNS`.
  Helper сохраняет порядок доступных серверов и направляет реальные
  запросы к исходным адресам по TLS. Он проверяет цепочку по системному
  набору CA и имя из `FallbackDNSEx` либо IP из сертификата, если имя
  отсутствует. При ошибке TLS реальный запрос завершается ошибкой.
  В Debian 13.7 и Ubuntu 24.04.5 с портом 1853 установленные helper и
  worker на Xray и sing-box прошли Fake A/AAAA, реальный NSS при активном
  TUN и после Stop, HTTPS и DoH. В отдельном прогоне на Ubuntu оба движка
  применили Fake DNS, а реальный запрос с неверным именем сертификата
  завершился ошибкой. Содержимое и метаданные `/etc/resolv.conf` совпали.
  В Fedora Cloud 45 системный resolve1 при публикации через D-Bus
  нормализует 853 в порт по умолчанию. Для TUN с отключённым локальным
  TLS helper публикует обычный DNS на порту 53, а релей сохраняет
  исходное TLS-назначение на порту 853. Установленный RPM под SELinux
  Enforcing прошёл тот же сценарий на обоих движках с неизменным
  `/etc/resolv.conf`.
  [Нормализация DNS-порта в systemd 262.1](https://github.com/systemd/systemd/blob/v262.1/src/shared/bus-message-util.c#L142-L150)

- [x] Проверить `DNSOverTLS=opportunistic` в конфигурации только с
  `FallbackDNS`. Helper пробует TLS с ограничением одной секунды на
  подключение и рукопожатие в пределах общего тайм-аута DNS. Режим
  сохраняет проверку подписей TLS, имя сервера и цепочка доверия в нём
  не проверяются. При отказе рукопожатия helper использует исходный
  обычный DNS. После успешного рукопожатия ответ DNS проходит обычные
  проверки релея, ошибка ответа завершает запрос.
  Установленный helper на Ubuntu 24.04.5 получил ответ по TLS от сервера
  с несовпадающим именем сертификата. Тот же сценарий прошёл с
  установленным RPM в Fedora Cloud 45 под SELinux Enforcing на порту 853.
  При отказе TLS стенд подтвердил
  переход с TCP/853 на UDP/53, а затем на TCP/53 после усечённого UDP.
  На Debian 13.7 при такой же последовательности все три запроса
  использовали явно заданный порт 1853. Fake A/AAAA, HTTPS, DoH и реальный
  NSS после Stop прошли на обоих движках. Содержимое и метаданные
  `/etc/resolv.conf` совпали.
  [Режим opportunistic в systemd](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html#DNSOverTLS=)

- [x] Проверить переподключение DHCPv4 в Debian 13.7 и Ubuntu 24.04.5 LTS с
  `systemd-networkd` и `systemd-resolved`. В тесте
  `production_helper_fake_dns_after_dhcp_reconnect`
  [стенд](../../../tools/fixtures/dhcp_dns_change.sh) разрывает тестовый линк.
  Установленный helper сам останавливает worker и отзывает Fake DNS-зону.
  После восстановления линка новый DNS из lease появляется в systemd-resolved
  и отвечает на системный запрос с другим A-адресом. Xray с kill switch и
  sing-box без него повторно подключаются до истечения TTL прежних Fake A/AAAA.
  Старые адреса остаются заблокированы, оба обычных DNS-сервера обслуживают
  свои запросы, файл `/etc/resolv.conf` сохраняет содержимое и метаданные.
- [x] Проверить штатное продление DHCPv4 во время активного TUN для
  systemd-networkd, встроенного клиента NetworkManager и dhcpcd.
  Проверки DNS охватывают systemd-resolved, файл NetworkManager,
  resolvconf и обычный файл. На Debian при `networkctl renew` с Xray и kill switch
  `nft monitor trace` увидел реальный UDP-пакет с исходного порта 68 на
  порт 67 и с выходным интерфейсом DHCP-линка. Цепочка output активной
  сессии применила `policy drop`, до сервера запрос не дошёл. Для поддержки
  продления требуется узкое разрешение, привязанное к DHCP-клиенту и лизу.
  Отдельная таблица стенда на Debian 13.7 и Ubuntu 24.04.5 пропустила реальное
  продление при совпадении адресов, UDP-портов, ifindex, UID и cgroup сокета
  `systemd-networkd`. Новый DNS появился в resolved. Пакет с тех же адресов
  и портов от того же UID из другой cgroup был отклонён, как и следующий
  запрос `systemd-networkd` после истечения временного элемента в ядре.
  Содержимое и идентичность `/etc/resolv.conf` совпали. Проверенные nftables
  1.0.9 и 1.1.3 приняли выражение `socket cgroupv2` из текстовой транзакции.
  JSON-ввод отклонил его, JSON-вывод опустил уровень cgroup. Тест Rust
  прочитал из NETLINK_NETFILTER числовые уровень и inode cgroup и сверил
  их с `systemd-networkd.service` на обоих ядрах. Отдельная проверка с
  `CAP_NET_ADMIN` и `NoNewPrivileges` на обеих системах сверила выданный
  DHCPv4-лизинг с адресом интерфейса, UDP-сокетом, UID, cgroup и маршрутом.
  `NETLINK_SOCK_DIAG` отдаёт TOS и метку сокета. Снимок использует их в запросе
  маршрута и сверяет сокет повторно. В Debian и Ubuntu проверены CS4 и CS6,
  счётчики nftables подтвердили DSCP и нулевую метку фактических пакетов.
  Отдельный фильтр отклонил продление CS4 с правилом для CS6. При проверке
  на свежем лизинге правило для CS4 пропустило запрос и DNS обновился.
  Повторная сверка отзывает снимок при смене лизинга. При выходе процесса
  снимок недоступен, срок ограничен двумя секундами и T2 лизинга. Содержимое
  и метаданные `/etc/resolv.conf` совпали. Активная политика Fake DNS
  резервирует пустую цепочку `dhcp_renewal` и набор с таймером. Переход
  стоит после блокировки приватных префиксов. В nftables 1.0.9 и 1.1.3
  четырёхпольный ключ из адресов и интерфейса сохраняет типы при сверке.
  Установленный helper прошёл запуск, автоматическую остановку при обрыве
  DHCP-линка, повторное подключение, Stop и Unlock с обоими движками на
  Debian и Ubuntu. До снятия политики набор оставался пустым.
  Исполнитель политики на обоих ядрах установил точное DHCP-правило
  атомарной текстовой заменой таблицы. Повторное открытие журнала и
  завершение `systemd-networkd` сохраняют возможность сверить и снять его.
  Подмена уровня cgroup при неизменном JSON отклонена по данным Netlink.
  Трассировка подтвердила блокировку запроса при пустом наборе. Исполнитель
  с повторной сверкой лизинга устанавливает элемент на 650 мс и обновляет
  его атомарной транзакцией. В Debian и Ubuntu проверены отказ для старой
  ревизии, повторное обновление, явный отзыв и истечение по таймеру ядра.
  С элементом DHCP-клиент продлил лизинг и обновил DNS в resolved, без
  элемента запрос заблокировала политика. Ревизия политики и
  `/etc/resolv.conf` сохранились. Для VM-теста
  `dhcp_rule_is_verified_through_durable_public_policy` стенд предоставляет
  oneshot `yonik-dhcp-fixture-change-dns.service`, который меняет DNS на
  DHCP-сервере на `10.203.2.2`. Сам тест запрашивает продление клиента.
  Штатный helper проверяет до восьми интерфейсов и ставит отдельное правило
  для каждого подтверждённого лизинга networkd в той же cgroup и namespace.
  Он проверяет поддержку правил и обновляет набор при работающем worker.
  Просроченные и изменившиеся лизинги исключаются из набора, пригодные
  остаются. При остановке и восстановлении helper явно очищает набор.
  Журналы с одним DHCP-правилом читаются и сохраняют прежний формат.
  Проверка топологии после продления учитывает новые конечные сроки
  адреса только при более новом подтверждённом лизинге. Остальные свойства
  адреса, маршруты и DNS проходят обычную сверку. Тест
  `production_helper_fake_dns_dhcp_renewal` проверяет `yonik-dhcp`.
  Для проверки двух лизингов стенд запускает тот же
  [скрипт DHCP](../../../tools/fixtures/dhcp_dns_change.sh) с
  `YONIK_DHCP_FIXTURE=second` и передаёт тесту
  `YONIK_DHCP_SECOND_FIXTURE=1`. Второй линк получает адрес по DHCP без
  публикации DNS. Управляющему интерфейсу QEMU задаётся его существующий
  статический адрес через networkd до снимка резолвера. Тест сверяет
  время лизингов через D-Bus, Fake A/AAAA и трафик до тестового peer,
  очистку после Stop и содержимое и метаданные `/etc/resolv.conf`.
  В Debian 13.7 и Ubuntu 24.04.5 оба лизинга продлились в активной TUN-сессии
  на Xray и sing-box. В том же тесте при приостановленном втором
  DHCP-сервере первый лизинг продлился, время второго не изменилось.
  Для встроенного DHCP-клиента NetworkManager 1.58.1 на Fedora 45 сделаны
  контрольный прогон без TUN и два независимых прогона с TUN. Без TUN
  тестовый сервер выдал второй DHCPACK примерно через 13 секунд после
  первого при сроке лизинга 30 секунд. На Xray и sing-box с helper и
  worker из `6fa15571`, установленными поверх RPM `0.1.0-900.fc45`,
  NetworkManager в окне штатного продления получил `error -1` при отправке
  DHCPREQUEST на адрес сервера. Сервер не выдал второй DHCPACK за окно
  наблюдения, worker продолжал работать, HTTPS и DoH прошли через TUN.
  Содержимое и метаданные `/etc/resolv.conf` совпали до и после.
  В контрольном прогоне без TUN ядро видело уже в состоянии Bound
  подключённый UDP-сокет `:68 → :67`, привязанный к адресу, интерфейсу
  и серверу лизинга. Сокет оставался у MainPID NetworkManager и сохранял
  inode при продлении. Unit работал в `/system.slice/NetworkManager.service`
  с `Delegate=no`. При втором ACK остаток срока IPv4-адреса в ядре вырос
  с 17 до 30 секунд, одновременно обновился `expiry` в D-Bus
  `DHCP4Config.Options`. В проверенном лизинге D-Bus не отдавал T1 и T2.
  С активным TUN на Xray и sing-box у того же сокета сохранились inode,
  привязка к интерфейсу и серверу, cgroup и DSCP 0. Число DHCPACK
  по-прежнему оставалось равным одному.
  При реализации нужно сверять конечные адреса и интерфейс сокета,
  идентичность unit, маршрут и конечный срок адреса в ядре. Встроенный
  клиент открывает подключённый сокет при принятии лизинга, а при
  переходе к повторной привязке переключается на приём DHCP на канальном
  уровне. [Исходный код клиента NetworkManager 1.58.1](https://github.com/NetworkManager/NetworkManager/blob/1.58.1/src/n-dhcp4/src/n-dhcp4-c-probe.c)
  Для проверки используется `production_helper_networkmanager_dhcp_renewal`
  из `installed_helper_session` с `test-support`. Для каждого движка нужна
  свежая VM с установленным helper, обычным стендом Fake DNS и
  `tools/fixtures/networkmanager_dhcp.sh`. Стенд запускает собственный
  DHCP-сервер в отдельном сетевом пространстве. Запуск теста требует
  `YONIK_NM_DHCP_ENGINE=xray` или `YONIK_NM_DHCP_ENGINE=sing-box`.
  Тест проверяет повторный DHCPACK при том же PID worker, восстановление
  после Stop и неизменность `/etc/resolv.conf`.
  RPM `0.1.0-901.fc45` подтвердил это продление с Xray и sing-box в
  Fedora 45 при SELinux Enforcing. Helper сверяет статус юнита, PID и
  cgroup через D-Bus и ядро. Встроенный DHCP-клиент должен уже иметь
  подключённый сокет к серверу лизинга. Наблюдаемый срок адреса в ядре
  ограничивает допуск. Политика может хранить подтверждённые правила
  обеих служб с отдельными cgroup. В отдельных чистых VM с этим же RPM
  NetworkManager и systemd-networkd одновременно получили повторные
  DHCPACK на разных линках при активном TUN с Xray и sing-box. Снимок
  nftables подтвердил отдельные UID, cgroup и интерфейс в каждом правиле.
  Fake DNS и Stop прошли, `/etc/resolv.conf` совпал по содержимому и
  метаданным.
  В Debian 13 отдельно проверен `dhcpcd-base 10.1.0-11+deb13u4` с
  privilege separation на изолированном veth. Без TUN при лизинге
  30 секунд DHCP-сервер получил unicast DHCPREQUEST примерно через
  15 секунд и отправил второй DHCPACK. Содержимое и метаданные
  `/etc/resolv.conf` совпали. До и после продления ядро видело
  неприсоединённый UDP-сокет приёма на порту 68 и отдельный raw-сокет
  протокола UDP у привилегированного процесса той же cgroup.
  Допуск для networkd и NetworkManager на такой сокет и лизинг пока
  не распространяется. Две чистые Debian 13 VM с установленными helper
  и worker из `71ebdcde` проверили штатный переход в RENEWING с активным
  TUN и включённым kill switch. На Xray и sing-box через 23 секунды после
  первого DHCPACK клиент попытался продлить 46-секундный лизинг. Счётчик
  unicast DHCP на выходном интерфейсе остался нулевым, сервер не увидел
  повторного DHCPREQUEST, в наборе разрешений helper не было элементов.
  С тем же PID worker до и после попытки прошли Fake A/AAAA и
  IPv4/IPv6 TCP/UDP. Продлённый прогон на обоих движках дождался
  REBINDING через 40 секунд после первого ACK. Сервер отправил второй
  DHCPACK, адрес `10.234.16.10/24` остался на интерфейсе с обновлённым
  сроком. Helper остановил worker после изменения срока адреса,
  сохранил kill switch и блокировку прежних Fake IPv4/IPv6. После
  Unlock состояние вернулось в `no_managed_policy`, содержимое и
  метаданные `/etc/resolv.conf` совпали с исходными. Для непрерывной
  работы TUN требуется подтвердить лизинг и транспорт dhcpcd и
  обработать их обновление в активной сессии.
  В отдельной Debian 13 VM без TUN диагностическая служба с
  `CAP_NET_ADMIN`, `NoNewPrivileges=yes` и ограничениями файловой
  системы и семейств сокетов штатного helper прочитала через SOCK_DIAG
  raw-сокет отправки и неприсоединённый UDP-сокет приёма. До и после
  штатного продления их inode и cgroup совпали. Пассивный счётчик nftables
  подтвердил, что unicast DHCPREQUEST совпал с cgroup сокета. Проверка
  `SO_PEERCRED` показала UID 0 и PID управляющего процесса из той же
  cgroup. Команда `dhcpcd -4 --dumplease` через управляющий сокет
  вернула состояние BOUND, затем RENEW, адрес, префикс, идентификатор
  сервера и длительность лизинга. Абсолютного времени получения лизинга
  в этих ответах нет. Для допуска остаётся связать снимок управляющего
  сокета с подтверждёнными текущими сроками адреса в ядре, учесть смену
  процесса и владельца интерфейса, затем проверить штатные службы
  dhcpcd в Debian и Arch. Этот прогон использовал отдельную службу стенда.
  В следующем прогоне запрос DUMPLEASE отправлен напрямую в
  непривилегированный управляющий сокет. UID, cgroup и pidfd проверены
  для процесса на том же соединении. Два снимка `RTM_GETADDR` по
  сторонам запроса подтвердили тот же ifindex, адрес и префикс, одинаковые
  `IFA_CACHEINFO.cstamp` и `tstamp`, а также пересечение интервалов
  истечения срока по данным ядра. После второго DHCPACK состояние
  сменилось с BOUND на RENEW, `cstamp` сохранился, `tstamp` сдвинулся
  на 21,03 с, а нижняя граница срока из снимков продвинулась на 20,78 с.
  PID управляющего процесса остался прежним. Эти наблюдения относятся
  к устойчивым снимкам до и после продления в Debian 13 без TUN.
  Unit `dhcpcd.service` из пакета Debian с временным параметром
  `-f` для конфигурации стенда повторил проверку через общий
  `/run/dhcpcd/unpriv.sock`. В этом режиме UDP-сокет приёма слушал
  `0.0.0.0:68`. Ответ DUMPLEASE был отфильтрован по интерфейсу и
  подтвердил тот же адрес, сервер и 42-секундный лизинг. Второй DHCPACK
  сдвинул `tstamp` на 21,02 с и нижнюю границу срока на 20,72 с при
  неизменных `cstamp` и PID. Счётчик cgroup зарегистрировал один
  unicast DHCPREQUEST. В обоих режимах содержимое и метаданные
  `/etc/resolv.conf` совпали до и после. Этот стенд открывал pidfd по
  числовому PID из `SO_PEERCRED`.
  Тестовая сборка Rust-клиента подтвердила в Debian 13 пакетный
  `dhcpcd.service` до и после второго DHCPACK. Она получает pidfd
  через `SO_PEERPIDFD`, читает DUMPLEASE без запуска процесса и
  сверяет cgroup по ответу IPv4 SOCK_DIAG для raw UDP. В обоих снимках
  совпали PID, inode raw-сокета, cgroup, TOS и mark. Тест выполнялся
  с `CAP_NET_ADMIN` и `NoNewPrivileges=yes`. Чтение требует ядра с
  `SO_PEERPIDFD` и однозначный ответ DHCPv4 без дополнительной записи
  IPv4LL. В том прогоне проверялось чтение лизинга и сокета.
  Следующий прогон установил новые helper и worker в чистые Debian VM.
  При privsep управляющий сокет dhcpcd обслуживает одного клиента,
  поэтому опросы сериализованы до подтверждённого закрытия соединения.
  После этого установленный helper создал временный допуск. Трассировка
  показала, что raw DHCPREQUEST на T1 попал в TUN с исходным адресом
  самого туннеля. Поиск маршрута с заданными реальным адресом и внешним
  интерфейсом возвращал физический путь. Такой поиск подтверждает
  конечный маршрут, а raw-сокет dhcpcd выбирает его без этих ограничений.
  В двух чистых Debian VM временное правило стенда для подтверждённой
  cgroup корректировало исходный IPv4 и ставило марку обхода TUN до
  повторного выбора маршрута. Пассивный счётчик postrouting увидел по
  одному DHCPREQUEST на физическом интерфейсе. Оба движка получили
  второй DHCPACK в T1, сохранили прежний PID worker, Fake A/AAAA и
  IPv4/IPv6 TCP/UDP, затем прошли Stop и Unlock. Содержимое и метаданные
  `/etc/resolv.conf` совпали. Коррекция маршрута была отдельной таблицей
  стенда.
  В двух следующих Debian 13 VM коррекция работала в таблице штатного
  установленного helper. Правило сверяло `ciaddr` из DHCPREQUEST с
  подтверждённым IPv4-адресом, использовало общий набор лизингов с
  таймаутом и проверяло реальный исходящий интерфейс в postrouting.
  Проверка таблицы подтвердила идентификатор cgroup и порядок правил.
  Xray и sing-box получили второй DHCPACK через 23 секунды после первого.
  Пассивный счётчик зафиксировал один запрос через физический интерфейс
  в каждой VM. Fake A/AAAA и TCP/UDP по IPv4 и IPv6 прошли при том же PID
  worker. Stop удалил временный набор DHCP, Unlock снял правила сессии.
  Содержимое и метаданные `/etc/resolv.conf` совпали. Сценарий подтвердил
  глобальную службу `dhcpcd.service` из Debian с конфигурацией стенда и
  SHA-256 обоих установленных ELF.
  Подписанный `dhcpcd 10.5.2-2` из Arch Extra использует
  `/run/dhcpcd/sock` с владельцем root и режимом 0600. Перед числом
  записей DUMPLEASE он передаёт native C int со статусом. В Arch VM
  проверены оба снимка BOUND и RENEW через этот сокет и
  `SO_PEERPIDFD`. PID совпал, срок ядра обновился после второго
  DHCPACK. Helper читает новый формат только после проверки типа и прав
  файла сокета и каталогов `/run` и `/run/dhcpcd`. Для старого
  формата сохранён прежний путь через непривилегированный сокет.
  С helper и worker из `b507e0a1` тот же тест на Xray и sing-box
  прошёл в Debian со старым сокетом и в Arch x86-64 с новым сокетом.
  В Arch бинарники заменили поверх установленного пакета `54334d03`.
  В каждой VM получен второй DHCPACK и подтверждён выход DHCP-запроса
  через внешний интерфейс. При том же PID worker прошли Fake A/AAAA,
  TCP/UDP по IPv4 и IPv6, Stop и Unlock. Содержимое и метаданные
  `/etc/resolv.conf` совпали. Затем в двух чистых Arch VM те же проверки
  прошли с полным нативным пакетом `b507e0a1`.
  Шаблон Arch `dhcpcd@.service` публикует приватный сокет
  `/run/dhcpcd/<интерфейс>.sock`. В VM лизинг прочитан через этот сокет
  с кодом статуса и PIDFD. Тест `native_dhcpcd_reads_instance_control_socket`
  подтвердил чтение через код Yonik и отдельную cgroup процесса внутри
  `system-dhcpcd.slice`. Правило nftables с уровнем 3,
  установленное через открытый дескриптор этой cgroup, зафиксировало
  исходящий DHCP-пакет экземпляра. Контрольный сокет соседней службы
  в том же slice отправил UDP-пакет, и правило его не сопоставило.
  Helper связывает PID управляющего сокета с ожидаемым экземпляром
  systemd. Компилятор удерживает дескриптор cgroup конкретного интерфейса,
  а проверка правил сверяет уровень и inode из ядра. В двух Arch VM
  служба `dhcpcd@.service` продлила лизинг в T1 при активном TUN на
  Xray и sing-box. В каждой VM счётчик подтвердил выход запроса через
  физический интерфейс. При прежнем PID worker прошли Fake A/AAAA и
  TCP/UDP по IPv4 и IPv6, затем Stop и Unlock. Содержимое и метаданные
  `/etc/resolv.conf` совпали. Для этой проверки свежие helper и worker
  установлены поверх полного пакета `b507e0a1` со сверкой хешей.
  С теми же ELF из `08f66b21` в Arch повторили глобальный
  `dhcpcd.service`. Оба движка снова получили второй DHCPACK в T1
  при прежнем PID worker, Fake A/AAAA и TCP/UDP продолжили работать.
  В отдельных ВМ прошли сетевые сценарии истечения Fake-IP после
  перезапуска резолвера и строгого DoT. Сертификат с неверным именем
  отклонён, правильный DoT на порту 1853 использовал TLS 1.3. Сокет
  с UID резолвера вне его cgroup заблокирован на обоих движках.
  Содержимое и метаданные `/etc/resolv.conf` совпали. Полный нативный
  пакет того же коммита повторил глобальный DHCP и режим экземпляра,
  сценарии TTL и строгого DoT в отдельных Arch VM.
  После добавления защиты DHCP при сне четыре чистые Arch VM повторили
  глобальный режим и режим экземпляра на нативном пакете `c8e016b6`.
  Xray и sing-box в каждом режиме получили второй DHCPACK в T1.
  Счётчик nftables подтвердил один запрос через физический интерфейс,
  а при прежнем PID worker прошли Fake A/AAAA и TCP/UDP по IPv4 и IPv6.
  Stop и Unlock прошли. Содержимое и метаданные `/etc/resolv.conf`
  совпали. Установленные ELF сверены с архивом по SHA-256.
  [Нативный DHCPv4-транспорт dhcpcd](https://github.com/NetworkConfiguration/dhcpcd/blob/v10.1.0/src/dhcp.c)
  nftables 1.0.9
  и 1.1.3 требуют путь cgroup при текстовой установке, поэтому её смену
  между компиляцией правила и сверкой нужно обработать до выдачи допуска.
  В Fedora Cloud 45 с systemd 262 и SELinux Enforcing проверены доступ
  `NETLINK_SOCK_DIAG`, идентификатор пространства имён и сверка inode cgroup
  через netfilter из домена установленного helper. В состоянии Bound
  networkd 262 может открывать UDP-сокет только при отправке запроса.
  Для немаркированных пакетов helper отдельно проверяет маршруты `none`,
  `CS4` и `CS6`. В nftables каждый подтверждённый DSCP получает своё правило
  с теми же адресами, портами, выходным интерфейсом, UID и cgroup. Таймер
  по-прежнему один на лизинг. Ответ ядра без таблицы FIB не подтверждает
  путь. Старые записи журнала с одним DSCP читаются в прежнем формате.
  В стенде `YONIK_DHCP_SERVICE_TYPE` задаёт DSCP, а тест читает DNS лизинга
  через `DescribeLink`.
  На Fedora активные TUN-сессии обновили лизинги одновременно с `CS4` и
  `none` на Xray и sing-box. При запрете маршрута для `CS6` через RPDB
  установленные правила nftables содержали только подтверждённые `CS4` и
  `none`. В Debian 13.7 и Ubuntu 24.04.5 повторно проверен стандартный
  `CS6` на обоих движках. [Параметр IPServiceType в systemd](https://github.com/systemd/systemd/blob/v262/man/systemd.network.xml#L2359-L2367)
- [x] Устранить окно DHCP сразу после сна и проверить установленный helper
  с Xray и sing-box. В Debian 13.7 и Ubuntu 24.04.5 после ACPI S3
  `CLOCK_BOOTTIME` продвинулся на 3,2–3,7 секунды, монотонное время —
  примерно на 100 мс. Элемент nftables с таймером 650 мс остался действующим,
  и контрольный UDP-пакет прошёл до обновления разрешения.
  Дополнительное окно `meta time` закрыло доступ сразу после пробуждения,
  а возврат часов к началу окна снова пропустил пакет. Этот вариант
  зависит от `CLOCK_REALTIME` и сам по себе не закрывает пробел.
  Установленный helper использует delay inhibitor logind. При
  `PrepareForSleep(true)` он запрещает выдачу новых разрешений, ждёт
  завершения записи nftables и истечения элементов, затем отпускает
  inhibitor. После пробуждения он получает новый inhibitor и будит
  штатную сверку сети. Новый допуск требует свежего снимка DHCP. При
  отсутствии login1 или слишком малом `InhibitDelayMaxUSec` временные
  DHCP-элементы не выдаются.
  В Debian 13.7 с остановленным и замаскированным logind тест
  `production_helper_fake_dns_suspend_without_logind` запустил S3 через
  `systemd-suspend.service`. До запуска был подтверждён DHCP-лизинг
  networkd, QMP подтвердил отдельный цикл сна на каждом движке. Набор
  `dhcp_renewal_leases` был пуст перед S3, сразу после пробуждения и в
  новой сессии. После отключения тестового линка helper остановил worker,
  а восстановленный линк получил другой DNS по DHCP. После истечения TTL
  старые Fake IPv4/IPv6 оставались заблокированы на физическом выходе и
  в новой сессии до первого свежего DNS-ответа. Затем на Xray и sing-box
  прошли TCP/UDP, HTTPS, DoH и Stop. Содержимое и метаданные
  `/etc/resolv.conf` совпали.
  На Debian 13.7 с установленным `.deb` из `9d5f09f2` отдельный
  тест `production_helper_fake_dns_suspend_with_short_inhibitor` проверил
  тот же цикл при действующем login1 с `InhibitDelayMaxSec=1s`.
  Тест прочитал эффективное значение через D-Bus. QMP подтвердил
  отдельный цикл настоящего S3 для каждого движка. DHCP-набор оставался
  пуст до сна, сразу после пробуждения и при переподключении.
  Новый DHCP-лизинг сменил DNS, а старые Fake IPv4/IPv6 остались
  заблокированы после TTL до первого свежего запроса. TCP/UDP, HTTPS,
  DoH и Stop прошли. Ссылка, права и содержимое `/etc/resolv.conf`
  совпали до и после. На том же пакете отдельный гость повторил
  этот результат с отключённым login1.
  Тест `production_helper_fake_dns_revokes_dhcp_on_login1_loss` на том же
  пакете проверил потерю действующего владельца login1 в активной сессии.
  На обоих движках временный набор DHCP опустел в пределах двух секунд
  после исчезновения владельца и оставался пустым до запуска logind.
  После появления нового владельца разрешение вернулось. Оба DHCP-лизинга
  продлились. Исходный worker сохранил PID, а трафик TCP/UDP через ранее
  выданные Fake IPv4/IPv6 прошёл при отсутствии login1 и после его
  возвращения. Stop снял набор, `/etc/resolv.conf` сохранил ссылку, права
  и содержимое.
  В Debian 13.7 с установленным `.deb` из `9d5f09f2` SIGKILL helper
  непосредственно перед запросом S3 через logind оставил два DHCP-элемента
  в nftables перед сном и сразу после пробуждения. QMP подтвердил S3
  на Xray и sing-box. Автоматический перезапуск helper очистил набор,
  сохранил действие kill switch и карантин Fake-IP. Состояние
  `/etc/resolv.conf` совпало до и после.
  Вспомогательный oneshot перед `sleep.target` задержал вход в сон
  на 800 мс. На обоих движках после SIGKILL набор был пуст до и после S3.
  При прямом запуске `systemd-suspend.service` с живым helper тот же
  oneshot оставил набор непустым на Xray. Обновление DHCP нужно
  блокировать на всё время подготовки и сна, затем дожидаться
  завершения записей и истечения уже выданных разрешений.
  Пакетные сценарии
  `production_helper_fake_dns_quiesces_dhcp_after_crash_before_s3`
  и `production_helper_fake_dns_quiesces_dhcp_before_direct_s3`
  фиксируют оба условия. Для них hook записывает результат проверки
  nftables в `/run/yonik-dhcp-sleep-pre` и `/run/yonik-dhcp-sleep-post`.
  Тест принимает `empty` для пустого набора и `absent` после снятия
  правила. Исходный oneshot с постоянной задержкой использовался в
  тестовых гостях.
  В `eebcca65` пакет ставит обязательную службу перед `sleep.target`.
  Служба блокирует новые записи DHCP до завершения сна, ждёт завершения
  уже начатой транзакции nftables и истечения 650-мс разрешений. Процесс
  nft наследует блокировку записи и удерживает её при SIGKILL helper.
  Helper сверяет связи юнита у PID 1 перед включением DHCP-допуска.
  На Debian 13.7 с установленным `.deb` из `eebcca65` четыре свежих
  гостя проверили SIGKILL перед запросом сна через logind и прямой
  запуск `systemd-suspend.service` при живом helper. На Xray и sing-box
  набор был пуст до и после S3, старые Fake-IP оставались заблокированы,
  исходный DNS восстановился. Дополнительный S3 прошёл до появления
  файла блокировки. Содержимое и метаданные `/etc/resolv.conf` совпали.
  В Fedora Cloud 45 x86-64, NetworkManager 1.58.1 и SELinux Enforcing
  установленный RPM `0.1.0-911.fc45` с исправлением `61fece1d` прошёл
  два цикла S3 через logind. Оба движка получили новый DHCPACK,
  восстановили Fake A/AAAA и TCP/UDP. `rpm -V` и проверка хешей ELF
  прошли, содержимое и метаданные `/etc/resolv.conf` совпали.
  Исчерпание задержки logind при активной записи требует отдельной
  проверки.
  [Порядок служб перед и после сна в systemd](https://www.freedesktop.org/software/systemd/man/256/systemd.special.html)
  Скрипт [nft_sleep_probe.py](../../../tools/fixtures/nft_sleep_probe.py)
  запускается только в одноразовом госте. Для режимов `relative` и
  `rollback` хост ждёт состояния `suspended` через QMP, держит гостя в
  S3 три секунды и вызывает `system_wakeup`. Скрипт сравнивает
  разрешённость пакета, таймер элемента, содержимое и метаданные
  `/etc/resolv.conf`. Реестр Fake-IP и его карантин используют монотонное
  время. При смене топологии после пробуждения helper завершает прежнюю
  сессию с выбранной политикой kill switch. Проверка установленного
  helper через `YONIK_DHCP_SLEEP_FIXTURE=1` требует read-only hook стенда
  для проверки пустого DHCP-набора перед S3. Hook пишет `empty` в
  `/run/yonik-dhcp-sleep-pre`, если ровно один набор
  `dhcp_renewal_leases` пуст, и создаёт `/run/yonik-dhcp-sleep-post` после
  пробуждения. В Debian 13.7 и Ubuntu 24.04.5 набор был пуст перед S3
  на обоих движках. Топология изменилась, поэтому helper остановил worker.
  После нового подключения тест проверил блокировку прежних Fake-IP,
  работу новых Fake A/AAAA, продление двух DHCP-лизингов и неизменность
  `/etc/resolv.conf`. Тот же сценарий пройден в Fedora Cloud 45 с
  SELinux Enforcing, systemd 262 и nftables 1.1.6 после установки RPM.
  Управляющий линк Fedora был статическим, чтобы штатное отключение
  интерфейсов NetworkManager перед сном не опередило проверку logind.
  Для NetworkManager 1.58.1 отдельно проверен установленный RPM
  `0.1.0-901.fc45` в Fedora 45 при SELinux Enforcing. Стенд с
  `tools/fixtures/networkmanager_dhcp.sh s3` и
  `production_helper_fake_dns_networkmanager_suspend` использовал
  отдельную чистую VM на Xray и sing-box. До запроса сна helper
  обновлял DHCP-элемент. К входу в S3 старый туннель остановился и
  набор уже отсутствовал. QMP подтвердил S3 и пробуждение. После
  нового DHCPACK и двух секунд без сетевых событий прежние Fake-IP
  остались заблокированы, новая сессия получила допуск DHCP и прошла
  трафик по Fake IPv4 и IPv6. Stop удалил набор. Содержимое и
  метаданные `/etc/resolv.conf` совпали до и после.
  В одном прогоне после S3 снимок Prepare содержал tentative IPv6-адрес.
  Ядро завершило DAD и добавило маршрут до сверки активной сессии.
  Prepare теперь ждёт завершения DAD на работающих интерфейсах по событиям
  Netlink до трёх секунд с учётом отмены и заново связывает снимок с
  поколением сети. Apply и проверка активной сессии по-прежнему сверяют всю
  топологию. В отдельных Fedora VM с SELinux Enforcing регрессия создала
  tentative IPv6-адрес перед повторным подключением. Оба движка прошли
  S3, новый DHCPACK, Fake A/AAAA, трафик IPv4/IPv6 и Stop. Для прогона
  поверх установленного RPM заменили только helper на проверяемую сборку.
  В совмещённом прогоне Xray → sing-box оба подключения дошли до новых
  Fake A/AAAA после своих циклов S3. После второго S3 временный допуск
  DHCP для sing-box отсутствовал. В отдельном диагностическом прогоне
  после S3 оба кандидата на допуск исчерпали 100 мс при начальном чтении
  лизинга, поэтому helper не создал правило. Лимит начального чтения
  увеличен до 300 мс на интерфейс. Периодическое чтение и повторное
  подтверждение лизинга перед обновлением nftables используют 100 мс.
  Штатный тест `production_helper_fake_dns_networkmanager_suspend` с
  `YONIK_NM_DHCP_ENGINE=both` прошёл дважды в чистых Fedora VM с
  обновлённым helper поверх RPM. Для каждого движка QMP подтвердил S3,
  тест зафиксировал новый DHCPACK, допуск DHCP, Fake A/AAAA, трафик
  TCP/UDP по IPv4 и IPv6, блокировку старых Fake-IP и Stop.
  Содержимое и метаданные `/etc/resolv.conf` совпали. Контрольный прогон
  с лимитом 100 мс также прошёл, отказ на прежнем лимите был плавающим.
  Нативный RPM Fedora `0.1.0-902.fc45.x86_64` собран из `8019e237`.
  Две чистые VM с SELinux Enforcing прошли тот же тест в режиме `both`
  с helper и worker из пакета. В каждой зафиксированы два цикла S3,
  новый DHCPACK после каждого пробуждения и допуск в новой сессии.
  Сверены SHA-256 RPM и установленных ELF. `rpm -V` прошёл до и после
  теста. Содержимое и метаданные `/etc/resolv.conf` совпали.
  При работающем sing-box первый лизинг также продлился с приостановленным
  вторым DHCP-сервером. На прежней сборке контрольный NSS-запрос падал
  при параллельном прогоне после повторного продления. Регрессионный тест
  воспроизвёл расхождение, когда снимок ядра ещё содержал прежний срок,
  а networkd уже вернул новый.
  Если расходятся только конечные сроки известных DHCPv4-адресов,
  helper один раз перечитывает топологию и лизинги с общим лимитом 300 мс.
  Второе чтение должно подтвердить оба срока. Смена маршрутов, правил,
  адресов или других свойств линка ведёт к штатной остановке.
  После исправления синхронно запущены четыре стенда с установленным
  helper. Fedora прошла S3 и отдельную проверку отказа FIB для `CS6`, а
  Debian и Ubuntu повторили продление на Xray и sing-box. Во всех четырёх
  стендах первый лизинг продолжил обновляться при недоступном втором
  сервере, Fake DNS и TUN продолжили работу, а `/etc/resolv.conf` совпал
  по содержимому и метаданным.
  [Справочник QEMU QMP](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html)

## 4. Fake DNS и проверка пакетов

- [x] Использовать существующий [план DNS](../../proposals/p14-production-integration/rust-plan-v1.md).
  Закрепить соответствие имени и Fake-IP на период выданного TTL, проверять
  маршруты пула на конфликты, блокировать неопознанный адрес. Проверить
  исчерпание пула, устаревший адрес после смены ядра и привязку выбранного
  реального адреса к соединению при совместных доменных и CIDR-правилах.
- [x] Проверить выдачу Fake A/AAAA и границы TTL на уровне DNS-ответа.
  Повторный запрос сохраняет адрес и исходный срок аренды, TTL округляется
  вниз, истёкшая до публикации аренда отклоняется. При исчерпании пула
  ответ содержит `SERVFAIL` без синтетического адреса. На ревизии `f647405`
  с Rust 1.85.1 прошли все 42 библиотечных теста `yonik-engine` и 1076
  тестов `yonik-linux`. Ещё 51 тест `yonik-linux` был пропущен в обычном
  запуске. [Тесты DNS-ответов](../../../crates/yonik-engine/src/fake_dns.rs)
- [x] Проверить истечение Fake-IP во время открытия TCP-соединения для D-07.
  После SOCKS-аутентификации у движка helper повторно подтверждает текущее
  соответствие Fake-IP исходной аренде при записи CONNECT. Если её срок
  истёк или поколение изменилось, клиент получает SOCKS-ответ «адрес
  недоступен». Тест с управляемыми часами удерживает аутентификацию до
  истечения TTL, в том числе с повторной выдачей того же адреса тому же
  имени. Движок получает EOF без единого байта CONNECT.
  UDP проверяет исходную аренду перед отправкой в обе стороны. Повторная
  выдача адреса для прежнего назначения закрывает старую ассоциацию.
  Тесты проверяют отсутствие отправки и запоздалого ответа после смены аренды.
  С этой правкой установленные в Debian VM helper и worker без
  `test-support` прошли штатный Prepare, Fake A/AAAA, TCP/UDP по IPv4 и
  IPv6, HTTPS, контрольный DoH, Stop и Unlock на обоих движках.
  Содержимое и метаданные `/etc/resolv.conf` совпали до и после.
  [Тесты моста](../../../crates/yonik-linux/src/fake_flow.rs)
- [x] Провести A/AAAA по TCP/UDP в изолированном TUN с Xray и sing-box.
  Контрольный сервер принимает соединения по исходному имени, а повтор после
  смены ядра отклоняет старый адрес. Проверка loopback с тремя UID подтверждает,
  что только helper и worker могут отправлять трафик со специальным адресом
  или к нему.
- [x] Проверить невыданные IPv4 и IPv6 из синтетических пулов в активном TUN.
  На Arch Linux ARM установленный helper с Xray и sing-box обслужил
  контрольные соединения к выданным адресам. Для каждого невыданного
  адреса счётчики подтвердили попытки TCP и UDP через TUN и ноль пакетов
  на двух внешних интерфейсах. VLESS-стенд подтвердил соединения по
  исходному имени, обращений к невыданным адресам в его журнале не было.
  Ссылка и содержимое `/etc/resolv.conf` совпали до и после. Проверка
  включается через `YONIK_CHECK_UNISSUED_FAKE_IP=1`.
- [x] Сохранять узкий блок Fake-IP пулов в ядре до истечения выданного TTL.
  При выключенном kill switch обычная сеть должна восстанавливаться сразу.
  Проверить Stop, Unlock, SIGKILL, повторное подключение и запись журнала.
  Debian подтвердил фильтрацию старых IPv4/IPv6 Fake-IP после Stop/Unlock
  при работающем обычном маршруте. Стенд также удалил таблицу Fake-IP после
  Unlock и подтвердил, что helper восстановил её до истечения срока защиты.
  Отдельный прогон завершил helper через SIGKILL после выдачи A/AAAA.
  Перезапущенный helper восстановил состояние, Unlock вернул обычную сеть,
  а проверенная таблица Fake-IP была снята после таймера ядра.
  В Arch Linux ARM после сетевого прогона Xray и sing-box стенд
  подтвердил отсутствие TUN и остановку helper. У обоих семейств
  максимальный оставшийся TTL составил 82 с до остановки, а через
  83 с от начала измерения ядро очистило оба набора. После истечения
  таймера системный DNS отвечал при остановленном helper.
- [x] Повторить SIGKILL и проверку карантина через штатный Prepare с обоими
  движками. На Debian 13.7 и Ubuntu 24.04.5 LTS штатные службы запускали
  helper и worker без `test-support`. До падения прошли Fake A/AAAA, TCP/UDP
  IPv4/IPv6, HTTPS с проверкой сертификата и контрольный DoH. После
  перезапуска с Xray и включённым kill switch блокировка сохранялась до Unlock,
  а с sing-box и выключенным kill switch обычная сеть была доступна ещё
  до Stop. В обоих случаях попытка отправить UDP к старым Fake A/AAAA по
  добавленным физическим маршрутам получила `EPERM`. Таблица карантина
  снялась после истечения таймера. Содержимое и идентичность
  `/etc/resolv.conf` совпали до и после всех четырёх сценариев.
  Архитектурный прогон на Arch Linux ARM повторил оба сценария через
  установленный helper с uplink-файлом systemd-resolved. После восстановления
  Xray требовал Unlock, а sing-box вернул состояние `no_managed_policy`.
  Прежние Fake IPv4/IPv6 фильтровались до истечения карантина.
  [Тесты установленного helper](../../../crates/yonik-linux/tests/installed_helper_session.rs)
- [x] Пройти G-DNS для Xray и sing-box. Проверять конечный сервер соединения,
  внешние DNS-пакеты и отсутствие пакетов к синтетическим адресам вне TUN.
  Условия зафиксированы в [D-01…D-07](../../specs/validation-and-roadmap.md#обязательные-случаи-g-dns).
  Для используемого в этой ветке режима D-06 подтверждены блокировка
  приватной зоны на публичном пути и восстановление её DNS после Stop и
  возврата WireGuard. Одновременный доступ к приватному DNS через
  локальный WireGuard при активном Fake DNS отложен по решению пользователя.
  С актуальным установленным тестовым `.deb` из `eebcca65` в двух свежих
  Debian 13 VM повторены D-02, D-03 и D-05. Стенд переставил записи
  внутри A и AAAA. В одном прогоне AAAA удерживался до тайм-аута,
  в другом стенд ответил SERVFAIL.
  На Xray и sing-box VLESS принял имя `early.example.test` по личному
  правилу Proxy без обращения к DNS политики для этого имени.
  Для нескольких A/AAAA оба порядка дали тот же IPv6 по старшему CIDR.
  В обоих вариантах отказа DNS стенд отправил восемь A-ответов, helper
  зарегистрировал `DNS_POLICY_UNRESOLVED` на каждом движке, а VLESS
  не получил ни имени, ни адреса из неполного ответа. Контроль NODATA
  прошёл, счётчики DNS и Fake-IP на физическом выходе остались нулевыми,
  содержимое и метаданные `/etc/resolv.conf` совпали.
  Классификатор возвращает канонический адрес из проверенного набора,
  который соответствует первому совпавшему правилу. Перестановка A/AAAA
  сохраняет маршрут и адрес. Если старшее условие потребовало проверить
  DNS, последующий переход к правилу без CIDR сохраняет адрес из того же
  набора. Совпавшее доменное правило, которому DNS не требовался, не
  использует адрес из переданного ответа.
  Установленный helper передаёт восстановленное имя через SOCKS, если
  старшее доменное правило сразу выбирает Proxy. Когда правило требует
  реальный CIDR, helper сначала запрашивает явно заданный DNS политики и
  передаёт движку выбранный буквальный IP. Профилю, которому нужен DNS
  политики, для этого режима требуется его адрес в Prepare.
  [Тесты классификатора](../../../crates/yonik-domain/tests/dns_policy.rs)
  · [Допуск Fake DNS](../../../crates/yonik-engine/src/system_tun/fake_bridge.rs)
  На изолированном стенде Xray 26.10.31 и закреплённый sing-box 1.14.4
  приняли буквальные IPv4/IPv6 через один SOCKS-вход на движок. Отдельные
  учётные записи направляли трафик через Proxy и Direct. Стенд
  передал выбранный классификатором IPv6 в Proxy при обоих порядках
  ответов и IPv4 в Direct при NODATA для AAAA. TCP и UDP прошли.
  При неполном ответе и SERVFAIL стенд отказал до обращения к SOCKS.
  DNS-адаптер собирает пару ответов с совпадающими исходным DNS-вопросом,
  конечным именем CNAME, узлом и режимом транспорта. Для DoT он также
  сверяет экземпляр TLS-конфигурации. TTL ограничен записями A/AAAA,
  цепочкой CNAME и SOA для подтверждённого NODATA. Срок отсчитывается
  от получения каждого ответа. В тесте с DNS по UDP классификатор использовал
  полученную пару для Fake-IP и после истечения TTL потребовал новый ответ.
  Тест Linux-моста меняет ответ DNS политики во время аутентификации
  SOCKS, после классификации и до CONNECT. В адресном поле CONNECT
  остаётся проверенный публичный IP. До завершения потока стенд получает
  только исходную пару запросов A/AAAA. Независимая классификация после
  смены ответа получает защищённый A и публичный AAAA и возвращает
  `DNS_POLICY_AMBIGUOUS`. Проверка использует реальные TCP-сокеты
  loopback и проверяет SOCKS-сообщение на входе движка.
  Клиент для публичного policy-resolver отправляет оба вопроса через
  SOCKS с аутентификацией к явно заданному IP и порту. Один дедлайн
  ограничивает весь обмен, включая аутентификацию. SERVFAIL закрывает
  пару, в том числе второй незавершённый запрос. В изолированной сети
  Xray и sing-box довели запросы A и AAAA до указанного узла через
  VLESS. При неверной авторизации DNS-узел запросов не получил.
  Prepare принимает явный адрес policy-resolver для профиля Fake DNS.
  Helper добавляет в конфигурацию worker отдельный SOCKS-аккаунт с
  доступом только по TCP к точному IP и порту. В Debian VM подготовка и
  запуск с этим адресом прошли на обоих движках. В отдельном прогоне
  конфигурация из штатного компилятора доставила A и AAAA до заданного
  DNS-сервера. Попытки использовать другой IP, другой порт, доменное
  назначение или UDP не дошли до контрольного peer.
  В публичных профилях с CIDR-правилами этот клиент включён в тракт Fake-IP.
  Helper передаёт ядру выбранный IP и проверяет срок аренды и DNS-ответа
  перед записью. Смешанные доменные и CIDR-правила прошли приёмку в Debian
  на Xray и sing-box. Защита приватного DNS подтверждена в D-06.
  [DNS через выбранный прокси](../../../crates/yonik-linux/src/resolver/forward/policy_proxy.rs)
  · [Разбор DNS для политики](../../../crates/yonik-linux/src/resolver/forward/policy_rrset.rs)
  · [Подтверждение NODATA и TTL](https://www.rfc-editor.org/rfc/rfc2308.html#section-5)
  На Fedora Cloud 45 с SELinux Enforcing установленный RPM
  `0.1.0-901.fc45` прошёл сценарий `production_helper_resolved_fake_dns_mixed`
  в двух свежих VM. DNS политики отдал `example.test` по две записи A и
  AAAA в прямом и обратном порядке. Для обоих порядков и движков
  журналы VLESS peer подтвердили TCP и UDP к `2001:db8:746f::2`,
  адресу из старшего правила Proxy. Другие адреса из этой пары RRset
  не появились среди соединений стенда к эхо-серверу. Отдельные запросы
  к буквальным IP прошли свои правила. Для `early.example.test` peer
  получил имя без запроса к DNS политики. SERVFAIL и NODATA проверены
  отдельными запросами. Stop прошёл, содержимое и метаданные
  `/etc/resolv.conf` совпали до и после. Это подтверждает D-03
  для входа через Fake-IP в этой конфигурации и часть D-02 и D-05.
  Для контроля D-03 с буквальным IP установленный тестовый `.deb` из
  `a03f49f0` запущен в Debian 13 с resolvconf и выключенным Fake DNS.
  На Xray и sing-box раннее пользовательское Proxy для IPv4 /32 и IPv6
  /128 выиграло у более широкого Block из пресета. При раннем Block
  более широкий Proxy из пресета не пропустил TCP и UDP к тем же IP.
  VLESS peer зарегистрировал ровно восемь разрешённых потоков на два
  движка и оба семейства. DNS-стенд видел только контрольные запросы
  до и после сессий. Stop восстановил обычный DNS, содержимое и
  метаданные `/etc/resolv.conf` совпали.
  С установленным тестовым `.deb` из `eebcca65` в Debian 13 повторили
  проверку буквального входа с TLS SNI при выключенном Fake DNS.
  DNS для `example.test` вернул IPv4 и IPv6 из другого CIDR до запуска
  первого worker. HTTPS-клиент сохранил SNI `example.test` и явно
  подключился к выбранным буквальным IPv4 и IPv6. При Proxy журнал VLESS
  подтвердил оба выбранных адреса на каждом движке, а HTTPS-сервер
  подтвердил SNI и ответил после проверки сертификата клиентом. При
  CIDR Block ни один из запросов не дошёл до сервера. После запуска
  первого worker запросов к DNS стенда для `example.test` не было.
  Содержимое и метаданные `/etc/resolv.conf` совпали.
  С тем же установленным пакетом два отдельных прогона с включённым
  Fake DNS проверили TLS SNI в смешанном профиле. Доменное правило Proxy
  пропустило HTTPS через выданный Fake-IP в обоих прогонах. Для
  буквальных IPv4 и IPv6 с тем же SNI решение зависело от CIDR.
  В первом прогоне VLESS зарегистрировал оба буквальных назначения
  для каждого движка. Во втором прогоне ни одно из них до peer не дошло.
  В обоих прогонах сервер подтвердил SNI для разрешённых соединений.
  После запуска первого worker запросов к исходному DNS для
  `example.test` не было, `/etc/resolv.conf` совпал до и после.
  Для явного CIDR Direct при выключенном Fake DNS установленный
  `.deb` из `9d5f09f2` прошёл два отдельных прогона Debian 13.
  На Xray и sing-box тест провёл IPv4/IPv6 TCP и UDP через физический
  шлюз. Подключения к адресам из тех же CIDR без шлюза и отправка
  пакета с верной меткой от другого UID блокировались. Дополнительный
  IPv6 CIDR без маршрута не помешал запуску и работе остальных адресов.
  В отдельном госте Prepare отклонил оба профиля с Direct CIDR,
  пересекавшимися с префиксами WireGuard при наличии физического шлюза.
  Состояние сети осталось `no_managed_policy`. Содержимое и метаданные
  `/etc/resolv.conf` совпали в обоих прогонах. Третий гость с тем же
  пакетом повторил успешную смену движка с Fake DNS, проверку CNAME
  и карантин старых Fake-IP.
  Для D-02 в смешанном тесте перенесли младший Direct CIDR в
  `preset_rules`, через который desktop передаёт правила ru-direct.
  Стенд DNS политики сопоставляет конфликтующему `early.example.test`
  адреса этого CIDR. С установленным RPM `0.1.0-902.fc45.x86_64` на
  Xray и sing-box победил личный Proxy. VLESS peer зарегистрировал
  имя по TCP и UDP при подключении к Fake IPv4 и Fake IPv6.
  DNS политики получил контрольные запросы для `direct.example.test`
  и ни одного для `early.example.test`. `rpm -V` прошёл до и после.
  Содержимое и метаданные `/etc/resolv.conf` совпали.
  В диагностическом повторе Debian отказ пришёл при проверке
  systemd supervisor. Unit-файлы worker были загружены из
  `/etc/systemd/system`. Для установленного worker проверяется
  канонический путь `/usr/lib/systemd/system`. В двух свежих Debian VM
  проверены штатный путь, владельцы и режим unit-файлов, затем обычные
  ELF helper и worker из сборки `b43c7f55` прошли обе перестановки на
  Xray и sing-box. Журналы peer подтвердили тот же IPv6 по TCP и UDP.
  Содержимое и метаданные `/etc/resolv.conf` совпали до и после.
  В отдельном прогоне D-05 на Debian тот же helper получил A для
  `failed.example.test`, а DNS политики удерживал AAAA без ответа.
  Для Xray и sing-box тест подтвердил отказ TCP и UDP на Fake IPv4 и
  Fake IPv6. Стенд отправил восемь A-ответов и увидел закрытие всех
  восьми соединений с незавершённым AAAA. VLESS peer был настроен
  принять соединение и к адресу из ответа A, и к исходному имени.
  Оба назначения отсутствовали в его журнале. Счётчики nftables
  на выходе из VM зафиксировали контрольный VLESS-трафик и ноль
  пакетов к пулам Fake-IP, к адресу из неполного ответа и к портам
  53/5353 вне TUN и loopback. Положительные DNS-сценарии, HTTPS, DoH
  и Stop прошли. Содержимое и метаданные `/etc/resolv.conf` совпали
  до и после.
  Установленный Fedora RPM `0.1.0-902.fc45.x86_64` проверен в двух
  отдельных VM с SELinux Enforcing. В первой DNS политики отправил A и
  удержал AAAA до закрытия всех восьми запросов. Во второй AAAA вернул
  SERVFAIL после A. В обеих VM Xray и sing-box отклонили TCP и UDP к
  Fake IPv4 и IPv6, а корректный NODATA одного семейства прошёл.
  VLESS peer был готов принять имя и IPv4 из неполного ответа. Ни одного
  такого соединения в журнале нет. На физическом выходе счётчики показали
  обычный VLESS-трафик и ноль пакетов к Fake-пулам, неполному IPv4 и
  портам DNS 53/5353. `rpm -V` прошёл, содержимое и метаданные
  `/etc/resolv.conf` совпали. В сценарии
  `production_helper_resolved_fake_dns_partial_direct` A совпадал
  только с младшим пресетом Direct, а незавершённый AAAA мог изменить
  решение старшего правила. Перед запуском TUN стенд подтвердил
  доступность адреса по TCP и UDP. В отдельных прогонах timeout и
  SERVFAIL с тем же RPM оба движка отклонили подключения. Счётчик
  выхода к адресу из A и журнал VLESS подтвердили отсутствие fallback.
  Linux bridge сохраняет `DNS_POLICY_UNRESOLVED` при ошибке обязательного
  lookup или если срок ответа истёк до применения решения. Селектор TCP
  и UDP сообщает этот код в журнал helper до одной записи за сессию.
  Запись содержит только фиксированный текст. Очередь диагностики
  ограничена, запись в stderr выполняется вне сетевого цикла.
  В отдельных VM с установленным Fedora RPM `0.1.0-903.fc45.x86_64`
  журнал содержал по одной записи для сессии Xray и sing-box при timeout
  и при SERVFAIL. В обоих случаях остались нулевыми счётчики Fake IPv4,
  Fake IPv6, неполного A и DNS 53/5353 на физическом выходе.
  `rpm -V` прошёл, содержимое и метаданные `/etc/resolv.conf` совпали.
  С теми же ELF в отдельных Debian VM проверена действующая защита
  приватной зоны `wg.test`. На Xray и sing-box зона исключалась из
  публикации Fake DNS и оставалась закрытой после отключения WireGuard
  и перезапуска helper. Запросы к приватной зоне не получили Fake-IP.
  Журнал VLESS не содержал соединений к контрольным IPv4 и IPv6
  приватной сети. Приватные DNS и трафик через WireGuard снова прошли
  после Stop. Это подтверждает принятую защиту D-06 для данного стенда.
  На установленном тестовом `.deb` из `eebcca65` в двух свежих Debian 13 VM
  публичный DNS ответил на контрольное имя под `wg.test` перед запуском
  WireGuard. После отключения WireGuard и перезапуска helper запрос
  к приватному имени через системный NSS завершился отказом. Запросы
  по TCP и UDP к DNS TUN также сохранили блокировку приватной зоны.
  В журнале публичного DNS для этой зоны остался только контрольный
  запрос до запуска. После Stop и повторного запуска WireGuard его
  приватный резолвер ответил на новое имя, TCP/UDP IPv4/IPv6 прошли.
  Результат совпал на Xray и sing-box, `/etc/resolv.conf` сохранил
  содержимое и метаданные.
  Для D-01 и D-04 отдельно проверена граница допуска профилей.
  В Debian и Fedora с SELinux Enforcing установленный helper на
  Xray и sing-box вернул `Unsupported` на Prepare для профиля Fake DNS
  с явным CIDR недоступного приватного VPN и для профиля с CIDR двух
  доступных VPN. Контрольный профиль с теми же публичными правилами
  прошёл Prepare. В журналах DNS политики и VLESS peer не появилось
  запросов. Состояние сетевой политики осталось `no_managed_policy`,
  содержимое и метаданные `/etc/resolv.conf` совпали до и после.
  Для режима Fake DNS с резолвером политики helper проверяет весь ответ
  A/AAAA по префиксам WireGuard из того же снимка, что и nftables.
  Приватное назначение блокируется. Смесь защищённых и публичных адресов
  даёт `DNS_POLICY_AMBIGUOUS` до передачи назначения движку. При
  защищённых префиксах раннее правило Proxy также использует проверенный
  буквальный адрес.
  В Debian 13 установленный helper на Xray и sing-box отклонил полный
  ответ с публичным A и защищённым AAAA. В журнале VLESS не было
  соединений к обоим адресам и к имени. Счётчики физического выхода
  остались нулевыми для адресов из ответа, Fake IPv4/IPv6 и DNS на 53/5353.
  Домен с ранним Proxy и публичными A/AAAA прошёл через выбранный IP.
  HTTPS, DoH, Stop и Unlock прошли на обоих движках. Содержимое и
  метаданные `/etc/resolv.conf` совпали.
  В отдельной Debian 13 VM A и AAAA из ответа политики принадлежали
  разным WireGuard-интерфейсам. IPv4-маршрут использовал именованный
  nexthop, IPv6 был связан с интерфейсом напрямую. На каждом движке
  установленный helper записал `DNS_POLICY_AMBIGUOUS`, а TCP/UDP
  к Fake A/AAAA завершились отказом. Журнал VLESS не содержал ни
  одного из двух адресов и имени, счётчики этих адресов, Fake-IP и
  обычного DNS на физическом выходе остались нулевыми. Контрольный
  прогон с публичным и защищённым адресами повторил тот же отказ.
  В обоих прогонах прошли публичный HTTPS, DoH, Stop и Unlock.
  Содержимое и метаданные `/etc/resolv.conf` совпали. Ответы из одной
  защищённой сети и пересекающихся префиксов проверены тестами
  классификации. Для D-01 тест
  `production_helper_resolved_fake_dns_guarded_proxy` использует одно
  раннее правило Proxy для `early.example.test` и `guarded.example.test`.
  В Debian 13 DNS политики вернул для первого имени публичные A/AAAA,
  для второго — A/AAAA из маршрутов одного интерфейса WireGuard.
  На Xray и sing-box публичное имя прошло через выбранный буквальный IP.
  Для защищённого имени клиент получил Fake A/AAAA, но TCP и UDP
  к ним завершились отказом. В журнале VLESS нет ни защищённого имени,
  ни его адресов. На физическом выходе их счётчики нулевые. Содержимое
  и метаданные `/etc/resolv.conf` совпали.
  D-01 и оба варианта D-04 повторены в трёх свежих Debian 13 VM
  с установленным тестовым `.deb` из `eebcca65`. SHA-256 helper и worker
  сверены с архивом. В каждом прогоне прошли Xray и sing-box.
  Для D-01 VLESS peer принял проверенный публичный адрес по TCP и UDP,
  а соединений к защищённому имени и адресам в его журнале не было.
  Для D-04 проверены полный ответ с публичным A и приватным AAAA
  и полный ответ с адресами двух отдельных WireGuard-интерфейсов.
  В каждом варианте helper записал по одному `DNS_POLICY_AMBIGUOUS`
  на движок. Счётчики внешнего выхода показали контрольный VLESS-трафик
  и ноль пакетов к защищённым адресам, пулам Fake-IP и DNS на 53/5353.
  Содержимое и метаданные `/etc/resolv.conf` совпали во всех прогонах.
  [Проверка профиля установленным helper](../../../crates/yonik-linux/tests/installed_helper_session.rs)
  Отдельная проверка TTL ниже покрывает часть D-07.
  На установленном тестовом `.deb` из `eebcca65` в двух свежих Debian 13 VM
  DNS политики вернул публичные A/AAAA, и Xray и sing-box провели TCP
  и UDP к проверенному IP. После истечения TTL старые Fake IPv4/IPv6
  отклонены до первого свежего DNS-запроса. С новым ответом, содержащим
  защищённый A и публичный AAAA, соединения к вновь выданным Fake-IP
  получили отказ `DNS_POLICY_AMBIGUOUS` при том же PID worker. В журнале
  VLESS соединения к эхо-серверу есть только до истечения TTL.
  Счётчики внешнего выхода остались нулевыми для защищённых адресов,
  Fake-IP и DNS на 53/5353. После Stop действовал карантин, содержимое
  и метаданные `/etc/resolv.conf` совпали.
  В Arch x86-64 и Debian 13 установленные пакеты `08f66b21` прошли
  Xray → sing-box → Xray в пределах TTL каждого прежнего DNS-ответа.
  При каждом переходе сменился PID worker, а подключения к прежним
  Fake IPv4/IPv6 блокировались до первого свежего запроса DNS. Новый
  ответ выдал другие адреса, на которых прошли TCP/UDP, HTTPS с
  проверкой сертификата и DoH. После Stop проверены блокировка Fake-IP
  на физическом выходе, ответ штатного DNS и неизменность
  `/etc/resolv.conf`. Хеши установленных ELF совпали с архивами.
  Для файловой схемы DNS релей публикует синтетические A/AAAA с TTL 0.
  Внутренний срок аренды Fake-IP составляет до 30 секунд, карантин
  сохраняется при смене движка. В Fedora с DNS от NetworkManager
  это исключило повторную выдачу адресов предыдущей сессии из кэша
  systemd-resolved. Последовательный прогон с установленными пакетами
  Fedora и Debian подтвердил блокировку старых IPv4/IPv6 и работу
  новых адресов через TCP и UDP. TTL реальных ответов задаёт исходный
  резолвер.
  Для HTTPS с явно заданным IP в Arch и Debian тот же пакет проверен
  с именем `doh.test` в TLS и адресом `203.0.113.45`. На обоих
  движках прошла проверка сертификата, а журнал VLESS подтвердил
  исходный буквальный адрес. В журнале публичного DNS стенда запросов
  `doh.test` не было. Содержимое и метаданные `/etc/resolv.conf` совпали.
  Контрактные тесты конфигурации проверяют отказ для рекурсивного
  bootstrap. Штатный Prepare системного TUN поддерживает буквальный IP
  и имя через обычный файл `resolv.conf` или доверенный путь NetworkManager
  или resolvconf с числовым DNS-сервером.
  Для имени helper отправляет запрос на первый штатный сервер с
  привязкой к подтверждённому интерфейсу. Срок адреса учитывает CNAME,
  а до Apply повторно проверяются DNS-конфигурация, маршрут к DNS и
  маршрут к прокси. Срок учитывает время сна через `CLOCK_BOOTTIME`.
  В Arch x86-64 через установленные helper и worker тест отклонил
  Apply обоих движков после 20-секундного CNAME при TTL конечного IP
  в 120 секунд. Для свежего профиля DNS-стенд подтвердил переход UDP
  → TCP к исходному серверу. Xray и sing-box дали Fake A/AAAA и провели
  TCP/UDP через TLS-прокси. Содержимое и метаданные `/etc/resolv.conf`
  совпали; helper и worker были обновлены поверх установленного пакета.
  В Arch с systemd 262.2 и Debian с systemd 257.13 проверен
  `ResolveRecord` на отдельном DNS-стенде. Прямые A и AAAA вернули
  индекс линка и исходные TTL. При запросе A через CNAME ответ D-Bus
  содержал только конечную запись с TTL 67 секунд, хотя CNAME имел TTL
  7 секунд. Самостоятельный запрос CNAME вернул 7 секунд, а A с
  `NO_CNAME` завершился отказом. Содержимое и метаданные
  `/etc/resolv.conf` совпали. Для bootstrap с псевдонимами срок допуска
  должен учитывать всю цепочку. Существующий разбор полного DNS-пакета
  в `policy_rrset` подтвердил этот расчёт в тесте.
  [Ответ ResolveRecord](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html)
  В тех же версиях systemd TCP-ответы с 127.0.0.53 и 127.0.0.54
  содержат CNAME вместе с конечной A или AAAA. Содержимое и метаданные
  `/etc/resolv.conf` совпали. Prepare использует полный stub 127.0.0.53.
  Helper сверяет UID и cgroup серверной стороны установленного TCP
  соединения с владельцем systemd-resolved. После ответа проверяет
  тот же inode и cookie, а до Apply повторно читает снимок службы и DNS.
  Путь через 127.0.0.53 сохраняет системную проверку DNSSEC.
  В Arch x86-64 и Debian 13 обновлённые helper и worker запущены
  поверх установленных пакетов. Чужой слушатель на 127.0.0.53:53
  принял TCP и не получил DNS-запроса. Штатный stub на обеих системах
  прошёл истечение CNAME перед Apply и свежий запуск Xray и sing-box
  с Fake A/AAAA и TCP/UDP через TLS-прокси. Содержимое и метаданные
  `/etc/resolv.conf` совпали. Debian-стенд создал системного пользователя
  штатной командой `systemd-sysusers` после установки тестового пакета.
  [Режимы stub systemd-resolved](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html#DNSStubListener=)
  После проверки маршрута Prepare закрепляет тот же IP в конфигурации
  движка и сверяет исходные адрес и порт. Тесты компилятора проверили
  сохранение TLS SNI и WebSocket Host. В Arch x86-64 с проверенными по
  хешу свежими helper и worker поверх установленного пакета Xray и
  sing-box прошли Fake DNS, HTTPS с проверкой сертификата и Stop.
  Содержимое и метаданные `/etc/resolv.conf` совпали.
  Компилятор Fake DNS принимает выбранный адрес от helper как с политикой,
  так и без неё. Тесты обоих движков подтвердили сохранение TLS-имени и
  отказ при совпадении с адресом TUN, DNS или пулом Fake-IP.
  Повторный прогон обновлённых helper и worker в Arch x86-64 подтвердил
  HTTPS с буквальным адресом на обоих движках и неизменность
  `/etc/resolv.conf`.
  Отдельно проверять обычный HTTPS после системного A/AAAA, включая проверку
  сертификата по имени, и HTTPS-запрос приложения к собственному DoH.
  Системный DNS может выдать Fake-IP для сайта. Приложение со своим DoH
  получает ответ выбранного им резолвера, а соединение с этим резолвером
  маршрутизируется как HTTPS-трафик. Для Firefox проверены системный DNS,
  строгий DoH, возврат к системному DNS при сбое DoH и исключение домена.
  [Режимы DNS через HTTPS в Firefox](https://support.mozilla.org/en-US/kb/dns-over-https)
  Для контрольного HTTPS в VM есть стенд
  [fake_dns_https.py](../../../tools/fixtures/fake_dns_https.py). Он слушает
  loopback в namespace VLESS peer на порту 24444. В тестовом peer назначения
  `example.test:443` и `203.0.113.45:443` направляются на этот стенд. Передать
  сертификат тестового CA через `YONIK_FAKE_DNS_TLS_CA`. Сертификат сервера
  должен покрывать `example.test` и `doh.test`. Сертификаты используются внутри
  теста. Оба запроса по 443 прошли в Debian и Arch на Xray и sing-box. Firefox
  проверен отдельным прогоном в Debian 13.7 с Firefox ESR 153.7. В отдельном
  профиле с системным DNS браузер открыл `example.test` через синтетический
  адрес на Xray. В профиле со строгим DoH браузер получил реальный адрес от
  тестового провайдера и открыл тот же сайт через sing-box. Адрес DoH
  провайдера в тесте задан напрямую. Имя сайта и адрес провайдера покрыты
  сертификатом тестового CA. На sing-box в отдельном профиле с системным
  fallback браузер открыл сайт после ответа HTTP 503 от DoH-провайдера.
  В другом профиле строгий DoH продолжал обслуживать другие имена, а
  `example.test` из списка исключений был открыт через системный DNS.
  Стенд подтвердил HTTPS-запрос для обоих профилей и отсутствие DoH-запросов
  для исключённого имени. Содержимое и метаданные `/etc/resolv.conf` совпали
  до и после.
- [x] Проверить HTTP/3 в Firefox ESR 153.7.0 на Debian 13.7 с установленными
  helper и worker на Xray и sing-box. HTTPS-сервер объявлял `Alt-Svc` для
  UDP/443. Стенд принимал сценарий только при записи `HTTP/3.0` со статусом
  200 в журнале Caddy 2.6.2. В профиле с системным DNS захват на TUN показал
  UDP/443 к Fake IPv6, а VLESS-сервер получил исходное имя `example.test`.
  В профиле со строгим DoH резолвер вернул реальный IPv4, который браузер
  использовал для HTTP/3 через TUN. Оба сценария прошли на обоих движках.
  В одноразовых профилях отключили ограничение HTTP/3 для сторонних корневых
  CA, поскольку стенд использовал собственный тестовый CA. Проверка цепочки
  и имени сертификата действовала. Содержимое и метаданные `/etc/resolv.conf`
  совпали до и после прогона.
  [Проверка стороннего корневого CA в Firefox](https://github.com/mozilla-firefox/firefox/blob/main/netwerk/protocol/http/Http3Session.cpp)
- [x] Проверить установку Fake DNS поверх штатной IP-only политики через
  `Prepare → ApplyOutputV1` с обоими ядрами. Правила DNS добавляются перед
  обычным списком, а его порядок и действие по умолчанию сохраняются.
  Первый вариант допускает только политики, которые дают Proxy для любого
  адреса. Direct, Block, LAN и приватные зоны закрывают этот путь до появления
  подтверждённого общего решения DNS и CIDR. Запрос требует явной политики
  в обычной сборке. Установленные helper и worker без `test-support` прошли
  эту проверку с Xray и sing-box в Debian и Arch. Полный цикл включал
  HTTPS с проверкой сертификата, контрольный DoH, Stop и Unlock. Содержимое
  и метаданные `/etc/resolv.conf` совпали до и после.
- [x] Применять доменные правила Proxy и Block к имени из действующей
  записи Fake-IP. Допускается Proxy по умолчанию, а доменные условия должны
  целиком входить в настроенные суффиксы Fake DNS. В Debian 13.7 точное
  пользовательское правило Proxy пропустило `example.test` раньше
  суффиксного Block из пресета. `blocked.example.test` получил Fake A/AAAA,
  затем оба движка заблокировали соединения к нему по TCP и UDP.
  В контрольном прогоне с действием Proxy тот же поддомен был доступен
  обоим движкам по IPv4/IPv6, TCP и UDP.
  Проверены HTTPS, DoH, Stop, Unlock и состояние `/etc/resolv.conf`.
  Доменные правила в этом режиме применяются к восстановленным именам.
- [x] Проверить сочетание доменных правил для Fake DNS с Proxy и Block по
  CIDR для буквальных IP. До первого CIDR доменные правила должны покрыть
  каждый выбранный суффикс. В Debian 13.7 Xray и sing-box пропустили
  `example.test` через точное пользовательское Proxy, а суффиксный Block
  остановил TCP и UDP для `blocked.example.test`. Независимые CIDR-правила
  остановили TCP и UDP для буквальных IPv4/IPv6. С действием Proxy те же
  контрольные адреса ответили обоим движкам. В обоих прогонах проверены
  маршрут контрольных адресов в TUN, HTTPS, DoH, Stop и состояние
  `/etc/resolv.conf`.
  Установочные сценарии `production_helper_scoped_fake_dns_literal_cidr_policy`
  и `production_helper_scoped_fake_dns_literal_cidr_control` используют
  эхо-сервер прокси на порту 40000 для `198.18.0.2` и `2001:db8:746f::2`.
- [x] Применять Direct с CIDR ненулевой длины для буквального IP по тем же
  правилам приоритета. Сессионный firewall проверяет TCP/UDP, UID worker,
  метку сокета, CIDR назначения, интерфейс и фактический шлюз пакета.
  Кандидаты интерфейсов и шлюзов берутся из проверенного снимка сети.
  Маршруты без шлюза не получают это разрешение. В Debian 13.7 Xray и
  sing-box открыли соединения к эхо-серверу через шлюз по IPv4 и IPv6.
  Прокси блокировал те же адреса. Вторые адреса из тех же CIDR с маршрутом без
  шлюза были заблокированы во время сессии и ответили после Stop/Unlock.
  Контрольный сокет с верной меткой и другим UID был заблокирован.
  Проверены снятие разрешений после Stop, HTTPS, DoH и неизменность
  `/etc/resolv.conf`. Сценарий `production_helper_scoped_fake_dns_literal_direct`
  использует `192.0.2.192/27` и `2001:db8:7471::/64`.
  В отдельном прогоне Xray помощник после SIGKILL снял разрешения Direct
  до явного Stop, а карантин Fake-IP действовал после Unlock до своего срока.
  Частные зоны и атрибуция приложений остаются в G-DNS.
- [x] Перед отправкой потока к Fake-IP применять публичные CIDR-правила к
  проверенной паре реальных A/AAAA. Этот режим доступен через Prepare для
  политики с правилами только по CIDR и явно заданным DNS политики.
  Helper спрашивает адрес DNS через выбранный прокси. Оба ядра получают
  буквальный IP, выбранный классификатором. Для Direct действуют те же
  ограничения сессионного firewall по адресу, интерфейсу и шлюзу.
  В Debian 13.7 сценарий `production_helper_resolved_fake_dns_cidrs` подтвердил
  Proxy, Direct, Block и отказ при неполном ответе DNS для обоих движков
  по TCP и UDP. HTTPS, DoH, Stop и сверка `/etc/resolv.conf` прошли.
  Библиотечные тесты отдельно проверяют два имени на общем реальном IP,
  изоляцию UDP при истечении DNS TTL и отсчёт TTL с учётом сна Linux.
- [x] Проверить на установленном helper публичный профиль с общим порядком
  доменных и CIDR-правил. В сценарии `production_helper_resolved_fake_dns_mixed`
  старшее доменное Proxy передало имя прокси без запроса к DNS политики.
  Старшее CIDR Block опередило младшее доменное Proxy, а SERVFAIL остановил
  такой же переход. Условие «домен и CIDR» проверено для Block и Direct.
  Для одного из адресов подтверждённый NODATA AAAA позволил применить Direct
  по A. Те же буквальные адреса сохранили собственную адресную политику.
- [x] Проверить запуск Fake DNS со свежим runtime-журналом сразу после установки.
  Цикл с двумя ядрами без начальной 30-секундной паузы прошёл за 19,43 с в Debian
  и 17,78 с в Arch. При наличии записи карантина после перезапуска помощника
  сохраняется ожидание максимального TTL.
- [x] Проверить Ubuntu 24.04.5 LTS без графической сессии. Ядро 6.8.0-147 и
  nftables 1.0.9 подтвердили запуск обоих движков, HTTPS, контрольный DoH и
  восстановление правил. Содержимое и метаданные `/etc/resolv.conf` совпали
  до и после. Проверка учитывает отсутствие поля `auto-merge` в выводе
  nftables 1.0.9 и сверяет установленные интервалы и таймеры.
- [x] Подключить выбор доменных суффиксов Fake DNS в настройках системного
  подключения desktop. Список сохраняется между запусками. С заполненным
  списком desktop отправляет текущую политику и выбранное ядро тем же
  системным способом `Prepare → ApplyOutputV1`. Для профиля сервера доступны
  оба ядра при совместимой политике. Полные Xray-профили используют своё ядро.
  В Arch одноразовый desktop backend прошёл подключение, HTTPS к имени из
  Fake DNS, Stop и Unlock с установленным helper на обоих ядрах. Состояние
  `/etc/resolv.conf` совпало до и после. Изменения собственного TUN проверяет
  helper. Desktop кратко повторяет Prepare при Busy. При Stale он один раз
  запрашивает новый снимок сети и заново отсчитывает окно для Busy. Оба
  повтора ограничены исходным дедлайном подключения.
- [x] Проверить Qt 6.4.2 в активной сессии Ubuntu 24.04.5 LTS с GNOME Shell 46
  и Wayland на ядре 6.8.0-147 с nftables 1.0.9. Клиент собран в гостевой ОС
  из текущей ветки. Для Wayland установлен `qt6-wayland`, для
  `QtQuick.Dialogs` — `qml6-module-qtquick-dialogs`, для SVG — `libqt6svg6`.
  Видимый Qt-клиент в smoke-режиме прошёл цикл подключения, Stop и Unlock
  с обычным UID, установленным помощником и штатными диалогами GNOME polkit.
  Независимый клиент той же пользовательской сессии на Xray и sing-box
  подтвердил Fake A/AAAA, IPv4/IPv6 TCP/UDP, HTTPS с проверкой сертификата и
  контрольный DoH. После Stop и Unlock старые Fake-IP блокировались даже
  при добавленном физическом маршруте. Элементы карантина истекли в ядре
  при остановленном helper. Содержимое и метаданные `/etc/resolv.conf`
  совпали до и после обоих подключений и истечения карантина.
  Обычный запуск с постоянным хранилищем также проверен после входа через
  GDM с паролем и `libpam-gnome-keyring`. При автологине с заблокированным
  кошельком Qt открыл окно и показал уведомление о хранилище секретов.
- [x] Проверить запуск Qt 6.11.2 на CachyOS x86-64 с ядром 7.2.9. Клиент
  собран из `6273b21` с Rust 1.97.0 и параметрами линковки из Arch PKGBUILD.
  В режиме offscreen с программным Qt Quick тест подтвердил видимое окно,
  готовность backend и штатное закрытие. Установка пакета и системный TUN
  проверяются отдельными сценариями.
- [x] Проверить нативный запуск desktop в Arch Linux ARM с Qt 6.12.0
  и ядром 7.3.5. Клиент `84d48fe` собран в QEMU с Rust 1.100.0 из
  адаптированного Arch PKGBUILD. ELF AArch64 из каталога сборки под обычным
  UID подтвердил готовность, видимое окно и штатное закрытие в режиме
  offscreen. Пакет из `4a773d87` отдельно прошёл запуск Qt и сетевой
  тест обоих движков после установки через pacman.
- [ ] Расширить приёмку до оставшихся сочетаний пакета, рабочего стола и
  графической системы.
  Для OpenRC/runit отдельно реализовать управление процессом worker с
  эквивалентными проверками личности, готовности и завершения. Supervisor
  должен привязать PID к конкретному запуску и подтвердить пустую отдельную
  cgroup перед очисткой сети. При перезапуске helper идентификация области
  worker требуется до использования журнала восстановления. Режим Check
  запускается без сетевых полномочий, а Run получает TUN и CAP_NET_ADMIN.
  Проверка пустой cgroup v2 выделена из systemd supervisor и применяется
  также к отдельному lookup worker. Она сверяет ID монтирования по
  открытому дескриптору и повторно сверяет inode каталога перед
  подтверждением пустоты. В Debian 13.7 с ядром 6.12.117 стенд увидел
  процесс во вложенной cgroup после повторного открытия, подтвердил
  пустоту после `cgroup.kill` и отклонил замену каталога и bind mount.
  В sandbox systemd отдельно проверены запуск Check и Recover с
  подтверждением пустоты. Установленный helper в Debian и Fedora RPM
  под SELinux Enforcing прошли Prepare, Apply, Stop и восстановление на
  Xray и sing-box с неизменным `/etc/resolv.conf`.
  [Семантика cgroup.events и cgroup.kill](https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files)
  В Debian VM стенд автономного запуска без настройки юнитов помещает
  процессы в разные cgroup до `exec`. После принудительной остановки
  контроллера стенд заново открывает cgroup, отклоняет bind mount другой
  группы и по очереди завершает каждую группу с проверкой пустоты.
  Следующий прогон в Debian VM запустил установленный Check worker
  с отдельным сетевым namespace и нулевыми capabilities через закрытый
  Unix-сокет без socket-активации systemd. До передачи конфигурации
  стенд сверил PID по pidfd, образ, UID/GID, cgroup и отсутствие
  дополнительных групп. Ожидание другого образа было отклонено.
  Фактические Xray и sing-box вернули статус Checked и освободили cgroup.
  В той же VM автономный Run получил только `CAP_NET_ADMIN` и остался в
  отдельном сетевом namespace контроллера. Стенд сверил образ, pidfd, UID/GID,
  cgroup и capabilities до передачи конфигурации. Для Xray и sing-box
  TCP-запрос через TUN получил ответ от локального SOCKS-сервера, счётчики
  RX и TX интерфейса выросли. После `cgroup.kill` стенд подтвердил выход
  ядра и пустоту cgroup перед удалением интерфейса. Штатная передача FD
  в systemd Check и Run теперь проверяет pidfd, время запуска, UID/GID
  и cgroup перед отправкой, отклоняет завершившийся процесс и сверяет
  PID в ACK. Run сохраняет исходный InvocationID до подтверждения.
  Этот код передачи использует и автономный стенд. В Debian и Fedora
  RPM с SELinux Enforcing штатные TUN и Fake DNS прошли с Xray и sing-box
  при неизменном `/etc/resolv.conf`. Установленный `yonik-helper` получил
  отдельные root-входы для автономных Check и Run. Launcher принимает
  заранее открытый блокирующий Unix listener в защищённом runtime,
  отклоняет лишние наследуемые FD, входит в нужную cgroup до `exec` и
  назначает права по роли. Debian VM подтвердила отказы для неверного
  stdin, неблокирующего listener и FD 3 без CLOEXEC, затем проверила
  Check и TCP через TUN на обоих установленных движках. Автономный
  backend подключён к сетевой сессии стендовой сборки helper в QEMU.
  Debian VM подтвердила остановку прежнего worker при старте, а также
  Prepare, Apply, Stop и Unlock через D-Bus с Xray и sing-box. Проверены
  NSS, Fake DNS, HTTPS по Fake-IP, DoH через TUN и неизменность
  `/etc/resolv.conf`. Перед передачей конфигурации launcher проверяет
  собственный mount namespace, делает унаследованные точки монтирования
  рекурсивно доступными только для чтения с `nodev,nosuid`, скрывает
  домашние каталоги и выделяет временные файловые системы. В приватном
  `/dev` только Run получает TUN. Отдельные тесты установленных Check и
  Run подтвердили ограничения на обоих движках. Полная сессия D-Bus
  повторно прошла в Debian VM с включённой файловой изоляцией.
  Для этого способа изоляции нужен util-linux с рекурсивными атрибутами
  монтирования. Launcher проверяет итог через `mountinfo` до запуска worker.
  [Документация util-linux](https://github.com/util-linux/util-linux/blob/master/sys-utils/mount.8.adoc)
  При штатной остановке автономного helper завершаются запросы D-Bus,
  затем запускается тот же порядок восстановления сети, что и при Stop.
  Debian VM подтверждает выход worker и исчезновение TUN до перезапуска
  helper. Карантин выданных Fake-IP сохраняется. Остановка Xray сохраняет
  включённый kill switch, после остановки sing-box с выключенным kill
  switch физический маршрут снова работает. Новый процесс выдерживает
  максимальный TTL перед повторной выдачей Fake-IP.
  Перед передачей конфигурации автономный supervisor проверяет, что
  worker получил собственный фильтр seccomp. Для его установки нужен
  `setpriv --seccomp-filter` из util-linux 2.41 или сборки с этим параметром.
  VM на x86-64 подтвердила Check и Run на обоих движках. Отдельная
  проверка в ядре подтвердила запрет `unshare`, AF_PACKET, изменяемой
  исполняемой памяти и установки setuid через `fchmod`. Обычные потоки
  и сокеты AF_UNIX, AF_INET, AF_INET6 и AF_NETLINK работают.
  [Документация setpriv 2.41](https://raw.githubusercontent.com/util-linux/util-linux/v2.41/sys-utils/setpriv.1.adoc)
  Для OpenRC и runit есть отдельные сценарии служб и сборка дерева
  пакета с общей политикой D-Bus и polkit. Служба объявляет системный
  TUN через обычный API возможностей, графический клиент использует
  его для допуска подключения. Путь с атрибуцией и каноническими
  ресурсами сохраняет требования systemd. Стенд Debian проверил
  объявления возможностей перед полной сессией на обоих движках.
  Две Debian VM загрузились с `openrc-init` и `runit` в PID 1.
  Установленная служба запустилась под соответствующим менеджером
  и ответила по системному D-Bus. С холодной загрузки helper активировал
  polkit и загрузил TUN. С системным DNS через systemd-resolved оба
  движка прошли полный сетевой цикл. После остановки службы обе cgroup
  опустели, интерфейс TUN был снят, выданные Fake-IP оставались
  в карантине. Проверены обычный DNS до и после сессии и сохранность
  содержимого и метаданных `/etc/resolv.conf`. Правило polkit для
  фонового root-клиента было только в одноразовой VM.
  С resolvconf 1.94 на обеих init-средах DNS менялся через API менеджера
  во время активного TUN. На Xray и sing-box прежний worker останавливался,
  заново выданные Fake A/AAAA отличались, карантин блокировал прежние
  адреса. На обоих DNS-серверах проверены UDP и TCP, а после смены DNS
  проверены HTTPS и DoH. Тест сверял содержимое и метаданные
  `/etc/resolv.conf` между изменениями, которые публиковал resolvconf.
  Отдельный вход PAM/elogind в обеих VM зарегистрировал обычный UID
  на активном локальном `seat0`. Журнал polkit подтвердил локальный
  активный сеанс. Первоначальный отказ без запроса аутентификации
  выдало правило, унаследованное от базового образа VM. После его
  удаления в дочерних образах штатная политика потребовала
  `auth_admin`. Без агента установленный helper отклонил `Prepare`.
  После проверки пароля администратора через `pkttyagent` тот же
  пользователь получил дескриптор подготовки на OpenRC и runit.
  На x86-64 с обычным ядром Debian 6.12.117, LightDM 1.32 и Xfce 4.20
  через X11 графический сеанс на обоих менеджерах служб прошёл
  аутентификацию через `mate-polkit`. Сеансовую шину в стенде запускает
  `dbus-run-session`. Проверены локальный активный `seat0`, запрос
  пароля по штатной политике и дескриптор `Prepare` у обычного UID.
  [Пакет helper для OpenRC и runit](../../../packaging/standalone/README.md)
  На Debian 13.7 с ядром AArch64 6.12.117 отдельная проверка заголовков
  Linux подтвердила размер `ifreq`, выравнивание, смещение флагов и
  номера трёх вызовов ioctl TUN. Сборка использовала `rustix/linux_raw`.
  В гостевой системе прошли штатное завершение дочернего процесса и
  SIGKILL при выходе создавшего его потока. Установленные службы без
  `test-support` прошли TUN и Fake DNS с явной политикой Proxy на
  Xray и закреплённом адаптере sing-box, который принимает
  `external_configuration`. Проверка профиля v4 с
  подтверждённым фильтром seccomp применяется только на x86-64.
  На AArch64 отдельно собраны и установлены тестовые `.deb` для OpenRC
  и runit. В обоих образах контрольные суммы установленных ELF совпали
  с обычной сборкой для systemd. После загрузки менеджеры запустили
  helper, который поднял TUN и опубликовал возможности на системном
  D-Bus. Оба ядра прошли смену DNS через resolvconf и восстановление.
  На отдельных образах AArch64 с systemd-resolved при штатной остановке
  helper с активным TUN оба worker завершились, их cgroup опустели,
  а TUN исчез. Карантин остался в ядре. После перезапуска службы
  прошли Stop, Unlock и повторная проверка реального DNS. Содержимое и
  метаданные `/etc/resolv.conf` совпали до и после каждого сценария.
  На Fedora Cloud 45 AArch64 официальный образ проверен по
  подписанной сумме. Штатный spec с AArch64 собрал RPM в гостевой
  системе. Установка и `rpm -V` прошли, байты ELF в RPM совпали
  с проверенной GNU-сборкой. В режиме SELinux Enforcing проверены
  полный сетевой цикл, восстановление DNS и карантин с обоими
  движками. На Arch Linux ARM установленный helper с обоими движками
  проверен при штатной ссылке `/etc/resolv.conf` на
  `/run/systemd/resolve/resolv.conf`. Helper использует проверенную
  конфигурацию systemd-resolved, прямые запросы к её адресам обрабатывает
  существующий DNS-релей. Установку проводили в QEMU по раскладке
  системных файлов из дерева пакетирования. Для строгого DoT на
  глобальном и резервном сервере проверены оба DNS-пути в режиме uplink. Прямые
  запросы клиентов к опубликованному адресу на порту 53 проходят через
  TLS-релей. Доменная привязка DNS сохраняется по снимку
  systemd-resolved, в том числе `DefaultRoute` исходных интерфейсов.
  С `YONIK_CHECK_UNTRUSTED_UPLINK_DOT` стенд подставил исходный набор
  корней только в mount namespace helper. Системный резолвер использовал
  тестовый CA. Для обоих движков проверены отказ прямых запросов реального
  DNS к недоверенному DoT и отсутствие перехода на работающий порт 53.
  Отдельный стенд проверяет это с `YONIK_CHECK_UPLINK_SPLIT_PEER`.
  Глобальный сервер в uplink-файле отвечает на `real.test`; сервер
  линка с `~private.test` и `DefaultRoute=no` возвращает свой адрес на
  отдельное имя для каждого движка. Стенд подтверждает TLS на приватном
  сервере и отсутствие синтетического ответа при прямом обращении к
  его порту 53.
  Отдельно на обоих движках проверен переход с opportunistic DoT на
  DNS по TCP и UDP, когда сервер не принимает TLS.
  Установленный нативный Arch-пакет с Qt для AArch64 отдельно проверен
  по строке матрицы для `4a773d87`.
  [Режимы resolv.conf в systemd-resolved](https://www.freedesktop.org/software/systemd/man/261/systemd-resolved.html)
  На Fedora Cloud 45 (ядро 7.2.11, nftables 1.1.6, SELinux enforcing)
  установленный helper загрузился. Системный Prepare вернул
  `Unavailable` до запуска ядра. Политики Fedora 45.23 и 45.24 отклонили
  переход `init_t → iptables_t` при исполнении `nft` с
  `NoNewPrivileges=yes`. Проверка содержимого и метаданных `/etc/resolv.conf`
  прошла.
  Отдельный тестовый домен на Fedora 45.24 выполнил `nft -j -f -` с
  командой `list tables`. Во время исполнения проверены переход в
  `iptables_t` и `NoNewPrivs: 1` обоих процессов.
  Fedora устанавливает общий drop-in `10-timeout-abort.conf`. Пакетные маски
  для двух worker-сервисов возвращают эффективный `TimeoutStopFailureMode=terminate`.
  Supervisor сверяет путь, владельца и цель каждой маски. В Fedora 45 это
  позволило пройти проверку unit-контракта и запустить проверочное ядро.
  Модуль из [каталога Fedora](../../../packaging/fedora/README.md) разделяет
  домены помощника и worker. На Fedora Cloud 45 установленная обычная сборка
  прошла системный DNS, TCP/UDP IPv4 и IPv6, HTTPS, DoH, Stop и Unlock с
  Xray и sing-box. Также проверены удаление модуля, восстановление
  контекстов, повторная загрузка и запуск помощника с `NoNewPrivs: 1`.
  `/etc/resolv.conf` сохранил содержимое и метаданные. При переключении с
  Xray на sing-box зафиксирован `Stale` до выдачи дескриптора Prepare. В
  контрольном прогоне клиент один раз повторил Prepare с новым снимком
  сети, после чего прошли Apply и проверка обоих движков.
- [x] Проверить транзакции RPM системного помощника в Fedora Cloud 45.
  Установлены пакетные systemd units, маски worker и SELinux-модуль.
  Xray и sing-box прошли до и после обновления при остановленном helper.
  Тест от root подтвердил отказ удаления при активном TUN. После Stop
  и Unlock RPM и модуль удалились, элементы карантина истекли в nftables
  при остановленном helper. `/etc/resolv.conf` сохранил содержимое и
  метаданные.
  На AArch64 повторён сценарий с ревизиями `0.1.0-1.fc45` и
  `0.1.0-2.fc45`. После отказа `rpm -e` активный Xray TUN сохранился.
  После обновления прошли `rpm -V`, проверка домена `yonik_helper_t`
  и `NoNewPrivs=1`, затем сетевой прогон на обоих движках. При
  удалении helper остановился с IPv4- и IPv6-элементами карантина в
  nftables. Их максимальный оставшийся TTL перед удалением составлял
  82 с, а через 82,7 с стенд увидел пустые наборы. RPM, helper, worker
  и SELinux-модуль удалились. SELinux остался в режиме Enforcing,
  содержимое и метаданные `/etc/resolv.conf` совпали до и после.
- [x] Проверить установленный RPM из обычной сессии Fedora GNOME Wayland.
  На базе Fedora Cloud 45 с GNOME Shell 51.1 и SELinux Enforcing клиент
  выполнил Prepare, Apply и Stop на обоих движках со штатной аутентификацией
  через GNOME Shell. В Xray-сессии подтверждён и Unlock после kill switch.
  Проверены системный Fake DNS, IPv4/IPv6 TCP/UDP, HTTPS и DoH, затем удаление
  RPM после пользовательской сессии. Ранний отказ polkit оказался наследием
  предыдущего теста, где локальное правило разрешало операции только root
  и выделенному тестовому пользователю. В контрольном прогоне использовалась
  пакетная политика polkit без этого правила. Клиент вызвал системный D-Bus
  напрямую.
- [x] Проверить Qt-клиент на Fedora Workstation 45 в GNOME Wayland.
  Система установлена на диск KVM из официального ISO с проверенной подписью
  контрольной суммы. Qt-клиент из `fc846c00` собран в Fedora 45 и запущен
  с Qt 6.11.2 в активной сессии обычного UID. RPM helper и worker установлен
  штатно, SHA-256 установленных ELF сверены с артефактами сборки.
  На каждом движке ожидаемый диалог GNOME polkit появился для Prepare, Apply,
  Stop и Unlock. Кнопка подключения подняла TUN. Независимый клиент прошёл
  Fake A/AAAA, TCP и UDP по IPv4 и IPv6, HTTPS с проверкой сертификата и DoH.
  После Stop и Unlock worker завершился, TUN исчез и вернулся обычный DNS.
  Затем удалены RPM и его SELinux-модуль. SELinux остался Enforcing.
  Содержимое, цель ссылки и метаданные `/etc/resolv.conf` совпали.
  [Официальный образ Fedora Workstation](https://fedoraproject.org/workstation/download/)
- [x] Проверить реакцию установленного helper на смену интерфейса транспорта
  и на отзыв DNS-зоны в Debian 13.7 и Ubuntu 24.04.5 LTS без графической
  сессии. В первом сценарии маршрут к VLESS-серверу переключается с
  `yonik-outer` на второй veth `yonik-alt` с локальным адресом
  `10.203.2.1/30` и адресом сервера `10.203.2.2/30`. Журнал сервера подтверждает
  новую точку выхода. Во втором сценарии стенд вызывает `RevertLink` у
  systemd-resolved только для TUN. Оба движка останавливаются без вызова
  Stop и снимают DNS-зону. Проверены сохранение kill switch на Xray и
  автоматическое восстановление обычной сети на sing-box. Повторный
  Prepare/Apply в пределах 30 секунд выдаёт другие Fake A/AAAA. Старые IP
  блокируются и на физическом выходе, и в новой сессии. TCP/UDP, HTTPS и DoH
  проходят после переподключения. Содержимое и метаданные
  `/etc/resolv.conf` совпали до и после четырёх прогонов.
  Тесты `production_helper_fake_dns_after_route_switch` и
  `production_helper_fake_dns_after_resolver_revert` используют штатный
  установленный helper и системную D-Bus шину.
- [x] Проверить смену файлового DNS в Debian 13.7 с `resolvconf` 1.94.
  Helper наблюдает за каталогами `/etc/resolv.conf` и поддерживаемого
  файла DNS-менеджера, поэтому замечает атомарную замену и перечитывает
  снимок перед продолжением DNS-обслуживания. После `resolvconf -a` оба
  движка останавливаются без Stop в пределах 10 секунд. После повторного
  Prepare/Apply старые Fake-IP блокируются, выдаются новые Fake A/AAAA,
  а новый реальный резолвер отвечает по UDP и TCP. Ни один из исходных
  резолверов не получил запросов к тестовому домену Fake DNS. Стенд
  также проверил HTTPS и DoH. Содержимое и метаданные `/etc/resolv.conf`
  сверены до и после действий Yonik, отдельно от обновления менеджером.
- [x] Проверить сохранность внешнего WireGuard при обоих порядках запуска
  в Debian 13.7 и Ubuntu 24.04.5 LTS. Появление WireGuard во время сессии
  привело к автоматической остановке Xray и sing-box и снятию зоны Fake DNS.
  Новая сессия с уже работающим WireGuard выдала другие Fake A/AAAA.
  Публичный путь прошёл TCP/UDP, HTTPS и DoH. После Stop и Unlock состояние
  интерфейса, маршрутов, конечной точки и AllowedIPs WireGuard совпало с
  исходным. Тестовый TCP/UDP по IPv4/IPv6 прошёл через WireGuard до и после
  новой сессии. При конфликте его маршрута с пулом Fake-IP Prepare отклонён
  с сохранением маршрута. `/etc/resolv.conf` сохранил содержимое и метаданные.
  Сценарий `production_helper_fake_dns_preserves_external_wireguard` запускает
  [стенд WireGuard](../../../tools/fixtures/wireguard_vm.py) из
  `/opt/yonik-gate/tools/fixtures` и использует `wg` в `/opt/yonik-gate/wg`.
  Передача приватного трафика через WireGuard во время активной сессии
  Yonik и приватный split DNS остаются в общей проверке VPN/G-DNS.
  На Arch Linux ARM обе последовательности запуска проверены с ядром
  7.3.5 и подписанным пакетом wireguard-tools 1.0.20260223. На обоих
  движках наблюдатель завершил старую сессию после появления WireGuard,
  затем прошли новые Fake A/AAAA, TCP/UDP, HTTPS и DoH. Чтение состояния
  WireGuard подтвердило совпадение интерфейса, маршрутов, endpoint и
  AllowedIPs, включая отказ Prepare при пересечении с пулом Fake-IP.
  На Fedora Cloud 45 x86-64 с ядром 7.2.11, NetworkManager 1.58.1,
  systemd-resolved и SELinux Enforcing тот же сценарий прошёл с
  установленным RPM `0.1.0-911.fc45`. На обоих движках появление
  WireGuard остановило старую сессию, а новая сессия при уже работающем
  WireGuard выдала свежие Fake A/AAAA и прошла TCP/UDP, HTTPS и DoH.
  После Stop трафик WireGuard прошёл по прежним маршрутам, настройки
  интерфейса совпали, а пересечение с пулом Fake-IP отклонено.
  `rpm -V` прошёл, SHA-256 установленных ELF сверены. Содержимое,
  метаданные и цель ссылки `/etc/resolv.conf` совпали до и после.
  На Arch Linux x86-64 с нативным пакетом `c8e016b6` оба порядка
  запуска также прошли с Xray и sing-box. Появление WireGuard отозвало
  DNS и остановило старый worker. При переподключении через Yonik
  проверены новые Fake A/AAAA, TCP/UDP, HTTPS и DoH. После Stop трафик
  WireGuard остался доступен по исходным маршрутам. Пересечение маршрута
  с пулом Fake-IP отклонено. Установленные ELF сверены с архивом, а
  ссылка, метаданные и содержимое `/etc/resolv.conf` совпали.
- [x] Закрыть выход обнаруженных префиксов WireGuard через VLESS во время
  системной сессии Fake DNS. До исправления в Debian 13.7 сервер VLESS
  получил тестовые приватные TCP/UDP IPv4/IPv6 и TCP к DNS-серверу WireGuard.
  Helper берёт маршруты с ненулевой длиной префикса из снимка топологии и
  ставит запреты перед общим разрешением TUN. На Xray и sing-box при
  выключенном kill switch публичные Fake A/AAAA и TCP/UDP продолжили
  работать. В журнале VLESS отсутствовали подключения к контрольным адресам
  WireGuard. Системный DNS обычного UID и приватные TCP/UDP прошли через
  WireGuard до запуска и после Stop. Содержимое и метаданные
  `/etc/resolv.conf` совпали до и после. Этот режим защищает обнаруженные
  назначения, а доступ к ним во время сессии требует отдельной подтверждённой
  привязки маршрута и транспорта WireGuard.
  На Arch Linux ARM повторены блокировка приватных IPv4/IPv6 и split DNS
  во время Fake DNS и возврат доступа после Stop. На каждом движке журнал
  VLESS зафиксировал публичные контрольные соединения, а DNS-сервер
  WireGuard подтвердил ответы до запуска и после Stop.
- Одновременный доступ к приватным сетям и split DNS через локальный
  WireGuard отложен по решению пользователя. В этой ветке во время Fake DNS
  действует блокировка приватных зон и назначений. Стенд с отдельной
  таблицей TUN в Debian 13.7
  (ядро 6.12.117, внешний UDP/IPv4) и Ubuntu 24.04.5 LTS (ядро 6.8.0-147,
  внешний UDP/IPv6) подтвердил маршруты `throw` к приватным префиксам и к
  адресу внешнего peer. Остальные адреса по-прежнему выбирали TUN. С
  точным правилом для исходного и целевого адресов, UDP-портов, метки и
  выходного интерфейса прошли приватный NSS и TCP/UDP IPv4/IPv6. При замене
  приватного маршрута на другой интерфейс nftables заблокировал пакет.
  Попытка отличить транспорт WireGuard по отсутствию `skuid` заблокировала
  и настоящий трафик WireGuard на обоих ядрах. После смены порта обычный
  UDP-сокет с правом выставить ту же метку совпал со старым правилом.
  При `fwmark=0` после освобождения порта то же исключение сработало для
  сокета обычного UID. Стенд также поместил точную связку с ненулевой меткой
  в набор nftables с таймером. Спустя три секунды после установки срока в
  две секунды ядро заблокировало совпадающий пакет без участия процесса
  проверки. Такой срок ограничивает время действия устаревшей записи.
  Снимок WireGuard через Generic Netlink читает текущие порт, `fwmark`,
  адреса peer и AllowedIPs по ifindex. На Debian 13.7 и Ubuntu 24.04.5 LTS
  подтверждены смена UDP-порта, обнуление `fwmark`, переключение endpoint
  с IPv4 на IPv6, сборка 2048 IPv6-префиксов из нескольких сообщений и отказ
  после удаления интерфейса. Ключи из ответа не включаются в снимок, буфер
  ответа очищается при завершении чтения. На тех же ядрах снимок маршрута
  связал исходный и целевой адреса, UDP-порты, `fwmark` и выходной L3-интерфейс
  для IPv4 и IPv6. На IPv4 правило RPDB с селекторами метки и портов перенесло
  путь на другой интерфейс и отозвало предыдущее наблюдение. Смена порта и
  endpoint, отмена сессии и истечение двухсекундного срока также закрыли
  доступ к старому снимку. При `fwmark=0` снимок отклонён. Содержимое и
  метаданные `/etc/resolv.conf` совпали до и после прогона. Снимок описывает
  FIB текущего namespace. [Стенд UDP-сокетов](../../../tools/fixtures/wireguard_socket_namespace.sh)
  подтвердил на тех же ядрах, что после переноса интерфейса сокеты IPv4 и
  IPv6 открываются заново с другими cookie в исходном namespace. В целевом
  namespace VXLAN может занять тот же UDP-порт. Удаление WireGuard закрывает
  его сокеты и сохраняет сокеты VXLAN. Номер порта и поля RTM_GETLINK сами
  по себе не связывают интерфейс с сокетом.
  В лабораторной проверке Netfilter BPF в `LOCAL_OUT` прочитал cookie
  фактического сокета через `nf_hook_state.sk`. Cookie совпал с SOCK_DIAG
  для UDP/IPv4 на Debian и UDP/IPv6 на Ubuntu. Контрольный UDP-сокет после
  смены порта WireGuard использовал прежнюю связку адресов, портов и метки,
  но дал другой cookie. Затем стенд закрепил ссылки фильтра в bpffs.
  После выхода загрузчика TCP/UDP через настоящий WireGuard продолжили
  работать, а контрольная отправка получила `EPERM`. Содержимое и
  метаданные `/etc/resolv.conf` совпали до и после проверок.
  На Debian 6.12.117 и Ubuntu 6.8.0-147 отдельная проба сняла cookie обоих
  сокетов после поиска конкретного интерфейса через `WG_CMD_GET_DEVICE`.
  Cookie совпали с SOCK_DIAG до переноса интерфейса, после переноса при том же
  порте VXLAN в целевом namespace и после смены порта WireGuard. Подготовка
  пробы через SOCK_DIAG заранее назначала cookie. Этот снимок годится для
  диагностики. В `wg_get_device_start` удерживается ссылка на устройство,
  а при одновременной смене порта отдельные поля сокетов могут попасть в
  снимок из разных поколений. Для выдачи допуска требуется согласованный
  снимок конкретного запроса и сверка namespace интерфейса и сокетов.
  [Чтение устройства WireGuard](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/netlink.c#L199-L309) · [Замена сокетов](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/socket.c#L419-L436)

  На Debian 6.12.117 и Ubuntu 6.8.0-147 лабораторная проба сняла cookie
  и сетевые пространства обоих сокетов непосредственно перед освобождением
  `device_update_lock` внутри `wg_get_device_dump` при удерживаемом RTNL.
  Проба сверяет поколение устройства с поколением dump и порт каждого
  сокета с портом устройства. До переноса интерфейса, после переноса при
  совпадающем порте VXLAN и после смены порта оба cookie совпали с SOCK_DIAG
  в исходном сетевом пространстве. При одновременной смене порта 25 из
  30 запросов в Debian и 30 из 30 в Ubuntu дали пару, согласованную
  с портом из ответа WireGuard. Остальные пять запросов не дали готовую
  пару cookie. После отключения интерфейса проба отклонила снимок на обоих
  ядрах. Содержимое и метаданные `/etc/resolv.conf` совпали до и после.
  В Fedora Cloud 45 с ядром 7.2.11-300.fc45.x86_64 и SELinux Enforcing
  тот же обработчик опубликован в BTF под именем `wg_get_device_dumpit`.
  Повтор с выбором этой точки прошёл в исходном сетевом пространстве:
  25 из 30 конкурентных запросов дали согласованный снимок, отключённый
  интерфейс отклонён. Перенос интерфейса в другое пространство на Fedora
  этим стендом не подтверждён.
  В лабораторном прогоне на Debian 6.12.117 и Ubuntu 6.8.0-147 код
  `read_wireguard_device` связал наблюдение сокетов с проверенным
  multipart-ответом. Порт netlink из `NETLINK_CB`, номер запроса,
  ifindex и пространство интерфейса совпали с результатом чтения.
  Каждый из трёх фрагментов ответа на 2048 AllowedIPs наблюдал одинаковые
  cookie и поколение. Перенос интерфейса и смена UDP-порта подтверждены
  отдельными запросами. При изменении fwmark после первого фрагмента
  тот же читатель вернул `Interrupted`. Снимок из прерванного ответа
  отброшен. Содержимое и метаданные `/etc/resolv.conf` совпали до и после.
  Отдельный прогон под systemd с `CAP_NET_ADMIN` и
  `NoNewPrivileges=yes` получил `EPERM` при пробной загрузке BPF на обоих
  ядрах. Установленный helper работает с этими ограничениями.
  На Debian 6.12.117 и Fedora 45 с ядром 7.2.11, оба x86-64, отдельная
  лабораторная служба systemd с `NoNewPrivileges=yes` подключила пробу
  через `kprobe.multi` с `CAP_BPF` и `CAP_PERFMON`. Для чтения WireGuard
  через Netlink добавили `CAP_NET_ADMIN`. Номер и порт запроса, ifindex
  и cookie сокетов IPv4 и IPv6 совпали в однофрагментном ответе.
  Повтор с теми же тремя capabilities проверил 2048 AllowedIPs в трёх
  фрагментах на Debian и Fedora, включая смену UDP-порта. В Debian
  также подтверждён перенос интерфейса в другое сетевое пространство
  с сохранением исходного пространства сокетов. В Fedora SELinux
  оставался в Enforcing, прогон прошёл в исходном сетевом пространстве.
  Домен установленного helper и ARM64 этой пробой ещё не проверены.
  Содержимое и метаданные `/etc/resolv.conf` совпали до и после.
  Для рабочего допуска ещё требуются загрузчик в рамках пакетной политики,
  проверка фактического UDP-выхода и отзыв разрешения в ядре.
  [Блокировки чтения WireGuard](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/netlink.c#L195-L275)

  На тех же ядрах прогоны QEMU проверили шестисекундный допуск фактического
  сокета по `CLOCK_BOOTTIME` в Netfilter BPF. До S3 прошёл контрольный
  обмен через WireGuard, после пробуждения фильтр отбросил пакет с тем же
  cookie по истёкшему сроку. Монотонные часы при первой проверке после
  пробуждения ещё оставались внутри исходного окна. Debian проверен с
  внешним UDP/IPv4, Ubuntu с UDP/IPv6. Содержимое и метаданные
  `/etc/resolv.conf` совпали до и после. Фильтр проверял срок на пакете без
  обновления карты после сна. Для интеграции в helper ещё нужны сверка
  фактического выхода с сохранённым исходным адресом и безопасный отзыв
  допуска при смене сокета, маршрута или остановке helper.
  [WireGuard UDP в Linux](https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireguard/socket.c#L342-L412) · [Netfilter BPF](https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nf_bpf_link.c) · [Часы ядра Linux](https://docs.kernel.org/core-api/timekeeping.html)

  [Стенд фильтра WireGuard](../../../tools/fixtures/wireguard_packet_gate.sh)
  на том же Debian с UDP/IPv4 и Ubuntu с UDP/IPv6 объединил проверку
  cookie сокета, обоих IP и UDP-портов, метки, выходного ifindex и срока
  `CLOCK_BOOTTIME` в хук `LOCAL_OUT`. Стенд загрузил его из службы с
  `NoNewPrivileges=yes` и только `CAP_NET_ADMIN`, `CAP_BPF` и
  `CAP_PERFMON`. После выхода загрузчика прошли приватные TCP/UDP и
  системное разрешение внутреннего имени через WireGuard. Удаление
  допуска заблокировало трафик и DNS. Смена маршрута на другой интерфейс
  и замена UDP-сокета отвергли прежний допуск. После публикации нового
  допуска связь восстановилась. Срок истёк в ядре без участия
  загрузчика. `/etc/resolv.conf` сохранил содержимое и метаданные.
  Хук проверял пакеты с выделенной меткой до возможной последующей
  трансляции. Интеграции в helper ещё нужны основной запрет обхода при
  смене метки, согласованная публикация и отзыв с учётом поколения
  сессии и пакетная политика службы.
  Прогон со сменой шлюза на том же интерфейсе использует фактический
  следующий узел из маршрута, прикреплённого к пакету в `LOCAL_OUT`.
  В Debian с UDP/IPv4 и Ubuntu с UDP/IPv6 проверены оба шлюза на одном
  интерфейсе с теми же адресами, UDP-портами, меткой и cookie. Старый допуск
  отвергнут при смене, новый восстановил TCP/UDP, затем восстановился
  прямой маршрут. Контроль на прежнем фильтре пропустил смену шлюза.
  В обоих итоговых прогонах загрузка прошла с теми же ограниченными
  capabilities, содержимое и метаданные `/etc/resolv.conf` совпали.
  Маршрут после `LOCAL_OUT` проверяется отдельно при интеграции с firewall.
  [Выбор IPv4 next hop в Linux](https://github.com/torvalds/linux/blob/v6.8/include/net/route.h#L349-L363) · [Выбор IPv6 next hop в Linux](https://github.com/torvalds/linux/blob/v6.8/include/net/ip6_route.h#L268-L277)

  На обоих ядрах стенд проверил отзыв сеанса по поколению. В ключ допуска
  входит поколение, а ядро перепроверяет активное поколение перед
  разрешением пакета. Состояние сеанса читается и обновляется в одном
  слоте BPF под spin lock. После завершённого Stop запоздавшая запись
  с продлённым TTL не восстановила связь. После старта нового поколения
  трафик прошёл только после его собственного допуска. Поздние запись,
  отзыв и Stop прежнего поколения на него не повлияли. Прежний фильтр
  пропустил тот же сценарий после запоздавшей записи. Содержимое и
  метаданные `/etc/resolv.conf` совпали.

  Допуски публикуются одним снимком. Издатель заполняет и замораживает
  внутреннюю BPF-карту, затем подменяет ссылку на неё под блокировкой.
  Каждая команда проверяет ожидаемые поколение и ревизию. В Debian и
  Ubuntu пройдены 70 замен полного снимка, отклонение дубликата с
  сохранением прежнего снимка, блокировка без снимка и снятие ссылки при
  Stop. В том же поколении поздние `replace` и `allow` со старой
  ревизией не восстановили отозванный маршрут. Базовый прогон без проверки
  ревизии восстановил трафик. Содержимое и метаданные `/etc/resolv.conf`
  совпали. В Debian отдельная служба опубликовала полный снимок с теми же
  тремя capabilities, что и загрузчик. Для установленного helper нужен
  издатель полного снимка из подтверждённых маршрутов. Команды частичного
  обновления стенда открывают предыдущую карту по ID, что на Linux 6.8
  требует `CAP_SYS_ADMIN`. [Вложенные BPF-карты](https://docs.kernel.org/6.8/bpf/map_of_maps.html) · [Открытие карты по ID](https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/syscall.c#L3988-L4000)

  Снимок UDP-маршрута проверяет срок по `CLOCK_BOOTTIME`. Монотонная граница
  сохраняется для тайм-аутов Netlink. Синтетический регрессионный тест
  подтвердил отзыв при истечении срока во время сна. На Debian 6.12.117 и
  Ubuntu 6.8.0-147 повторена проверка реального маршрута, смены RPDB и
  endpoint и отзыва снимка.

  Rust сверяет принадлежность UDP-сокетов и поколение устройства в двух
  чтениях WireGuard вокруг проверки маршрута. Из снимка с подтверждёнными
  сокетами формируются записи точного допуска и абсолютного срока.
  Стендовый издатель принимает полный двоичный снимок и перепроверяет срок
  перед заменой карты. На Debian 6.12.117 и Ubuntu 6.8.0-147 ядро
  пропустило WireGuard через такой снимок и блокировало пакет после срока.
  Неполная запись, просроченная запись и старая ревизия оставили прежнюю
  карту. На Debian отдельно проверены два реальных чтения WireGuard с
  BPF-наблюдателем и публикация из Rust в фильтр для внешнего IPv4 и IPv6.
  После истечения срока ядро блокировало пакеты в обоих прогонах.

  В сценарии совместной работы с nftables транспорт отбирают по списку
  сокетов и конечных точек. Эти карты замораживаются до установки фильтра
  и действуют после отзыва разрешения. Проверка проходит в конце OUTPUT
  и в POST_ROUTING перед штатным SNAT. На Debian 6.12.117 и Ubuntu
  6.8.0-147 правило nftables с приоритетом `2147483647` меняло метку уже
  после первой проверки. POST_ROUTING блокировал пакет даже с живым
  разрешением. При корректной метке и действующем разрешении обмен прошёл.
  Смена шлюза на том же интерфейсе, истечение срока и Stop отзывали допуск.
  Сторонний сокет с той же меткой продолжал работать. Содержимое и метаданные
  `/etc/resolv.conf` совпали.
  [Путь IPv4](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/ip_output.c#L429-L443) · [Путь IPv6](https://github.com/torvalds/linux/blob/v6.12/net/ipv6/ip6_output.c#L222-L243)

  Подтверждение приватного DNS ограничено исходным сроком по монотонным
  часам и `CLOCK_BOOTTIME`. Проверка топологии и обоих транспортов
  расходует этот срок. Смена поколения, закрытие наблюдателя и отмена
  проверки отзывают общее подтверждение маршрута. Реальный стенд с
  WireGuard проверяет смену RPDB и потерю источника наблюдения.
  Обмен проверяет зону запроса и удаляет данные опций EDNS, сохраняя
  заголовок OPT и флаг DO. Namespace проверяется перед созданием сокета,
  UID сверяется у созданного сокета. UDP и TCP привязываются к индексу
  интерфейса перед соединением. Исходный срок проверяется перед
  продолжением асинхронной отправки и перед выдачей ответа.
  В CachyOS, Debian 13 и Ubuntu 24.04 стенд подтвердил UDP и TCP через
  WireGuard поверх IPv4 и IPv6, отклонение запроса вне зоны и отзыв
  запроса в полёте при закрытии наблюдателя. Содержимое и метаданные
  `/etc/resolv.conf` совпали.
  [Привязка сокета к индексу в ядре Linux](https://github.com/torvalds/linux/blob/v6.12/net/core/sock.c#L1509-L1511)

  Установленный helper распознаёт конкретные зоны WireGuard из снимка
  systemd-resolved и отдаёт им приоритет над Fake DNS. Публикация TUN
  сохраняет публичный родительский суффикс и исключает приватные зоны
  и их потомков. Оба входа helper проверяют зону перед выдачей Fake-IP
  или пересылкой запроса к обычному резолверу. На Debian и Ubuntu с Xray
  и sing-box проверены публичный ответ, отказ для приватного имени при
  прямом TCP/UDP-запросе к DNS-адресу TUN и восстановление доступа к
  WireGuard после Stop. Состояние `/etc/resolv.conf` совпало.
  Авторизованный Apply сохраняет обнаруженные зоны в защищённом
  хранилище `/var/lib/yonik`. Журнал сетевых ресурсов и карантин Fake-IP
  остаются в `/run/yonik`. При обновлении helper объединяет прежние зоны
  всех UID из журнала текущей загрузки с постоянными и записывает результат
  атомарно. Повторный Prepare
  включает сохранённые зоны текущего UID, в том числе при смене движка
  или сервера. Состояние сохраняется после Stop, перезапуска helper и
  перезагрузки ОС. Ошибка чтения или записи закрывает запуск Fake DNS.
  На Debian и Ubuntu с Xray и sing-box после удаления WireGuard и
  перезапуска helper новый Prepare сохранил отказ для приватной зоны
  по UDP и TCP, а публичный Fake DNS восстановился после карантина.
  Предыдущий helper не прошёл проверку публикации зон TUN после того же
  перезапуска. Во всех успешных прогонах `/etc/resolv.conf` совпал.
  После смены boot ID проверка без тестового интерфейса прошла на Debian
  после миграции и на Ubuntu после записи в новый каталог.
  Оба движка получили Fake-IP для публичного имени и отклонили запросы
  приватной зоны по UDP и TCP. Прежняя сборка на Debian снова опубликовала
  приватную зону. Fedora RPM в SELinux Enforcing подтвердил перенос зоны
  реальным helper, режимы `0700` и `0600`, исправление метки при
  переустановке и сохранение данных при удалении пакета.
  При известных зонах WireGuard глобальный строгий DoT можно обслужить
  через существующее реле на собственном TUN. Реле проверяет имя до
  открытия TLS к публичному DNS и сохраняет проверку сертификата и имени
  сервера. Для стабильного UID systemd-resolved nftables разрешает
  только точные DNS-входы на TUN и ответы локальным клиентам. Маршрут `~.`
  собственного TUN ведёт имена без более точной зоны к реле. На Debian
  с зоной из журнала и Ubuntu с зоной активного WireGuard оба движка
  получили публичный ответ через TLS и Fake-IP для выбранного домена.
  Сокеты с UID systemd-resolved не подключились к настроенному DoT и
  отдельному DoT-адресу, отсутствовавшему в снимке Prepare. Публичный
  TLS-сервер не получил приватных имён. После Stop повторное и новое
  имя снова разрешились через исходный DoT. Ссылка и содержимое
  `/etc/resolv.conf` совпали. Конфигурации, требующие прямого DoT на другом
  интерфейсе при известных приватных зонах, возвращают `Unsupported`.
  Вариант D-06 с одновременным доступом к приватным DNS-серверам через
  локальный WireGuard отложен.
  [Маршрутизация DNS по суффиксам](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html#Protocols%20and%20Routing)

  Сетевой план уже умеет журналировать собственные
  IPv4/IPv6 `throw` и сверять их с опорными маршрутами своей таблицы. На тех
  же ядрах отдельный тест исполнил реальный RTNETLINK и путь восстановления
  helper с переоткрытым журналом. Правила RPDB снялись до удаления `throw`.
  При чужой записи таблица осталась неизменной. При потере опорного маршрута
  сохранились `throw` и его запись в журнале до восстановления опоры.
  Прогон использовал отдельный TUN и правила стенда. Установленный helper
  пока сохраняет блокировку приватных назначений во время Fake DNS.
  [WireGuard Generic Netlink в Linux](https://docs.kernel.org/netlink/specs/wireguard.html)
- [ ] Для каждой принятой конфигурации проверить два порядка запуска
  стороннего VPN, сон/пробуждение, смену Wi-Fi, потерю DNS, падение ядра,
  повторное подключение, Stop и удаление пакета. Фиксировать точный состав
  конфигурации и результат, включая явную причину отсутствия поддержки.
