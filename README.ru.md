# yonik

<img src="crates/yonik-desktop/assets/yonik.svg" alt="yonik" width="112" height="112">

[English](README.md) · [Русский](README.ru.md) · [GitHub](https://github.com/MYRSGRAL/yonik)

[Руководство пользователя Linux](docs/user/linux-ru.md).

[План завершения и текущая готовность](docs/PLAN.md).

Нативный прокси-клиент с открытым исходным кодом. Сначала Linux
(CachyOS/Arch, KDE Plasma, Wayland), затем Android. Запланированы Xray-core и
sing-box, TUN, Fake DNS, подписки, маршрутизация по приложениям и работа в трее.

**Ранняя разработка:** в репозитории есть спецификации, переносимые
Rust-библиотеки, CLI и изолированные тесты ядер, а также первый нативный Linux GUI.
GUI управляет подписками и локальными SOCKS-сессиями; TUN, системная сетевая
интеграция и установщик ещё не реализованы.

### Что реализовано

- Проверка и сопоставление канонических IPv4/IPv6-подсетей.
- Порядок решений: защищённые приватные VPN-сети → обнаруженная LAN → личные
  правила → пресеты → действие по умолчанию.
- Условия executable и назначения: И между группами, ИЛИ внутри группы.
- Блокировка приватного назначения при недоступности его VPN-маршрута.
- Проверки lifecycle TUN и реальных TCP/UDP IPv4/IPv6 echo-потоков Xray/sing-box
  в отдельных Linux namespace.
- Нативные executable-правила, включая два разных пути с одинаковым basename.
- Переносимая модель сессии с отклонением устаревших событий и явным cleanup.
- Одноразовый PreparedPlan с привязкой к поколениям окружения и digest конфига.
- Ограниченный URI/Base64 импорт VLESS, VMess, Trojan, Shadowsocks, HTTP CONNECT и SOCKS5.
- Строгая компиляция одного сервера для Xray 26.10.31 и sing-box 1.14.4:
  loopback SOCKS, проверка TLS и явные ошибки неподдерживаемых параметров.
- Linux host `yonik-local`: проверяет immutable snapshot ядра и конфигурацию,
  обслуживает локальный SOCKS, проверяет HTTPS через него и завершает/reap процесс.
- IDNA exact/suffix правила и общая DNS-модель с явным разрешением,
  неоднозначностью, TTL/поколениями и привязкой fake mapping к сессии.
- Нативные доменные или явно IP-only политики proxy/direct/block с приоритетами,
  блокировкой недоступных приватных назначений и авторизованным health listener.
- Staged-обновление подписки с согласием на конкретный отчёт и отклонением
  устаревших результатов; Linux Direct HTTPS-загрузка с проверкой DNS/peer,
  зашифрованные SQLite snapshots и адаптер ключа Secret Service. Это библиотечный
  API; существующий CLI по-прежнему получает профили через stdin.
- Устойчивые identity серверов, зашифрованное избранное, поиск/сортировка страниц,
  дедупликация и выбор по revision из согласованного сохранённого snapshot.
- Optional Qt Quick/CXX-Qt desktop: RU/EN, review подписки, выбор профиля,
  управление локальной сессией, событийный трей и один экземпляр на каталог данных.

Rust-библиотека рассчитывает политику; изолированные стенды дают описанные ниже
ограниченные сетевые доказательства. Полный mixed domain/CIDR DNS/Fake-IP тракт,
планировщик подписок, проверку peer при proxy-загрузке, TUN-интеграцию политики,
helper и редактор маршрутизации ещё предстоит реализовать. Приёмка desktop/трея
на живом KDE Wayland и окончательное визуальное решение остаются открытыми.

`yonik-application` реализует начальный цикл подключения, проверки и остановки.
Host обязан выбрать уникальный controller ID, пока возможны callbacks старого
экземпляра. I/O, recovery, перенастройка и сохранение состояния ещё не
реализованы; состояние reducer само по себе не доказывает исправность сети.
Подготовка проходит через `prepare/apply`; прямое `Event::Validated` удалено.
Доверенный host передаёт свежие поколения и SHA-256 проверенного immutable artifact.
Это не заменяет авторизацию ОС и согласованное применение изменений самим host.

Изолированный native DNS-стенд подтвердил неполный A/AAAA, смену адреса между
route и dial и повторную выдачу Fake-IP до исходного TTL. Поэтому смешанный
DNS/Fake-IP режим остаётся выключенным; G-DNS не объявляется пройденным.
[Evidence и требования адаптера](docs/validation/2026-11-09-native-dns-contracts.md).

Закреплённый sing-box получил экспериментальные DNS provenance и direct TCP/UDP
`pin_resolution`: исходные TTL CNAME/NODATA, метаданные выбранного ответа и
привязку адресов при retry/UDP write. Изолированная матрица прошла 62 сценария;
сетевые/policy epochs, proxy/Xray parity и Fake-IP lifecycle остаются открытыми.
Compiler по-прежнему отклоняет mixed DNS/Fake-IP; desktop engine не заменяется.
[Сборка и ограничения](adapters/sing-box/v1.14.4/README.md),
[проверки resolution pin](docs/validation/2026-11-09-resolution-pin.md).

Для переработки UI выбраны почти чёрная тема, лавандовый акцент и простой экран
подключения. Все настройки уходят в отдельный раздел. Из
[интерактивных вариантов](design/ui-variants.html) выбран А с большой кнопкой по центру.
Нативный Qt-прототип уже
реализует А: карточка сервера, центральная кнопка connect/stop и статус.
Карточка открывает **Серверы**, шестерёнка справа сверху — **Настройки**.
«Назад» возвращает на предыдущий уровень. Дополнительных кнопок, бейджа режима
и сводки подписки на главном экране нет.
Начальный размер окна — 420×760 логических пикселей, минимальный — 380×600.
Шрифты Onest/Unbounded и OFL-лицензии встроены.
Рабочий UI не ждёт системного TUN. [Направление UI](docs/specs/ui-direction.md).
[Контракт главного экрана/backend](docs/specs/ui-backend-contract.md).
[Реализация и проверки нативного А](docs/validation/2026-11-09-ui-a-native.md).

## Разработка

### Нативный Linux GUI

Тесты требуют `dbus-daemon` для отдельной частной шины; системные D-Bus-службы
не изменяются. При обычном запуске недоступные службы явно отображаются в GUI.

Прототип требует Qt 6 Base/Declarative (Quick, Controls, Widgets, Network, DBus и
QML build tools), C++ compiler, системный SQLite и совместимый linker
(`lld`, `gold` или `mold`; CI устанавливает `lld`). CXX-Qt выбирает его вместо
системного GNU ld.bfd. Qt включается optional feature
`gui`; обычные workspace/Android проверки Qt не собирают. CXX-Qt закреплён на
0.10.0 с согласованными версиями ABI CXX/cxx-gen.

```sh
yonik_build=/var/tmp/codex-myrs/transient/yonik-dev
mkdir -p "$yonik_build"
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo build --locked -p yonik-desktop --features gui --release
"$yonik_build/target/release/yonik-desktop" --engine-dir /абсолютный/путь/к/engines
```

Каталог ядер содержит проверенные `xray-26.10.31/xray` и/или
`sing-box-1.14.4/sing-box`; бинарники не включены в поставку. GUI автоматически
выбирает свободный loopback-порт TCP/UDP. Адрес копируется в **Настройки → Подключение**;
`--listen-port PORT` оставлен для диагностического фиксированного порта. Адрес нужно указать в приложении,
которое должно использовать прокси: GUI не включает TUN или системный proxy.

Для запуска из меню установите пользовательский ярлык (без root и терминала при запуске):

```sh
python tools/install_desktop.py --binary /постоянный/путь/yonik-desktop --engine-dir /абсолютный/путь/к/engines
```

Бинарник должен оставаться по указанному пути вне временного build-каталога.
В **Серверы → Добавить** вставьте ссылку: загрузка начинается сразу.
Все подписки и их серверы находятся в разделе **Серверы**. Выбранную подписку
можно обновить, отменить её текущую загрузку, а через **Ещё** — переименовать
или удалить с подтверждением. Элементов управления избранным в текущем GUI нет.
Подтвердите JSON или частичный импорт после просмотра отчёта. Имя и разрешение
локального HTTP-источника находятся в дополнительных параметрах формы.
Вернитесь на главный экран, выберите сервер и нажмите центральную
кнопку. `Limited` означает, что ядро работает,
но HTTPS-проверка не прошла. Данные находятся в `$XDG_DATA_HOME/tofu` либо
`~/.local/share/tofu`; `--data-dir PATH` выбирает приватный каталог.
Имя каталога `tofu` и идентичность Secret Service сохранены
для совместимости с существующими зашифрованными данными. Master key
остаётся в Secret Service. При недоступном ключе plaintext fallback отсутствует.
URL подписок не передаются аргументами командной строки.

Если провайдер требует HWID, включите **ID устройства** в дополнительных
параметрах добавления или в **Серверы → Ещё** выбранной подписки. Опция выключена
по умолчанию. При включении провайдеру отправляется случайный стабильный ID
этой подписки; идентификаторы оборудования не читаются. ID хранится зашифрованно
и сохраняется после отключения опции и перезапуска. Изменение настройки сразу
повторяет загрузку. Лимит устройств показывается отдельной ошибкой; приложение
не создаёт новый ID для обхода лимита. HWID относится к загрузке подписки.

Черновик маршрутизации поддерживает destination `tcp`/`udp` и порты 1–65535
(например `443,8000-8080`, до 16 диапазонов на правило). Это условия назначения,
а не порт локального SOCKS. Включённые transport-условия пока блокируют Connect
как неподдержанные; сохранение не применяет их к трафику. Первое сохранение transport-черновика
требует проверенного актуального зашифрованного backup и переводит БД в format5;
старые readers её отвергают. Перед использованием старого бинарника сохраните
согласованный backup.

В **Настройки → Запуск и обновления** запуск при входе и автоподключение —
независимые опции, обе по умолчанию выключены. Нажмите **Подтвердить текущую цель**
для выбранного сохранённого профиля, ядра, режима и ревизии маршрутизации.
Сохранение не подключает. Изменившаяся цель или недоступный ключ блокируют попытку
при запуске: другой профиль не выбирается, keyring автоматически не разблокируется.
Остановка отменяет ожидающую попытку. Запуск при входе управляет только
пользовательской XDG-записью `autostart/yonik.desktop` с командой
`/usr/bin/yonik-desktop --start-hidden`; установка пункта меню не размещает там
бинарник. Обычный запуск видим; скрытый запуск требует зарегистрированного трея,
иначе окно показывается.

В **О приложении** и заголовке окна отображается идентификатор сборки. При
обновлении завершите прежний экземпляр через меню трея: обычное закрытие окна
может лишь скрыть его, а повторный запуск поднимет уже работающий экземпляр.

Закрытие скрывает окно при доступном трее, иначе запрашивает безопасное завершение.
Выход ждёт очистку сессии; команды трея проходят через тот же controller.
Сейчас доступны connect/disconnect/restore/quit;
редактор маршрутизации сохраняет черновики; применение к сети и полная приёмка
T-01…T-04 ещё впереди. Ядро, язык и безопасные HTTPS-настройки сохраняются;
URL с credentials, query или fragment действуют только в текущем сеансе.
[Проверки GUI и оставшиеся gates](docs/validation/2026-11-09-native-desktop.md).

В **Настройки → Диагностика** можно задать свой HTTPS URL и ожидаемый статус 200–299;
по умолчанию требуется ровно 204. GUI проверяет TLS, не следует редиректам и
использует timeout 5 секунд. Настройка действует на следующий Connect; безопасный URL сохраняется,
а URL с credentials, query или fragment действует только в текущем сеансе; при активном ядре изменение запрещено. URL скрыт по умолчанию и не
передаётся в state/tray/trace. Результат активной проверки показывает HTTP-код и
длительность либо TLS/timeout/transport. Это одиночное HTTPS-измерение, а не
TCP-задержка хоста или непрерывная гарантия доступности интернета.

[Проверки настраиваемого HTTPS endpoint](docs/validation/2026-11-09-configurable-health.md).

В **Настройки → Диагностика** действие **Проверить TCP** измеряет выбранный сервер отдельно от HTTPS.
DNS разрешается один раз, затем выполняются три прямые TCP-пробы к одному
выигравшему IP, порту и IPv6 scope. Сокеты сразу закрываются без аутентификации
и payload. Показано медианное время трёх успешных проб без DNS и ожидания гонки
адресов. При частичном сбое серия останавливается, медианы нет. Общий deadline
всех стадий — пять секунд. Для имён нужен
нативный Varlink API systemd-resolved; IP не требует resolver. Недоступность
resolver показана явно, внешнего DNS fallback нет. QUIC/неизвестный транспорт
получает «не применимо». Отмена останавливает только TCP; Stop/выход отменяют и
эту задачу. Результат привязан к source/profile/revision и времени. Это одна
прошлая серия из трёх проб: обнаруженная смена сети отменяет текущую TCP-проверку и удаляет
старый результат; история пока не сохраняется. Он не подтверждает
proxy-аутентификацию, HTTPS-доступ или пропускную способность.

[TCP-проверки и evidence](docs/validation/2026-11-09-tcp-probe.md),
[серия из трёх проб](docs/validation/2026-11-09-tcp-series.md).

Пакетный Linux API планирует до 10000 TCP-серий с 1–32 слотами активных/готовых
результатов и ограниченным выходным каналом. Отмена, закрытие получателя и Drop
пакета освобождают I/O. Отдельных runtime или задач на каждую цель нет; кнопка
массовой проверки desktop ещё впереди. [Контракт пакета](docs/specs/tcp-batch-contract.md).

Linux наблюдает изменения маршрутов и адресов через netlink, а DNS и сетевых служб —
через системный D-Bus. GUI явно показывает недоступные источники наблюдения.
Результат привязан к поколению сети текущего процесса: поздний ответ старого
поколения не возвращает успешный статус. Смена сети инвалидирует HTTPS-проверку
и оставляет работающее ядро в `Limited`; для новой проверки нужно переподключиться.
Автоматические проверки и переподключения не запускаются. Этот наблюдатель ещё
не реализует атомарный снимок и применение NetworkHost, необходимые для TUN.
[Проверки наблюдения и оставшиеся ограничения](docs/validation/2026-11-09-network-observation.md).

Linux-библиотека также предоставляет ограниченные read-only API `read_topology`
и `lookup_route`: интерфейсы, адреса, маршруты всех таблиц, policy rules, nexthop
objects либо запрос пути к ядру с явными UID/mark/source и TCP/UDP-селекторами.
Неизвестные атрибуты сохраняются как неполнота интерпретации. Эти данные не дают
права Apply, не доказывают достижимость и не включают привязку к приватному VPN.
ResolverHost Apply и привилегированный жизненный цикл сети ещё не реализованы.

Для явной диагностики в build-каталоге из примера выше:

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo build --locked -p yonik-linux --example network_inspect
printf '%s\n' '{"op":"snapshot"}' | flock -s "$yonik_build" "$yonik_build/target/debug/examples/network_inspect"
```

CLI намеренно выводит адреса и селекторы сети; обычный Debug скрывает содержимое.
[Проверки topology/route-get и ограничения](docs/validation/2026-11-09-network-topology.md).

Read-only API ResolverHost `read_resolver_snapshot` и `subscribe_resolver` читают
полную глобальную/per-link DNS-конфигурацию через systemd Varlink. Route-only
домены, nullable-факты и неизвестные поля сохраняются; DNS не перенастраивается.
Dump требует API systemd v259+, поток — v258+ и авторизацию. Диагностический
пример `resolver_inspect` выводит только счётчики и известные режимы:

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo run --locked -p yonik-linux --example resolver_inspect -- snapshot
```

Для явно запрошенного потока используется `watch`; интерактивная авторизация
не запрашивается. На проверенном хосте снимок сообщает `foreign`, подписка —
`PermissionDenied`. Наличие daemon или снимка не доказывает владение системным
DNS, namespace или G-DNS. Наблюдатель GUI выше пока не использует этот поток
и не гарантирует полное покрытие изменений DNS-конфигурации.
[Проверки ResolverHost и ограничения](docs/validation/2026-11-09-resolver-host.md).

Диагностический пример читает профили только из stdin, проверяет одну принятую
запись по индексу и выводит только счётчики/status/durations:
`cargo run --locked -p yonik-linux --example tcp_probe -- 0`.
Подавайте текст через stdin; URL подписки и credentials не передавайте через argv
или логи. SIGINT/SIGTERM отменяют измерение.

### Авторизация сетевого helper

`yonik_linux::helper::PeerAuthorizer` проверяет credentials отправителя и
фиксированное действие polkit, закрепляет root-owned authority и проверяет
sender сырых ответов. После решения повторно сверяет peer и authority,
ограничивает число проверок и отменяет запрос у исходного владельца authority.
`PeerIdentity` — снимок: перед эффектами Prepare/Apply нужна новая авторизация.
Тесты используют private bus и fake authority. Системный сервис не
устанавливается, сеть не меняется. [Контракт авторизации](docs/specs/helper-authorization.md).

`yonik_linux::helper::TrustedRegistry` читает фиксированный системный реестр
с владельцем root и создаёт проверенный по хешу sealed snapshot из того же
проверенного файлового дескриптора. Небезопасные пути, metadata и записи manifest
отклоняются. Пользовательский каталог ядер остаётся отдельным режимом. Компонент
не устанавливает сервис и не применяет сеть. [Контракт реестра](docs/specs/helper-trusted-registry.md).

`PreparedRequests<A>` привязывает проверенный artifact к peer и поколению,
заново проверяет polkit на prepare/claim и выдаёт artifact однократно.
Настоящий `CheckedConfig` предоставляет SHA-256 текущих bytes. Pending-операции,
payload и TTL ограничены; память executable snapshots учитывается общим бюджетом, описанным ниже. [Контракт Prepare/claim](docs/specs/helper-prepared-requests.md).

Общий процессный бюджет учитывает конфигурационные buffers и helper snapshots.
Выданный artifact сохраняет lease; weak-cache реестра разделяет sealed inode,
а при нехватке бюджета освобождаются expired pending из связанных stores.
Учёт не является измерением RSS или завершённым G-POWER.
[Контракт памяти](docs/specs/helper-memory-budget.md).

### Журнал управляемых сетевых ресурсов

`yonik_linux::managed_network` предоставляет ограниченный устойчивый журнал
владения для будущего привилегированного сетевого helper. Он записывает intent
до эффекта, требует явной сверки с ОС после открытия и сохраняет неочищенные
ресурсы. Сессионные ресурсы и публичная блокировка kill switch имеют разный срок
жизни. Хранение использует приватные права, directory FD, exclusive writer lock,
fsync и атомарную замену. В журнале находятся типизированные дескрипторы без
секретов и исполняемых команд. Сам журнал не применяет маршруты, DNS или
firewall и не включает системный TUN. [Проверки и границы](docs/validation/2026-11-09-network-resource-journal.md),
[план helper](docs/superpowers/plans/2026-11-09-linux-network-helper.md).

`managed_network::nft::NftExecutor` создаёт, наблюдает и удаляет собственные
пустые nftables-таблицы. Он закрепляет namespace и доверенный системный `nft`,
проверяет полную метку владения и удаляет по ненулевому kernel handle.
`Journal::mark_cleanup` сохраняет границу cleanup перед асинхронным эффектом.
Вывод, параллелизм и время команд ограничены.
[Контракт исполнителя](docs/specs/helper-nftables-executor.md).

`PublicBlockPolicy` добавляет атомарную блокировку исходящего IPv4/IPv6 с явными
LAN/VPN, TUN и точечными служебными исключениями. Подтверждение требует полного
совпадения правил в ядре; замена политики выполняется одной транзакцией.
Библиотека сохраняет публичную блокировку после очистки сессии и снимает её
явным Unlock. Полная системная сессия, GUI и платформенная
интеграция ещё не завершены. [Контракт](docs/specs/helper-public-block.md).

Journal schema v2 сохраняет desired/previous политику и намерение Unlock в том
же атомарном файле, что и ресурсы. Durable Apply/Unlock и startup recovery
сверяют реальные правила; сохранённые интерфейсные исключения автоматически
не воспроизводятся. Проверены crash-границы и сериализация команд в живом
процессе. Восстановление полной системной сессии ещё предстоит связать.
[Контракт восстановления](docs/specs/helper-policy-recovery.md).

`yonik-helper` предоставляет версионные D-Bus Prepare/Apply/Stop/Unlock/State
для durable публичной блокировки: свежий polkit и startup cgroup fence.
Проверены private-bus и настоящий nft-трафик в изоляции. Packaging сервиса есть,
но он не установлен и не связан с GUI. Системный TUN и live reconcile ещё нужны;
LAN до этого явно unsupported. [Контракт и evidence](docs/specs/helper-service.md).

Типизированный persistent TUN executor записывает intent, проверяет полную
метку владельца и очищает интерфейс по ifindex. Оба закреплённых ядра и
адаптированный sing-box прошли single-queue traffic/lifecycle fixture;
multi-queue не поддержан. Сетевые ресурсы реализованы отдельно;
DNS и service/GUI-сессия ещё не подключены.
[Контракт и evidence владения TUN](docs/specs/helper-owned-tun.md).

Системный compiler сохраняет профиль и авторизованный probe; адресами и
маршрутами владеет helper, policy-режим пока только IP. Xray и pinned адаптер
sing-box с external configuration прошли TUN→VLESS→echo и crash cleanup.
Обычный sing-box для этого режима отклоняется: auto_route=false всё ещё
создаёт IPv6-эффекты.
[Контракт и evidence](docs/specs/helper-tun-configuration.md).
RPDB executor с durable-журналом захватывает непомеченный трафик, а помеченные
сокеты ядра продолжают существующую маршрутизацию. Оба ядра прошли TCP/UDP
IPv4/IPv6 через peer за veth в соседнем namespace с очисткой своих ресурсов.
Service/worker/GUI, live reconcile и DNS gates остаются открыты.
[Контракт RPDB](docs/specs/helper-tun-rpdb.md).
Новый sealed-FD launcher разделяет Check/Run, сохраняет PID при exec и фиксирует
argv/среду ядра. Оба ядра проходят TUN fixture с отдельным ненулевым UID,
только NET_ADMIN и no-new-privileges; тот же профиль проходит Check без capability.
Закреплённые systemd units и supervisor связывают lifecycle с InvocationID и
подтверждённой пустой cgroup. Установленные units, dedicated UID, setsid,
helper crash/recover и TUN traffic обоих ядер прошли
[проверку в одноразовой Arch VM](docs/validation/2026-11-10-installed-worker.md).
Подключение к profile Prepare/Apply и GUI, полная TERM→KILL приёмка ещё нужны. [Контракт worker](docs/specs/helper-worker-runtime.md).

Для системной сессии добавлены закрытый `ServerIntent` и helper-owned сетевой
план: одни дескрипторы используются compiler и TUN executor. Проверены проекция
внешней topology и configure/capture/cleanup в собственных namespaces.
[Контракт и ограничения](docs/specs/helper-session-network.md).
Авторизованный session host, worker/nft orchestration и GUI ещё не связаны;
это не включает системный TUN в установленном приложении.

### Rust-библиотеки и CLI

Rust 1.85+ (edition 2024). Application использует только std, нормализация доменов — IDNA; у импортера
стандартные библиотеки Base64, URL/IDNA и JSON. Linux host использует Tokio,
reqwest/rustls, SHA-256 и безопасные rustix syscalls. Хранилище подписок дополнительно
использует системный SQLite (нужны заголовки `sqlite3`), XChaCha20Poly1305 и Secret Service.
Cargo.lock фиксирует MSRV-совместимые версии.
Сборки размещаются вне checkout. На рабочей машине проекта:

```sh
yonik_build=/var/tmp/codex-myrs/transient/yonik-dev
mkdir -p "$yonik_build"
cargo fmt --all -- --check
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo test --workspace --locked
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo clippy --workspace --all-targets --locked -- -D warnings
```

Для smoke-тестов нужны Linux, Python 3.12+, `ip`, `unshare`, `/dev/net/tun`,
разрешённые непривилегированные user/network namespace и проверенные бинарники:

```sh
python tools/engine_smoke.py xray /абсолютный/путь/к/xray
python tools/engine_smoke.py sing-box /абсолютный/путь/к/sing-box
python tools/engine_traffic.py xray /абсолютный/путь/к/xray
python tools/engine_traffic.py sing-box /абсолютный/путь/к/sing-box
```

Тесты не меняют сеть хоста и системный DNS. Если бинарники размещены в transient,
удерживайте `flock -s` корня task-каталога весь запуск.
[Версии, хэши и результаты](docs/validation/2026-11-09-foundation.md).
Smoke проверяет конфигурацию и lifecycle интерфейса. Traffic suite передаёт
случайную нагрузку через TUN к перенаправленным локальным echo-серверам,
проверяет счётчики интерфейса и отрицательный контроль после остановки.
[Результаты потоковых проверок](docs/validation/2026-11-09-tun-traffic.md).
Полные G-LINUX/G-DNS/G-APP ещё не пройдены: нужны proxy outbounds, DNS,
интеграция приватного VPN и расширенная проверка атрибуции процессов.

Для начальной проверки атрибуции есть отдельный стенд:

```sh
yonik_apps=/var/tmp/codex-myrs/transient/yonik-apps
mkdir -p "$yonik_apps"
flock -s "$yonik_apps" python tools/engine_apps.py xray /абсолютный/путь/к/xray --work-dir "$yonik_apps"
flock -s "$yonik_apps" python tools/engine_apps.py sing-box /абсолютный/путь/к/sing-box --work-dir "$yonik_apps"
```

Он проверяет точные executable-пути последовательных TCP/UDP IPv4/IPv6 потоков
одного UID. Охват desktop-приложений и полный G-APP этим не подтверждаются.
[Результаты executable-проверок](docs/validation/2026-11-09-process-routing.md).

Не коммитьте ссылки подписок, credentials и настоящие конфигурации серверов.
Каталог `local/` исключён из Git для приватных файлов разработки.

### Диагностика offline-импорта

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo run --quiet --locked -p yonik-import < local/subscription.txt
```

На входе тело подписки, не URL загрузки. CLI выводит только счётчики, протоколы,
статические коды ошибок и номера строк. Exit 0 означает получение отчёта, включая
частично ошибочный импорт; профили не активируются.
Лимиты: 8 MiB входа, 32 MiB decoded, 20 000 URI, 64 KiB на URI, глубина JSON 64.
Xray JSON object/array сохраняется для review; VLESS и Shadowsocks outbounds
извлекаются в управляемые профили. Исходные маршруты/DNS/inbounds не исполняются.
Неизвестные параметры блокируют компиляцию, неподдерживаемые протоколы показываются
в отчёте. Прочий JSON остаётся opaque. Загрузчик использует `Happ/1.0 yonik/<version>`
для JSON-совместимости Remnawave; правила провайдера могут переопределить ответ.
Отдельный компилятор проверяет возможности профилей;
host всё ещё обязан выполнить config-check закреплённым ядром до активации. Фатальные ошибки
сохраняют исходные байты в API; обрезанный/сбойный поток помечается неполным.
[Результаты и ограничения импортера](docs/validation/2026-11-09-subscription-import.md).

### Компиляция одного сервера

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo run --quiet --locked -p yonik-engine --bin yonik-compile -- xray --server 0 < local/profile.txt
```

Обычный вывод — метаданные (`compiled_not_checked`), а не результат подключения.
Нужен полный импорт URI без отклонённых записей; индекс `--server` начинается с нуля.
Для другого ядра укажите `sing-box`, для смены порта 10808 — `--listen-port`.
Флаг `--emit-secret-config` явно выводит чувствительный JSON в stdout: передавайте
его только доверенному потребителю, не в логи или публичный issue. Debug типа
`CompiledConfig` скрывает содержимое; JSON доступен через `write_sensitive`.

Поддерживаются шесть импортируемых протоколов, совместимые TCP/WS/gRPC,
XHTTP у Xray, TLS с проверкой сертификата по системным CA, VLESS TCP REALITY и Vision.
Неизвестные/неприменимые параметры, небезопасный TLS, legacy VMess alterId,
плагины и неподдерживаемые транспорты/шифры явно отклоняются. Публичный plaintext
VLESS у Xray запрещён; тесты на приватных IP разрешены. SOCKS поверх TLS и
активация native JSON ещё не реализованы. Listener всегда `127.0.0.1`, outbound
один, прямого fallback нет. Компилятор не включает TUN, правила маршрутизации,
системный прокси или DNS и не запускает ядро.

Синтетические config-check, TCP/UDP IPv4/IPv6 и отрицательные проверки TLS:

```sh
flock -s "$yonik_build" env TMPDIR="$yonik_build" python tools/engine_compile.py "$yonik_build/target/debug/yonik-compile" /абсолютный/путь/к/xray /абсолютный/путь/к/sing-box
```

Нужен `openssl` в дополнение к namespace-инструментам и закреплённые версии ядер.
[Результаты и ограничения компиляторов](docs/validation/2026-11-09-engine-compiler.md).

### Запуск локального SOCKS на Linux

Нужны Linux 6.3+, executable sealed memfd и `/proc`. Закреплённый бинарник ядра
загружается отдельно: сначала проверьте release-архив, затем доверенный хеш бинарника.
`--sha256` относится к извлечённому executable, не к архиву. Для проверенного
Xray Linux amd64, использованного в тестах:

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo run --quiet --locked -p yonik-linux --bin yonik-local -- xray --binary /абсолютный/путь/к/xray --sha256 cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1 --server 0 < local/subscription.txt
```

Host копирует и хеширует ELF regular file в sealed memory snapshot; version,
config-check и start используют одну и ту же неизменяемую копию. Конфигурация
остаётся в памяти и передаётся через stdin. Stdio ядра скрыт для защиты секретов.
Принадлежность listener процессу проверяется до и после проверки HTTPS.
Управляемый ресурс — процесс ядра и его SOCKS на `127.0.0.1:10808`.
Системный прокси, TUN, маршруты и системный DNS не включаются.

Вывод — безопасные NDJSON события. Для `Connected` нужен ожидаемый HTTPS-статус строго через
выбранный SOCKS outbound. Ошибки TLS, timeout и HTTP дают `Limited`; ядро продолжает
обслуживать SOCKS. Прямого fallback и перехода по redirect нет. `--check-url` выбирает
HTTPS endpoint, `--check-status` задаёт ожидаемый статус 200–299 (по умолчанию 204),
`--check-timeout` принимает 1–60 секунд; по умолчанию generate_204 и
10 секунд. Ctrl+C/SIGTERM останавливает и reap ядро. `--once` проверяет и завершает
сессию: exit 0 при успехе/отмене, 2 при отказе endpoint, 1 при ошибке импорта/host.
Автоматического recovery и постоянного supervisor пока нет; SIGKILL host не позволяет
выполнить cleanup. Локальный CLI ещё не является полным production EngineHost.

Частичный импорт по умолчанию отклоняется. После просмотра отчёта `yonik-import`
флаги `--accept-partial --server N` явно выбирают одну распознанную запись и сообщают
число отклонённых; неподдерживаемые параметры выбранной записи не разрешаются.
Native JSON пока не поддерживается. Индексы считаются среди распознанных записей
с нуля. Для sing-box укажите `sing-box` и его проверенный executable/hash.
Ядра не включены в поставку CLI.

Изолированные тесты host (также нужны `rustc`, `openssl`, PID/mount namespaces):

```sh
flock -s "$yonik_build" env TMPDIR="$yonik_build" python tools/engine_host.py "$yonik_build/target/debug/yonik-local" /абсолютный/путь/к/xray /абсолютный/путь/к/sing-box
```

[Результаты и оставшаяся работа](docs/validation/2026-11-09-linux-engine-host.md).

### Библиотека подписок

`yonik-subscription` подготавливает неизменяемый отчёт до согласия на сохранение.
Linux `SubscriptionService` связывает его с `FetchHost` и
`EncryptedSubscriptionRepository`: новая загрузка, отмена и смена источника
инвалидируют старый результат; SQLite сверяет поколение источника и revision
snapshot внутри одной транзакции. Ошибки и пустой импорт сохраняют последний
утверждённый snapshot. `offline()` также сообщает, относится ли он к старому источнику.

URL/имя, тело, метаданные и validators зашифрованы XChaCha20Poly1305 с привязкой
к записи и поколениям. Ключ 32 байта получает `subscription_master_key()` через
Secret Service; в SQLite ключа нет. Для существующей БД нужен `allow_create = false`;
отсутствующий или заблокированный ключ вызывает ошибку. Вызывающий host выбирает
канонический приватный каталог (0700); права БД — 0600. Последний GUI handle
освобождается через `close().await`, чтобы checkpoint SQLite не блокировал UI.

Публичный источник требует HTTPS и публичные DNS/peer-адреса на каждом редиректе.
Локальные HTTP/private источники разрешаются явным исключением. Proxy-загрузка
пока возвращает `UnsupportedPeerVerification`: SOCKS показывает peer прокси,
а контракт требует peer конечного сервера. Перехода на Direct нет. Native JSON
можно сохранить после review; это не разрешает его запуск. Планировщик,
редактор маршрутизации и автоматическое применение
нового snapshot к сессии ещё не реализованы.
[Проверки и ограничения](docs/validation/2026-11-09-subscription-snapshots.md).

Identity включает версионированные параметры соединения и неизвестные опции;
URI fragment и VMess `ps` меняют только имя. Source-scoped HMAC-индекс сохраняет
ID и избранное при переименовании/перестановке. Смена endpoint, credentials или
опции создаёт новый identity; отсутствующие и явные defaults могут различаться
консервативно. Дубликаты объединяются по первой разобранной записи. Пропавшее
избранное хранится как недоступное и восстанавливает ID при возвращении; прочие
пропавшие записи удаляются, их числовые ID не переиспользуются.

`profiles()` возвращает ограниченные страницы поиска/сортировки;
`select_profile(id, revision)` возвращает owned parsed server из того же snapshot,
отклоняя старую страницу вместо использования устаревшего ordinal. Schema v2
транзакционно мигрирует v1 и лениво индексирует прежние snapshots; master key
не меняется. [Проверки identity, миграции и нагрузки](docs/validation/2026-11-09-profile-identities.md).

### Политика маршрутизации

Оба CLI принимают вместе `--policy FILE --policy-mode names|ip-only --probe-port PORT`.
Режим `names` поддерживает exact/suffix домены и действие по умолчанию; сочетания
CIDR/LAN с обязательным DNS отклоняются. `ip-only` поддерживает CIDR/LAN и блокирует
доменные SOCKS-запросы до маршрутизации. Доменное правило не теряется молча.
Атрибуция процесса через локальный SOCKS и привязка доступного приватного VPN пока
не доказаны и дают явную ошибку. Отключённые личные правила/пресеты не влияют на маршрут.

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo run --quiet --locked -p yonik-linux --bin yonik-local -- xray --binary /абсолютный/путь/к/xray --sha256 cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1 --server 0 --policy examples/policy-names.json --policy-mode names --probe-port 10809 < local/subscription.txt
```

[Доменный пример](examples/policy-names.json) и [IP-only пример](examples/policy-ip-only.json)
содержат документационные назначения: замените их своими правилами. Schema version 1:
`default_action`, `user_rules`, `preset_rules`, `lan`, `private_networks`, `private_domains`.
Правило содержит `id`, `action`, необязательные `enabled` и `conditions` с массивами
`domain`, `domain_suffix`, `ip_cidr`, `executable_paths`. Группы executable, домена и CIDR соединены
через И, значения внутри каждой группы — через ИЛИ. Пустая группа означает любое значение. Личные правила идут перед пресетами. Недоступные
приватные сети/зоны блокируются раньше LAN и личных правил. `available: true` не
разрешает использовать VPN: нужна будущая подтверждённая NetworkHost binding.

Лимиты: 2 MiB JSON, 10 000 правил, 100 000 значений селекторов. Неизвестные/повторные
поля, повторные ID в группе, неверные имена/CIDR отклоняются. Политика нормализует
IDNA, регистр и root-dot; нативный SOCKS ingress принимает канонические ASCII/punycode
имена. Raw Unicode/root-dot/невалидные wire-имена блокируются, чтобы не попасть в fallback.

Отдельный health listener требует случайный пароль 256 бит, доступный только host
и чувствительному конфигу. Анонимный доступ для обхода правил закрыт. HTTPS проверяется
через proxy даже при default DIRECT/BLOCK. Известные защищённые адреса/зоны endpoint
отклоняются до запроса. Системные маршруты и DNS не меняются.

Общая модель покрывает решения D-01…D-07. Нативное смешение domain/CIDR всё ещё
заблокировано gate: воспроизводимый Xray `IPOnDemand` после SERVFAIL проваливается
к младшему доменному правилу. Такое поведение не принимается за требуемый fail-closed.

```sh
flock -s "$yonik_build" env TMPDIR="$yonik_build" python tools/policy_traffic.py "$yonik_build/target/release/yonik-compile" "$yonik_build/target/release/yonik-local" /абсолютный/путь/к/xray /абсолютный/путь/к/sing-box
flock -s "$yonik_build" env TMPDIR="$yonik_build" python tools/dns_policy_gap.py /абсолютный/путь/к/xray
```

Вторая команда намеренно воспроизводит проблему upstream на синтетических данных;
её exit 0 не означает пройденный G-DNS. [Результаты и ограничения политики](docs/validation/2026-11-09-policy-routing.md).

### Документация и лицензия

- [Требования, архитектура и roadmap](docs/specs/README.md)
- [План начального этапа](docs/superpowers/plans/2026-11-09-linux-foundation.md)
- [GNU GPL v3.0](LICENSE); уточнение SPDX и notices зависимостей требуется перед поставкой.
