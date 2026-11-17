# План завершения yonik

Проверенная принятая база этого среза: `4b432f8ee6b88c15ea26a9703f9bfa91c303fa6e` (PR221, 2026-11-14 18:38:02 UTC); [текущая готовность и очередь](validation/2026-11-14-current-readiness-86c4228.md). PR219 и PR220 приняты в своих source bounds; PR221 принял driver/unit producer только в source scope, без actual N5/FR16 runtime. PR223 (prep), PR224 (FR16) и PR225 (Qt path) ожидают приёмки. Попытка root freeze/capture01 на source `91fe56c` завершилась ошибкой до компиляции из-за отсутствия `/usr/bin/qtpaths6`; CXX/Rust payload PASS нет. P05 остаётся qualified software Ready в прежних bounds; счёт 9/15/2. Native/runtime и final A4/A5 остаются OPEN.

Готовность исходного P11 после проверки replacement/source freshness: [решение и границы](validation/2026-11-14-p11-replacement-integration.md). Готовность исходных P04/P08 на принятом main `b25ed11`: [решение и границы](validation/2026-11-14-linux-p04-p08-readiness.md). Готовность исходных P06/P22 на принятом main `3247e6c`: [решение и границы доказательств](validation/2026-11-14-linux-p06-p22-readiness.md). Историческая delta до `d74e618` сохранена в [реестре 14 ноября](validation/2026-11-14-linux-accepted-delta.md).

Начальная инвентаризация: 10 ноября 2026, UI `85b2a8e`. Принятые срезы актуализированы 12 ноября 2026 по main `cceede520842a17e4ef548807f63f64b2be19226`; полные статусы требуют итогового аудита. Цель — пройти весь порядок из
[спецификации](specs/validation-and-roadmap.md): рабочий Linux-продукт,
проверенная поставка, затем Android. Пункты и критерии ниже уточняют порядок
исполнения, не заменяя требования FR и обязательные матрицы приёмки.

## Как считаем готовность

Всего **26 пунктов**: **9 готовы**, **15 частично выполнены**, **2 отложены (Android)**.
Остаётся полностью закрыть **17 пунктов**, включая отложенные Android P03/P26.
Это учёт полных критериев, а не процент реализации Linux: частичные пункты
различаются по объёму и не пересчитываются в процент готовности продукта.
Частичные результаты учитываются в описаниях, но не получают условные 50–90%.

Ранние G-LINUX/G-DNS/G-APP включены в соответствующие сетевые пункты, поэтому
одна интеграционная проверка не посчитана дважды. Android compile-check и
технический Android-host разделены: успешная компиляция не доказывает работу VPN.

Статус «готов» требует проверяемого результата по всему критерию пункта.
Исторические evidence подтверждают только описанные в них срезы. После правок
обязательны релевантные проверки; green CI и независимое ревью нужны перед
слиянием согласно действующим договорённостям. Нельзя закрыть весь план только
по наличию GUI, количества unit-тестов или namespace-прототипа.

## Текущие принятые срезы — 12 ноября 2026

[Реестр обновления](validation/2026-11-12-linux-accepted-progress.md) фиксирует
результаты на main `cceede520842a17e4ef548807f63f64b2be19226` и их границы.
Он уточняет текущие срезы; полный перечень исходных критериев сохраняется в
[историческом индексе](validation/2026-11-11-linux-acceptance-index.md).
Этот исторический срез сам по себе не повышал число готовых пунктов. Последующее
решение по P06/P22 приведено в начале документа; оно основано на runtime evidence
и проверке исходных критериев, а не на одном CI или merge.
Production issuer/BoundTun, foreign-UID и mixed-policy Linux-приёмка,
финальная поставка и итоговая сверка всех критериев остаются открытыми.
Android и физические G-UI/G-POWER отложены без PASS.

## Исторический acceptance-срез: main b9e5071, 11 ноября 2026

[Полный индекс Linux](validation/2026-11-11-linux-acceptance-index.md) связывает
все FR, P01…P26, gates, D/A/T, P-01…P-08 и leaves исходных контрактов с evidence
и остатком этого среза. Последующие принятые результаты перечислены выше. Linux done не
заявлен; 3/26 (11,5%) сохраняется, P20 исправлен на частичный, Android P03/P26
отложен без изменения знаменателя.

Приняты #90 production CONFIG0600 12/12 на frozen 8ae373f (не #49 libtest),
#101 OFD, #114 native DNS partial, #107 6201cbe, #117 0ca6780, #118 b9e5071.
Открытые #109/#112/#115/#119–#123 учитываются отдельно от main; #91 остаётся
историческим открытым snapshot. Merge/CI/hash не заменяют runtime-приёмку.
Приоритет: integrated production Apply и domain/app provenance, полный DNS/private
lifecycle и итоговая поставка. По уточнению пользователя после #125 узкие
Go-интеграции обоих закреплённых ядер с Rust broker/TUN FD и локальный
`yonik-nsfs` adapter с Cargo edge явно разрешены; ожидание этих разрешений
больше не блокирует работу. Root возобновил #122 anchor; это не runtime proof.
Физические G-UI/G-POWER пользователь пока отложил: они остаются недоказанными,
без waiver или PASS; разблокировка KDE и hardware-counter permissions не заявлены.

## Историческая очередь (10 ноября; не текущий статус)

Продолжается полное выполнение спецификации по
[плану волн](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/docs/superpowers/plans/2026-11-10-spec-completion-waves.md).
Первая волна влита в main: PR #43 (`374ec75`) — переводы и CI,
#44 (`3768988`) — переносимый scheduler, #45 (`830af0d`) — матрица импорта,
#46 (`e33fa19`) — проверки восстановления хранения. На принятых heads все пять
jobs зелёные; замечания независимых reviews исправлены. P10 перешёл из «не начат»
в «частично»; число полностью закрытых пунктов и **3/26 (11,5%)** не изменились.
Runtime-срез подготовлен к независимому review: типизированный IPC, общий journal
и worker-first recovery проверены unit tests и namespace gates. Installed session
VM-матрица и TERM→KILL не приняты; `system_tun:false` сохраняется.
[Фактические проверки и остаток](validation/2026-11-10-system-session-runtime.md).
Следующая волна: системный runtime, Linux scheduler host, постоянные настройки,
Arch-пакет и ранний Android gate. Завершение волны не завершает весь проект.
После исследования Android пользователь отложил его реализацию и установку
инструментов: текущая очередь продолжает Linux. P03/P26 остаются открытыми.

Повторная проверка 10 ноября: desktop entry указывает на установленную сборку
`85b2a8e`, SHA-256 бинарника совпал с опубликованным evidence. На этой сборке
снова прошли 142 GUI-действия при 380×600 и масштабе 150% в offscreen-окне,
включая проверки отсутствия удалённых controls. Evidence:
`local/validation/whole-ux/recheck-2026-11-10/`. Это функциональная проверка;
она не заменяет замеры плавности в живой Wayland-сессии P23.

1. Последние UI-правки и desktop CI завершены: PR #28 влит как `63fb1a5`
   после успешных push/PR workflows (все 5 PR jobs). UI установлен и проверен.
   Причина сбоя CI — путь сокета 107 байт; короткий приватный runtime исправляет запуск.
2. Реестр системных ядер влит через PR #29 (`628d5c3`), CI зелёный.
   Одноразовые peer-bound artifacts влиты PR #30 (`d585b01`), CI зелёный.
   Общий бюджет buffers/snapshots реализован в `73a6ab2`: локально 393 Rust-теста
   прошли, независимое ревью выполнено. PR #31 влит как `acff6c5` после всех
   пяти зелёных jobs в обоих workflows. Выявленный CI сбой очистки launcher на
   relatime исправлен в `ed770be`, все 100 Python-тестов прошли.
   [Nftables executor](specs/helper-nftables-executor.md) влит PR #32 (`dd82114`)
   после всех пяти зелёных jobs, включая fixes `0a90a8e`/`d479217`.
   [Evidence базового executor](validation/2026-11-10-helper-nftables.md).
   Добавлена [типизированная блокировка](specs/helper-public-block.md) с атомарной
   заменой правил: реальные TCP/UDP IPv4/IPv6, VPN/LAN, cold NDP, DNAT и Unlock
   [проверены в namespace](validation/2026-11-10-helper-public-block.md),
   PR #33 влит как `37401a4` с зелёным CI.
   Добавлено [durable хранение и восстановление](specs/helper-policy-recovery.md):
   schema v2, desired/previous/Unlock и шесть SIGKILL-границ в namespace;
   [evidence](validation/2026-11-10-helper-policy-recovery.md): 427 workspace tests,
   три namespace-сценария и независимое review.
   PR #34 влит как `cef982a`, все пять jobs зелёные.
   Реализован [IPC v1 и public-protection host](specs/helper-service.md),
   добавлены service packaging и cgroup fence; [проверки](validation/2026-11-10-helper-service.md)
   охватывают private-bus/реальный nft и inert restart. PR #35 влит как `e61c7e8`,
   все пять jobs зелёные. [Владение persistent TUN](specs/helper-owned-tun.md)
   реализовано отдельным executor: create/alias/reopen/cleanup и совместимость
   обоих ядер [проверены в namespace](validation/2026-11-10-owned-tun.md).
   PR #36 влит как `3342b29`, все пять jobs зелёные после исправления
   namespace staging и чистого Cargo target в Ubuntu CI.
   [Адреса/маршруты и системный компилятор](specs/helper-tun-configuration.md)
   реализованы: [actual TUN→VLESS→echo](validation/2026-11-10-system-tun-configuration.md)
   проверен для Xray и адаптера sing-box с external configuration; PR #37 влит
   как `e9c4c1` после всех пяти зелёных jobs обоих workflows и исправления
   гонки CLI-теста `8a148c2`.
   [Управляемая RPDB](specs/helper-tun-rpdb.md) добавляет durable правила и
   mark bypass; оба compiler-профиля проверены с peer за veth в отдельном netns.
   PR #38 влит как `3a48c40`, все пять jobs обоих workflows зелёные.
   Срез [worker runtime](specs/helper-worker-runtime.md) добавляет sealed-FD
   Check/Run, fixed systemd units и supervisor. Actual TUN/RPDB traffic обоих
   ядер проверен с отдельным UID и только NET_ADMIN; Check без capability.
   Установленные units/cgroup и dedicated UID проверены в одноразовой Arch VM:
   [три actual gates](validation/2026-11-10-installed-worker.md) прошли, включая
   setsid-потомка, helper SIGKILL/recover и TUN traffic обоих ядер. Остаются
   TERM→KILL для упрямого потомка и подключение runtime к session host.
   PR #39 влит как `6355150`, PR #40 — как `49debdd`; все пять jobs обоих
   workflows зелёные на соответствующих heads. Следующий срез:
   [типизированный профиль и неизменяемый сетевой план](specs/helper-session-network.md).
   Шесть протоколов DTO и configure/capture/external-check/cleanup проверены;
   [evidence](validation/2026-11-10-session-plan.md). Сам SystemSessionHost ещё нужен.
   Следом нужны системная установка/клиент, live reconcile и TUN-сессия с явным
   владением ресурсами и cleanup по [плану интеграции](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/docs/superpowers/plans/2026-11-10-system-session-integration.md);
   затем DNS/Fake-IP и атрибуцию приложений.
3. Интегрировать приватные VPN/LAN/ru-direct, сценарии смены сети и полную
   Linux-матрицу. При включённом kill switch после исчерпания retries сеть
   блокируется; при выключенном восстанавливается обычная сеть.
4. Довести продуктовый GUI, редакторы, сохранение настроек, трей, диагностику,
   производительность и Arch-поставку. Основная часть остаётся на Rust;
   Go допустим только для минимальных совместимых патчей самих ядер.
5. Ранний Android runtime-gate P03 проверять параллельно Linux-основанию, до
   окончательного закрепления общей архитектуры. Полное Android-приложение и его
   поставка P26 идут после Linux v1, как требует исходная последовательность.

## Основа и общая логика

| ID | Пункт | Статус | Критерий полного завершения и текущий остаток |
| --- | --- | --- | --- |
| P01 | Требования и архитектурные контракты | Готов | Зафиксированы FR, сетевые инварианты, границы компонентов, Android-риски и бюджеты. Evidence: [требования](specs/requirements.md), [приёмка](specs/validation-and-roadmap.md). Реализация gates считается отдельно. |
| P02 | Переносимая библиотека: Android compile-check | Готов | Общая Rust-часть компилируется для `aarch64-linux-android` без Linux-адаптеров; проверка включена в CI. Evidence: [snapshots](validation/2026-11-09-subscription-snapshots.md), [workflow](../.github/workflows/check.yml). Это не Android-приложение. Final6pairs PR187 принят (`48ce743`); новый final build PASS не заявлен. |
| P03 | Технический Android-host / G-ANDROID | Отложен | Оба engine через FFI, TUN FD/protect, TCP/UDP, stop/revoke, lifecycle и package callbacks; закреплённые wrappers. Остаток — runtime-host и измеренные результаты. [Контракт](specs/platforms.md). |
| P04 | Импорт URI/JSON/Base64 и ручной ввод | Готов | Исходный критерий покрыт text/file → review/approve → save, URI/JSON/Base64, ручной формой, original preservation и bounded robustness. Исторические functional proofs сверены по пяти bundles; известная утрата raw write trace раскрыта и не объявлена восстановленной. [Evidence join](validation/p04-fr07-accepted-evidence/README.md), [решение и source bounds](validation/2026-11-14-linux-p04-p08-readiness.md). Новый whole-tree runtime и final A5 не заявлены. |
| P05 | Подписки, обновления и идентичность профилей | Готов | Исходный P05 software-qualified Ready принят решением root после trusted R2 и source transfer до `cfcb457`. Native issuer/N5 и final A5 остаются отдельными gates. Исторические source bounds и ограниченный semantic transfer сохранены в текущем реестре готовности. Плановые обновления и physical energy — P10. [Snapshots](validation/2026-11-09-subscription-snapshots.md), [identity](validation/2026-11-09-profile-identities.md). |
| P06 | Зашифрованное хранение, миграции и восстановление | Готов | Исходный storage-критерий покрыт encrypted repository/CAS, migration/fault/Missing/Locked evidence и normal Backup → Restore NEW → fresh normal Host с тем же private Secret Service item. Проверены original/metadata/revision, missing-source refusal и неизменность live DB. [Actual restore](validation/2026-11-14-p06-real-restore.md), [решение о готовности и source bounds](validation/2026-11-14-linux-p06-p22-readiness.md). Final A5, physical login/PAM и reboot/autoconnect не объявлены выполненными. |
| P07 | Общая модель политик и семантика представлений | Частично | Приняты Linux selector/Draft V2, port/protocol semantics, wire v3, format5 CAS/backup barrier и old-reader preservation через PR210/213. Normal Host/private Secret Service persistence и GUI roundtrip подтверждены в своих frozen source bounds; unsupported enabled draft сохраняется и Connect явно отказывает. PolicyApply bridge сохраняет selector semantics. Actual process/domain/CIDR enforcement и полная интегрированная матрица редакторов остаются. [P07 V2](validation/2026-11-12-p07-linux-v2.md), [port/protocol](validation/2026-11-14-p07-port-protocol-implementation.md), [persistence](validation/2026-11-14-p07-normal-ss-persistence.md), [Apply](validation/2026-11-12-p07-policy-apply-integration.md). |
| P08 | Capabilities и компиляторы обоих ядер | Готов | Исходный compiler-критерий покрыт заявленным набором профилей/правил, unit/property проверками и config-check закреплённых ядер, включая положительный SS2022 AES-128 witness. Неподдерживаемые options и DNS/routing contracts явно отклоняются без потери параметров. [Compiler evidence](validation/2026-11-09-engine-compiler.md), [SS2022](validation/p08-ss2022/README.md), [решение и границы](validation/2026-11-14-linux-p04-p08-readiness.md). Native activation, runtime DNS и handshake остаются P13–P15. |
| P09 | Lifecycle сессии и PreparedPlan | Частично | Приняты reducer/generations, actual LocalSession cancellation обоих pinned cores и health cancellation с terminal process-group oracle, учитывающим zombie. DesktopHost Stop имеет actual Disconnected snapshot; это не request-ID ACK health cancellation. Полный production system lifecycle и связанные cleanup/recovery gates остаются. [Native cancellation](validation/2026-11-12-native-cancel-matrix.md), [health](validation/2026-11-12-health-probe-cancellation.md). |
| P10 | Scheduler фоновых обновлений | Частично | Переносимый scheduler, DesktopHost dispatch/review/cancel, событийная NM/UPower policy, persisted due/retry budget и private-bus restart/reopen реализованы. Остаются фоновые окна и полная энергоприёмка. [Evidence](validation/2026-11-10-desktop-private-bus.md). |
| P11 | Ошибки и переводы RU/EN | Готов | Исходный human-error критерий покрыт закрытыми RU/EN catalog/V2, typed producer/context proofs и actual representative Main/export/clipboard. Final source freshness gate 6/6; replacement failure обоих callers публикует typed initialize cause без выдуманного generation, library 118 PASS/1 ignored и assertion mutant RED. [Решение, CI/merge condition и source bounds](validation/2026-11-14-p11-replacement-integration.md). Исторические producer bindings и P11_main_closed=false сохранены; native issuer, FR16 worker availability и whole merged-runtime отдельно не приняты. |

## Linux-сеть

| ID | Пункт | Статус | Критерий полного завершения и текущий остаток |
| --- | --- | --- | --- |
| P12 | Privileged helper и владение ресурсами | Частично | Авторизация, [реестр](specs/helper-trusted-registry.md), [одноразовые artifacts](specs/helper-prepared-requests.md) и [бюджет](specs/helper-memory-budget.md) существуют. [Nftables executor](specs/helper-nftables-executor.md) и [правила блокировки](specs/helper-public-block.md) влиты PR #32/#33 с зелёным CI. [Durable policy schema v2/recovery](specs/helper-policy-recovery.md) проверены на шести SIGKILL-границах. [IPC v1, авторизованный Apply/Unlock и cgroup fence](specs/helper-service.md) реализованы и локально проверены с actual nft; сервис ещё не установлен. [Persistent TUN executor](specs/helper-owned-tun.md) локально проверен, но ещё не связан с session. [Адреса/маршруты и compiler](specs/helper-tun-configuration.md) проверены в namespace. [RPDB executor](specs/helper-tun-rpdb.md) проверен с mark bypass и cleanup. [Установленные worker units/cgroups](validation/2026-11-10-installed-worker.md) проверены в VM с реальными ядрами. Production non-app installed helper/system bus/polkit lifecycle подтверждён #90: 12/12 на frozen 8ae373f; остаток — live topology reconciliation, production app/domain Apply и полная матрица владения. См. актуальный индекс; ранние утверждения о wiring выше исторические. [Авторизация](validation/2026-11-09-helper-authorization.md), [journal](validation/2026-11-09-network-resource-journal.md). |
| P13 | Системный TUN обоих ядер / G-LINUX | Частично | Namespace TCP/UDP/IPv4/IPv6 пробы и persistent single-queue TUN для обоих ядер проверены; [owned TUN](validation/2026-11-10-owned-tun.md). Системный compiler и TUN→VLESS→echo проверены также через установленные systemd workers в одноразовой VM; sing-box требует pinned external-configuration adapter. Подключить helper/host к реальной политике, минимальным правам, исключению транспорта и stop/crash cleanup, пройти Linux-матрицу. [Evidence](validation/2026-11-09-tun-traffic.md). |
| P14 | DNS/Fake DNS / G-DNS | Частично | Есть модели, выявленные gaps и native pinning/provenance-патчи. Production DNS software integration отсутствует и требуется наряду с runtime-проверкой; завершить единый fail-closed контракт D-01…D-07, поколения/TTL, оба ядра, Fake DNS on/off и IPv4/IPv6. [Native DNS](validation/2026-11-09-native-dns-contracts.md), [pinning](validation/2026-11-09-resolution-pin.md). |
| P15 | Атрибуция приложений / G-APP | Частично | Проверены отдельные executable-path пробы. Нужны реальная TUN-маршрутизация обоих ядер, одновременные приложения, составные правила, A-01…A-08, упаковки/ограничения и стоимость P-06. [Evidence](validation/2026-11-09-process-routing.md). |
| P16 | Приватные VPN, LAN и изменения сети | Частично | Read-only наблюдение topology/resolver реализовано. Нужны verified binding WG, split DNS, Apply и сохранение защиты при смене VPN/сети/sleep, затем корректное восстановление. [Наблюдение](validation/2026-11-09-network-observation.md), [topology](validation/2026-11-09-network-topology.md), [resolver](validation/2026-11-09-resolver-host.md). |
| P17 | ru-direct и комплексная Linux-приёмка | Частично | Приняты immutable snapshots и product preset wiring, CAS/ACK/busy/cancel, объединённые с P05/P07/PolicyApply/P11 guards. Mixed domain/CIDR Unsupported и system_tun=false сохраняются; actual приоритеты private/LAN/user и полная native Linux-матрица остаются. [Интеграция P17](validation/2026-11-12-pr116-final-integration.md), [исходные snapshots](validation/2026-11-10-preset-snapshots.md). |

## Приложение и поставка

| ID | Пункт | Статус | Критерий полного завершения и текущий остаток |
| --- | --- | --- | --- |
| P18 | Последние согласованные UI-правки и HWID | Готов | yonik, узкое окно, card+gear, центральная кнопка; нет избранного, footer-кнопок/текста, бейджа и чекбокса анимации. Opt-in HWID стабилен и зашифрован. Установлена `85b2a8e`: по 142 GUI-действия в двух размерах, 6 health-сценариев, review без findings. [UI evidence](validation/2026-11-09-home-cleanup.md), [HWID](validation/2026-11-09-hwid-ui.md). Общая продуктовая приёмка — P19/P23. |
| P19 | Продуктовые экраны и системное подключение | Частично | Приняты PolicyApply, product import и P17 wiring с revision/generation/cancel fences. Полный production GUI/TUN run, recovery и итоговая проверка пользовательских путей остаются. [PolicyApply](validation/2026-11-11-inline-policy-apply.md), [import](validation/2026-11-12-desktop-local-import.md), [контракт](specs/ui-backend-contract.md). |
| P20 | Два редактора правил и каталог приложений | Частично | Редакторы, каталог и диагностика имеют component evidence; [L15](validation/2026-11-11-editor-policy-diagnostics.md). Software замены активной сессии отсутствует в текущих LocalSocks и System; необходимо реализовать и доказать атомарный actual Apply одного поколения и полную приёмку A-04/A-07/A-08 без потери семантики. [Спецификация](specs/routing-and-tray.md). |
| P21 | Трей и desktop lifecycle | Частично | Принят настоящий private Plasma restart для обоих pinned cores × RU/EN: hidden traffic с peer-sensitive oracle, сохранение процесса, повторная SNI регистрация, Stop/Connect/active Quit и cleanup. Перезапускались plasmashell/kded, KWin сохранялся. Это изолированная desktop-приёмка; физические G-UI/G-POWER остаются отложенными. [Plasma evidence](validation/2026-11-12-fr19-private-plasma.md). PR214 принят на `e358653dfd8e0d74e29a2a28ec73e7969626072d`: отдельные autostart/autoconnect, оба default OFF, software scope. Physical PAM/reboot/lock OPEN. |
| P22 | Пакетные проверки серверов и диагностика | Готов | Исходный критерий покрыт HTTPS/TLS/refusal, тремя TCP-пробами, bounded API до 10 000 целей, actual GUI/CancelBatch/Stop и source/revision/network/generation fences. Сохраняются source bounds исторических runtime proofs; перенос на принятый код проверен по связанным producer-инвариантам. [GUI evidence](validation/2026-11-14-p07-production-gui.md), [решение и границы](validation/2026-11-14-linux-p06-p22-readiness.md). Новый current merged-runtime PASS и final A5 не заявлены. |
| P23 | Выбор toolkit, G-UI и G-POWER | Частично | Qt UI есть. Нужны продуктовая приёмка ввода/clipboard/масштабов/трея и P-01…P-08 с idle/hidden/attribution. [бюджеты](specs/performance.md). Физические G-UI/G-POWER пока отложены пользователем, без waiver/PASS; критерии и статус частичного выполнения сохранены. Экран блокировки и питание без согласования не менять. |
| P24 | Arch-поставка, обновления и откат | Частично | PR119 принят в main: source package и изолированные old→new→old/uninstall/userdata проверки подтверждают свои frozen refs. Они не заменяют итоговый package из конечного source freeze с production helper/ядрами. Host install не выполняется. [Arch source](validation/2026-11-11-arch-source-6cf65a4.md), [production custody](validation/2026-11-11-arch-production-custody.md). |
| P25 | Открытая Linux-поставка и release-приёмка | Частично | P25 capture PR215 и postcapture attribution join PR217 приняты как инструменты/source integration; actual final build и итоговая release-приёмка OPEN. GPL и README RU/EN есть. Нужны notices/SPDX и аудит условий зависимостей, пользовательские инструкции, зелёные проверки, evidence всех FR и явные ограничения. Релиз/публикация выполняются только в разрешённом объёме. [Лицензия](../LICENSE), [приёмка](specs/validation-and-roadmap.md). |
| P26 | Android-приложение и поставка | Отложен | После P03: нативный UI/VpnService, встроенный WG, оба worker, protect/revoke/lifecycle/UID/package, полная матрица и измерения на физическом телефоне. [Платформы](specs/platforms.md), [этап 6](specs/validation-and-roadmap.md). |

## Правила дальнейшей работы

- Перед каждой задачей выбирать конкретный остаток и критерий завершения.
- Обычно 1–2 сабагента, только для независимых полезных частей; root интегрирует
  изменения и проверяет спорные выводы. Не повторять надёжное исследование целиком.
- Не менять критерий готовности ради повышения процента. При обоснованном изменении
  декомпозиции отдельно пересчитать знаменатель и объяснить изменение.
- После каждого закрытого пункта обновлять таблицу и итоговые числа. Partial
  превращается в «готов» только после необходимой runtime/acceptance-проверки.
- Пользовательские подписки/ключи сохранять; сетевые тесты проводить в собственном
  изолированном окружении. Секреты в repo, argv, логи и evidence не помещать.
