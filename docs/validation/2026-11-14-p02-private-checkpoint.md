# P02 SHORT: private interposer, checkpoint до независимого review

Продолжение preflight 6d1905e после разрешения root. Общие application/build/P01,
product CLI и public QML API не изменены. Это checkpoint, **не SHORT PASS**.

## Проверенное

Свежий production source a29ea61610ea5de9fd188e65198295d71e9f2278 собран Rust
1.85.1, gui, dev/unoptimized+debuginfo, jobs=1, with-rust-slot. Это не release
budget acceptance. ELF и source archive сохранены вне TTL. Собственный target
очищен cargo clean (2.5 GiB); transient task root удалён.

Actual Main/qrc hash и actual yonik::DesktopBridge проверяются driver. Негативная
qrc-binding канарейка с неверным expected hash завершилась отказом до measurement.
Observer использует QSocketNotifier, existing bridge dispatch и оригинальные
production QMenu QAction; SNI копии SystemTrayMenuItem исключены. Hide вызывает
реальный close окна. Нет периодического test GUI timer; один deadline 1100 s.

Настоящий установленный KSecretD запущен на собственном same-UID bus, без service
activation directories и host settings. Через штатный --pam-login создаётся новая
private коллекция со случайным одноразовым hash. Ключ приложения создаёт production
Secret Service path; key/config injection в positive path отсутствует. Проверяется
PID владельца org.freedesktop.secrets. Production backup → import_text → review →
approve_refresh → select_profile проходит через existing bridge.

Оба pinned core прошли короткие actual-GUI positive → peer absent → restored
positive, hide и Stop/pidfd readiness/rebind; после Stop проверено отсутствие детей.
Strict TLS negative — curl через actual SOCKS с чужим CA (exit 60), затем правильный
CA positive. Это **не** отдельный negative тест trust policy самого Rust health
client; actual GUI health positive отдельно подтверждён попаданием в HTTPS fixture.
StateChanged не доказывает всю внутреннюю работу.

LocalSession пишет config в pipe. Private write interposer сохраняет только bytes,
для которых kernel write вернул успех, связывая artifact с inode stdin actual
engine. Захват включается только на connect и выключается при Connected/Limited,
до idle. Никакого чтения/поглощения pipe, перекомпиляции или упрощения baseline.
Production ELF проверяет pin; driver дополнительно сверяет composition metadata,
actual /proc/engine/exe и hash сохранённых bytes. Config содержит случайный probe
credential: bytes разных connect не обязаны совпадать. Каждая измеряемая пара
использует **одни и те же** captured bytes полного приложения в engine-only.
Standalone получает файл через stdin вместо production pipe; различие сохранено
здесь явно. Его actual stdin bytes/exe проверяются. Короткий baseline oracle обоих
ядер прошёл; idle окна в нём 2 секунды, не 900.

Внешний sampler сохраняет CPU ticks, PSS/private dirty, FD/threads, starttime/ns и
потомков. FD канарейка удержания семи дескрипторов PASS. Wakeups=null: точного
per-process wakeup count без tracing нет; main-thread context switches — только
явно подписанный proxy. Fixture HTTPS event должен оставаться пустым после warmup;
это не packet capture произвольного сетевого трафика.

Actual Qt window/renderer/QSystemTrayIcon находятся внутри GUI PID и учитываются
в product group вместе с единственным active engine. Внешние private bus,
SecretService, Python SNI watcher, HTTPS/peer и sampler — test infrastructure,
перечислены отдельно. Это offscreen/software Qt + private SNI, не physical Plasma.
Метрики GUI включают memory/callback overhead private interposer.

## Живая кампания и границы review

`short-campaign2` запущена по прежнему разрешению **до** дополнительного checkpoint.
При checkpoint уже существует `sing-box-1-full/samples.json` первого 900 s окна;
она не остановлена и не перезапущена автоматически. Новых длинных кампаний до
review не запускать. Исходная классификация: unfinished SHORT workload, не PASS.

Handle exec session **57793**, supervisor PID **1658427**, starttime **4662119**.
Run/deadline, source hashes, ELF bindings и short oracle результаты находятся в
`docs/evidence/p02-short-private-20261114/checkpoint.json`. Полные source/raw/ELF:
`/home/myrs/projects/yonik/local/evidence/p02-short-private-20261114/`.
Текущая кампания: `short-campaign2`; terminal files `result.json` / `failure.json`,
после каждого законченного интервала обновляется `progress.json`. Общий deadline
12000 s; SIGTERM supervisor обрабатывается через cleanup контекстов. Сигналить
только после сверки starttime, через pidfd. Не принимать старые/оборванные
`short-campaign1` samples за новый результат: она прервана до завершения первой
пары при выравнивании SSL_CERT_FILE environment baseline и product.

Независимому reviewer проверить именно пассивность private управления, связь
успешных pipe writes с actual engine, exact baseline bytes, чувствительность
binding/resource/peer/TLS controls и normal/emergency cleanup. Product proofs
169/173/177 не переобъявляются результатами нового workload.

Запланированы три пары по 900 s на каждом ядре, порядок full → engine внутри
каждой пары (возможный order bias не исключён). Полный variance/overhead станет
известен только после terminal result; сейчас не установлен. 8h energy/G-POWER,
release budgets, physical desktop, full-system TUN, app-rules/FakeDNS/WG/ru-direct
матрица и посторонние сети этим сценарием не покрываются.

Проверки checkpoint: C++ interposer build, Ruff check/format, sampler FD test,
actual short oracles и отказная qrc канарейка. Ранние неуспешные tooling attempts
сохранены вне TTL, не включаются в измеряемую статистику.
