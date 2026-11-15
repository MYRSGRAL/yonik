# Completion API: состояние реализации

Это SOURCE/PURE codec milestone, не завершение P5 и не runtime acceptance.
Production issuer, delivery/custody, versioned backend dispatch, native DAT
delivery, новый resolver snapshot и dynamic firewall lifecycle — следующие части.

## Shared codec

`yonik-linux/src/profile_channel.rs` — private модуль. `Header`, `LaunchRecord`,
`Message`, `Frame` и `Capsule` не являются grant или доказательством peer/FD.
Header — exact YNKCAP01/128; сообщения — root revision2.1 с AUTHORIZE scope/branch
из mapping v3. `Sequence` после gap/replay/wrap остаётся revoked. Launch records
и ACK exact: YNKEXT01/YNKLOC01/192, YNKEXAK1/40. Ancillary и pidfd validation
относятся к production OS wrapper, а не byte decoder.

`OwnedCapsule::build(intent, plan, snapshot_ref, digest, policy_revision,
admission_id)` принимает один `ProfileIntent`, сам вызывает validate и проверяет
typed ingress mapping. Caller не подставляет независимый graph. Builder выводит
все 11 tables, subjects в compiler order, scopes TCP→UDP, endpoints в первом
normal/mux encounter order, chain C→nextInput и exact nextBranchMask.
SHA-256 manifest/fingerprint использует существующий sha2 только в yonik-linux.
SnapshotRef и plan bindings пока DATA: custody не удостоверяется их полями.

Decoder заимствует wire bytes; row offsets и validation scratch фиксированы,
нет heap allocations. Count/length preflight выполняется до просмотра rows;
MemoryPreflight учитывает RX/TX, queues, pending, tombstones, ingress/grant/
pool/physical/logical/owner metadata в общем 8MiB. Builder резервирует aggregate
credit до graph/container allocation; после освобождения временных структур
удерживает credit итогового Vec. Frame≤64KiB, tables1..11 обязательны,
mappingVersion=3, tableCount=11. Проверяются indices/backreferences, протоколы,
branch sentinels, ацикличность, hashes, snapshot cross-reference, unique staged
assets≤16 и общий private storage≤64MiB. Эти caps не увеличивают firewall128.

`tests/fixtures/xray-profile-channel-v3/` содержит независимые synthetic
struct.pack vectors: Local, System chain/mux/probe/snapshot, все сообщения и
оба launch record/ACK. `rowLength` означает размер payload без четырёхбайтового
row prefix; `byteLength` таблицы включает row prefixes. Поля hashes не заменяют
source proofs; ADMIT_ACK Allow означает commit всех проверенных references только
в authenticated issuer lifecycle.

## Закрытая проекция carrier

`ProfileIntent::project_branch(subject: &str, input: WireNetwork,
mux_worker: bool) -> Result<BranchProjection<'_>, ProfileCompileError>` вычисляет
P→D→C из private typed fields того же intent. `WireNetwork` использует TCP=6,
UDP=17. `BranchProjection` имеет только getters `dial`, `carrier`,
`active_stream`, `action`, `next_subject`; публичного конструктора нет.
`WireAction` соответствует mapping v3: PhysicalStatic=1, Chain=2,
DirectDynamic=3, NoDial=4. Результат заимствует intent, не копирует credentials.

`mux_worker=true` означает синтетический TCP input proxy handler. Это вычисление
кандидата, а не доказательство наличия или выбора outbound mux.
`ProfileIntent::branch_mask(subject,input,port)` выводит допустимые branches из
private typed mux fields; None port объединяет port443 и остальные решения.
Builder использует этот getter, для nextBranchMask передаёт точный source port.
Для chain следующий input берётся из carrier, а не исходного flow.
Pinned `infra/conf/xray.go::MuxConfig.Build` превращает пустой/отсутствующий
`xudpProxyUDP443` в `reject`. Memoized derivation фильтрует недопустимые chain
branches по subject/input/port443; отклонённый переход не создаёт edge. Если
для input нет допустимой branch, scope остаётся с mask0 и всеми branch полями
Absent. Mapping v3 запрещает прочие bits, но не требует ненулевой mask scopes
(в отличие от ingress mask). Actual попытка такой branch должна быть denied.
Отдельный independent vector `system-chain-default-reject.json` фиксирует это
поведение без отказа от допустимого TCP пути того же профиля.
Blackhole/DNS не получают общий dial. Raw UDP не использует configured stream.
Exact XHTTP TLS ALPN `[h3]` даёт UDP; смешанный ALPN этого не делает.

## Local launch record

При реализации delivery Local использует отдельный `YNKLOC01`, version=1,
length=192, тот же layout, что YNKEXT01; SCM rights=0. `workerPid@132` и
`workerStart@144` равны нулю до spawn; owner PID/start принадлежат Host.
Остальные binding/manifest поля сохраняются, reserved bytes нулевые.
Это не System proof: mode проверяет потреблённый trusted issuer, не env.
После spawn Host обязан проверить actual child pidfd/PID/start и HELLO;
Go — inherited Host pidfd, sender peer и binding. Frozen records не меняются.

## Следующая интеграция

Нужны Local/System authenticated issuer и реальные callsites. Этот API не снимает
существующий Unsupported и не объявляет native feature доступной.
