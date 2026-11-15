# Completion API: состояние реализации

Это SOURCE/PURE codec milestone, не завершение P5 и не runtime acceptance.
Production issuer, delivery/custody, versioned backend dispatch, native DAT
delivery и dynamic firewall lifecycle — следующие части. Source producer DAT и
новый resolver snapshot реализованы отдельно от runtime admission.

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

## Сверка Go a004e92

Exact Go golden сохранён без изменений в
`tests/fixtures/xray-profile-channel-v3/go-a004e92-launch-admission.json`.
Он проверяет byte grammar, а не production builder: его config bytes `config`
не являются валидным ProfileIntent, а transport hash синтетический.

Две несовместимости требуют root integration, Rust authority не ослабляется:

- Go `profileCapsule.validate` отвергает table9 payload byte3=0. Native default
  UDP443 reject может дать закрытый mask0 scope (описан выше); этот вариант
  отдельно закреплён Rust independent vector, никакой branch/edge он не разрешает.
- Go `profileAssetPath`/`verifyAssets` ожидают `<digest>.dat`, тогда как принятый
  P3 emitter `native_profile/emit.rs:238` создаёт `ext:r-<digest>.dat:<category>`
  через `ExternalRef::tag`. Catalog source basename `<digest>.dat` не меняется;
  runtime stage/consumer должны согласовать deterministic `r-<digest>.dat`.

Go `main/run.go` читает bounded stdin до `PrepareProfileLaunch`, хотя parser и
NewWithContext идут после admission. Local launcher обязан удостоверить image
до передачи provider config; ожидание HELLO перед stdin с этим caller не работает.
Go gate остаётся off; наличие golden/ACK не заменяет flow grants или deployment.

## Trusted source producer

`helper/profile_intent.rs::NativeResourceSet::capture(graph,cancel)` открывает
только fixed root-owned catalog и digest basenames. Категории связываются с
compiler requirements после actual bounded DAT parsing. Удерживаются каталог,
все parent FDs и DATA FDs; revalidate сравнивает identities/bytes/hash отдельно.
Это native DAT proof, не `canonicalRebuiltBatch`; актуальный payload/stage описан ниже.
Ошибочный revalidate делает source set/snapshot sticky stale; повторный вызов
не открывает источники и не выдаёт новый proof. Custody остаётся у объекта.

`PinnedResolverSnapshot::capture` теперь охватывает nsswitch, resolv, hosts и
actual kernel hostname (`/proc/sys/kernel/hostname`, bounded read без libc/NSS).
Прямые и symlink parents удерживаются через O_PATH|NOFOLLOW; resolv chain≤4,
каждый link/root-owned parent и final source проверяется before/after. Missing
hosts — отдельное retained parent observation. Остальные missing sources дают
отказ. Revalidate повторяет fixed capture и проверяет retained handles; unit tests
не вызывают capture и не читают `/etc`/`proc`.

`resolver_snapshot_data` реализует pinned netgo files/DNS ordering (включая
resolve при отсутствии explicit dns), defaultNS, первые три valid nameservers
с duplicates, search/domain, options и coalesced hosts aliases. Неизвестная или
непредставимая grammar даёт typed Resolver error. Canonical YNKDNS01 asset и
sourceDigest v2 различаются. `profile_channel::verify_resolver_asset(bytes,ref)`
сначала проверяет exact size/hash, затем zero-allocation bounded readback.
Independent vector `resolver-snapshot-v1.json` предназначен для Go parity.

`FullProfileRequest::prepare_system(plan,policy_revision,admission_id,cancel)`
связывает same intent → source capture → resource/resolver bindings → один
CompiledProfileSystem → RetainedSystemProfile digest → capsule. Возвращённый
`PreparedFullProfile` удерживает exact compiler result и source proofs, но не
подтверждает selection/installed image/owner и не выдаёт Apply/Run/grants.
Serialized backend должен проверить эти authority proofs отдельно, перенести
тот же retained result в SessionArtifact и revalidate перед каждой стадией.
Numeric/provider-DNS synthetic fixture этого producer не вызывает OS capture.

Дополнительные exact Go a004e92 несовместимости для root review:

- `profileDNSName` в snapshot decoder запрещает uppercase, но pinned netgo
  `ensureRooted` не меняет регистр search/domain/hostname. Rust сохраняет эти
  bytes; pure fixture `search Example.INVALID` не подгоняется под decoder.
- `decodeProfileSnapshot` применяет `profileIP` к hosts addresses, запрещая
  unspecified/multicast. Pinned netgo hosts parser принимает valid literals
  (например `0.0.0.0 blocked.invalid`). Сами hosts rows не разрешают physical
  dial: mandatory destination checks остаются отдельными. Resolver peers в Rust
  проходят более строгие mandatory checks, неподдержанный selected peer не
  заменяется следующим nameserver.

## Production counterpart после 9b1bba9

Это незавершённый integration milestone. Capability остаётся закрытой:
`helper/native_profile_channel.rs::require_consumer` возвращает Unsupported до
проверенного complete Go consumer/physical-pools/DNS/service counterpart и
installed-image proof. Go ff5d0ce — source pin, не deployment proof. Наличие
HELLO/manifest ACK отдельно не снимает этот gate. Runtime acceptance не выполнялся.

`service::PrepareFullProfileV1` после preflight/Polkit/trusted bus peer передаёт
`FullProfileRequest` в `SystemProtectionHost::prepare_full_profile`, затем в
serialized `Backend::prepare_full_profile`. Не создаётся ServerIntent. Source
capture предшествует listen/check; один compile result удерживается в
`Arc<PreparedFullProfile>` в SessionArtifact и WorkerPayload. Config memfd digest
сверяется с retained result. Все physical/provider-direct DNS/snapshot peers
имеют отдельные RouteCapture. Их проверяют prepare/apply/start/active fences;
неудача делает весь SessionArtifact sticky stale. Chain remote не создаёт
дополнительную firewall exception. Hostname physical leaf пока закрыт до
проверенного pinned resolver query/provenance counterpart.

`WorkerPayload::new_full_profile` создаёт отдельный `TrustedNativePayload`
из actual DAT source FDs и resolver asset. Private helper→worker envelope
`YNKNPY01` имеет header112, descriptors88, затем exact capsule; общий размер
не более65536. Header: totalLength u32@8,configLength u32@12,imageHash32@16,
configHash32@48,mode u8@80,assetCount u8@81,outputCount0/2@82,reserved0@83,
resourceSession u64@84,generation u64@92,capsuleLength u32@100,reserved0[8]@104.
Descriptor: kind1/2/3@0,format1@1,reserved0[2]@2,digest32@4,bytes u64@36,
records u64@44,sourceDigest32@52,flags u32@84. DAT source/flags равны0;
resolver records=0. Receiver сначала проверяет bounded layout/capsule и exact
table6/11 references, затем materializes FD copies и повторяет hashes/seals.
FD order: image,config,native assets,optional stdout/stderr. Старые worker
envelopes и frozen role FD counts не меняются. Неизвестные ancillary rights
полностью закрываются, oversize не расширяет FD vector.

`native_assets::Assets::create_profile` использует existing worker tmpfs ledger,
включая empty controlled root, deterministic `r-<hash>.dat`/`dns-<hash>.bin`,
copy/readback/hash и Unknown quarantine. Общий file-count16/storage64MiB и
existing physical working-copy reservations сохраняются.

`SystemWorkerSupervisor::start_native` после verify_pending получает
`Session::owner_endpoint`, запускает ProfileRuntime и передаёт отдельный
extension endpoint. `handoff_verified_profile_run` удерживает stamp до первого
send, посылает YNKEXT01+один FD, ждёт exact YNKEXAK1, затем отправляет прежние
YNKROLE1+два FD без изменения bytes. Worker сверяет extension с authenticated
helper credentials, frozen challenge, actual task PID/start и frozen binding;
после проверки создаёт sealed launch memfd. Перед exec full payload capsule,
manifest и actual sealed config digest должны совпасть. Legacy payload не
получает extension; full payload без него запрещён. Только full System branch
добавляет LANG=C и четыре locators к прежним frozen System env переменным;
profile peer pidfd — отдельный owned duplicate. Точный ff5d0ce Go env parser
ещё запрещает эти прежние три переменные до decoded mode; root/Go должны
согласовать mode-specific frozen binding check. Rust не удаляет legacy env.

NativeRuntime удерживает ProfileRuntime/extension/source payload до worker
KnownClosed. `native_attached` требует frozen attach и exact manifest ACK.
Revoke останавливает issuer; неизвестный cleanup удерживает endpoint, ledger,
payload/resources и reservations. All-empty supervisor recovery переводит
profile в retained retired slot и блокирует новый begin. Только последующий
durable deny replacement/DesiredRules в `BackendRecovery::restrict` вызывает
`confirm_profile_rules_retired`: worker и policy вместе подтверждают KnownClosed.
Ошибка restrict сохраняет retired ledger/resources. Это не выдаёт новый grant
после reconnect.

`Session` остаётся единственным владельцем RemoteLookup. Его один actor loop
обслуживает frozen wire и bounded64 owner operations. FrozenSent хранится только
после actual sendReply; fallback lookup выдаёт SidebandOperation, без synthetic
frozen frame. KnownOwnerProof связывает sourceFlowId/immutable initiator tuple/
scope/subject с original expiry; очередь/refresh не продлевают20ms. Local
не вызывает OS owner lookup и возвращает required=false/ownerNone/fresh0.

`Issuer::open/authorize/cancel_*` — те же методы, которые вызывает production
driver. Driver проверяет exact ACK/hash/id, monotonic sequences, bounded pending
queue и targeted CANCEL до публикации late результата. Refresh снова выполняет
route fence. Grant TTL/freshness пересчитываются при каждой send attempt от
original expiry. Unknown retirement сохраняет grant/ticket и отзывает context;
обычная отмена одного flow сохраняет соседний. DNS class3 через user-flow и
PROBE сейчас не создают service authority: до отдельного trusted service path
они явно закрыты.

`ProfileRoutes` получает Weak на тот же Backend и его runtime; новый backend,
lookup reader или kernel owner не создаётся. Static/DNS rows должны совпасть с
captured routes. Direct numeric route проходит context/source/owner/network
fences, exact marked worker RouteQuery, durable replacement и DesiredRules.
Existing policy сохраняется полностью. Общий cap128 включает static/DNS/private/
LAN/link-control и dynamic rows. Unique BoundTransport разделяет до4096 refs;
последний grant отзывается до durable удаления правила. Ошибка replacement/
retirement делает context Unknown, сохраняет desired journal и custody. Для
ledger до heap allocations зарезервированы384KiB внутри общего8MiB preflight.

### R8: инициаторный tuple и UDP association

Tuple40 всегда local=initiator,remote=ingress. `Tuple::owner_flow` меняет только
family4/6 на kernel AF_INET2/AF_INET6 10. Адреса и порты не переставляются.
Accepted TCP проверяет remote_port=ownedPort и exact compiled loopback ingress;
original protocol должен совпасть с socket protocol. Production socket proof
дополнительно удерживает actual child FD и повторяет PID/start/image,
remote FD identity, socket cookie/inode и accepted endpoint orientation.
Independent `initiator-ingress-r8.json` содержит32001→1080, wrong listener1081,
UDP49152 и foreign49153. Pure owner actor vector различает Known/Unknown.

UDP явно Unsupported: child-owned ephemeral FD, cookie и UDP owner lookup ещё
не связывают сокет с конкретным SOCKS control association. Минимально требуется
issuer-retained связь parent control/source flow → actual UDP socket FD/cookie/
bound endpoint → actual UDP initiator tuple, с отменой на закрытие control.
В ff5d0ce `ProfileAssociateUDP` эта связь private внутри Go; OPEN_INGRESS
передаёт только ingress index/provenance/tuple/original и не предоставляет
независимую association custody Host. TCP owner proof и child assertion её
не заменяют. Нового wire Rust не вводит и UDP готовым не объявляет.

### Local endpoint и точная оставшаяся граница

`CheckedConfig::validate_full_profile(binary,intent,runtime,cancel)` использует
один typed intent, validate, actual retained sources, existing local compiler и
final logging rewrite **до** digest/capsule. Local stage — normal0700 directory,
exact deterministic basenames, retained readonly FDs, type/owner/mode/nlink/
size/hash/identity readback; budget16/64MiB. Check branch получает controlled
asset path, но не Run locators/grants. `LocalSession::start` готовит YNKLOC01,
spawn channel, actual child/image verification до sensitive stdin; issuer
ожидает HELLO после stdin без deadlock. Stop отзывает issuer до terminate/reap,
Unknown сохраняет custody. Local не выдаёт System stamp/OS attribution.

`Launch::configure` остаётся fail closed. Exact source blocker: workspace
`Cargo.toml:11` forbids unsafe_code, а единственный existing safe wrapper
`crates/yonik-nsfs/src/local_parent_death.rs::install_kill_on_parent_death`
не поддерживает child-only FD inheritance. Этот nsfs файл вне writer ownership.
Минимальный требуемый API: безопасный wrapper, принимающий owned четыре FD,
удерживающий их lifetime и снимающий CLOEXEC только в raw pre_exec child,
с прежним fixed parent-death fence. Parent-wide fcntl неприемлем из-за утечки
FD в параллельный exec. Новые dependencies, fork/exec helper и scope обходы
не добавлены. После wrapper root подключает его только в Launch::configure;
legacy spawn/check не должен получать эти FD. Local API возвращает typed
`HostError::Unsupported`. Gate также остаётся закрытым до
installed complete Go consumer proof.

Pure проверка driver использует injected Channel/Authority: synthetic ACK,
два flow, pending cancellation, monotonic outgoing sequence, Known/Unknown,
refresh, receipt kind и rollback/Unknown custody. OS wrappers только компилируются;
tests не вызывают process, proc, NSS, socketpair, systemd или kernel backend.
