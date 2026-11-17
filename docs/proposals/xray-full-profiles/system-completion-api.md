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

Уточнение SOURCE/PURE после root1cc67ed: parser сверён с exact tag
[`go1.27.1`](https://github.com/golang/go/tree/go1.27.1/src/net), прежде всего
`conf.go::lookupOrder`, `nss.go::parseNSSConf`, `hosts.go::readHosts`,
`dnsconfig_unix.go::dnsReadConfig`, `parse.go::{dtoi,file.readLine}` и их тестами.
SHA256 четырёх основных source files закреплены в независимом корпусе
`tests/fixtures/xray-profile-channel-v3/resolver-netgo-1.27.1.json`;
retained upstream sources/tests/VERSION и полный identity manifest находятся
в evidence `p5-netgo-1cc67ed/source-basis`. Проверенные файлы совпали побайтно
с локальным Go1.27.2, но именно Go1.27.1 является source basis.

Поддержанный subset — Linux CGO0/netgo с закрытым env-policy1:
Files/Dns/FilesDns/DnsFiles; повторные `hosts:` дописываются в source order,
source names case-sensitive. NSS разделяет tokens по literal space: внутренний
TAB не превращает `files\tdns` в два sources. Known SUCCESS/NOTFOUND/UNAVAIL/
TRYAGAIN criteria, `!`, return/continue и пустой `[]` разбираются; при CGO0
actions не меняют order. Unknown identifier source не запускает plugin: по
`lookupOrder` он становится DNS только без explicit `dns`; при explicit DNS
он пропускается. Это относится также к resolve/myhostname/mdns, без чтения
mdns.allow, NSS modules или libc. Malformed grammar любого database отвергается;
unknown criteria/actions, source punctuation вне identifier/TAB subset и
приклеенный `[criterion]` остаются typed Resolver error/Unsupported.

Resolv сохраняет search/domain replacement, case/root dot, default search от
captured hostname, first3 valid peers с duplicates/defaultNS, rotate,
single-request(-reopen), use-vc/usevc/tcp, trust-ad и EDNS default.
`no-reload` совместим с immutable snapshot: active revalidation при изменении
source отзывает context, а не перечитывает resolver live. Numeric decimal
options сохраняют Go saturation/clamping (ndots<=15, zero/negative attempts и
timeout ->1); повреждённые numeric suffix/plus, unknown options/directives,
attempts>5, timeout>30s, search>6, выбранный zone/mapped/non-unicast peer и
непредставимые ASCII labels дают отказ, без замены следующим peer.
Строка raw source длиной>=64KiB отвергается до parse reservation: pinned
`file.readLine` иначе прекратил бы чтение из fixed64KiB buffer. Mandatory source
open/stat errors остаются Unsupported; defaults допустимы только из captured
successfully read config, не как fallback на ошибку capture.

Hosts IP lookup сохраняет first-seen lowercase `absDomainName` alias keys,
coalescing и ordered IP duplicates, включая unspecified/multicast data;
строка без alias пропускается до parseLiteralIP. Valid zone/mapped IPv6 с alias
и labels вне frozen asset grammar отвергаются. Wire хранит alias keys и IP,
не отдельную canonicalName первого имени строки или reverse/PTR mapping:
эти операции не получают authority из snapshot alias rows и не объявлены
поддержанными. Limits4096 aliases/16 addresses проверяются до добавления;
legacy test-only `hosts:dns`/nameserver-only parser удалён, тесты вызывают
тот же `resolver_snapshot_data`, что и production capture.
YNKDNS01 bytes/limits, sourceDigest v2/env-policy1, retained source FD/identity,
bounded root-owned resolv links<=4 и sticky stale не менялись. Старый binary
golden сохраняется. Это parser/capture SOURCE/PURE milestone; DNS transport,
stub/bootstrap, libc/NSS compatibility и full P5/runtime readiness не закрыты.

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
обычная отмена одного flow сохраняет соседний. На b04c2c0 DNS class3 через user-flow и
PROBE ещё не создавали service authority: до отдельного trusted service path
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

R10 расширил ownership для Local wrapper. `Launch::configure` теперь передаёт
ровно четыре CLOEXEC owned duplicates в safe
`yonik_nsfs::local_parent_death::install_local_profile_fds(&mut Command,[OwnedFd;4])`.
Canonical env numbers фиксируются до move; parent flags не меняются. Command
удерживает handles в pre_exec closure. Уже существующий fixed parent-death hook
из `BinarySnapshot::command` исполняется раньше FD hook; новый wrapper его не
переустанавливает. Child использует только raw F_GETFD/F_SETFD, Copy flags и
errno-only errors; снимает только FD_CLOEXEC. Любая ошибка запрещает exec.
Launch configure одноразовый даже после ошибки/env_clear. Уже настроенный
Command отвергается до env_clear и до добавления hooks. Fresh Command создаётся
в `process::spawn_profile`, затем configure потребляет его и возвращает opaque
ConfiguredCommand с единственным consuming spawn. Raw Command после configure
не публикуется: удалить locators или добавить ещё один Launch нельзя. Legacy/check вызывают
старый spawn без FD wrapper. Gate остаётся закрытым до installed complete Go
consumer proof; Local wrapper не выдаёт System/flow authority.

Pure проверка driver использует injected Channel/Authority: synthetic ACK,
два flow, pending cancellation, monotonic outgoing sequence, Known/Unknown,
refresh, receipt kind и rollback/Unknown custody. OS wrappers только компилируются;
tests не вызывают process, proc, NSS, socketpair, systemd или kernel backend.

## R10/R12 System extension — Rust implementation, gate закрыт

Уточнения R12 реализованы в Rust producer/consumer; Go counterpart этой extension
и runtime acceptance этим документом не подтверждаются. Независимые synthetic
wire vectors: `tests/fixtures/xray-profile-channel-v3/system-proof-extension-v1.json`.
Тесты используют только fake controls/in-memory state; ioctl/exec/network не запускались.

Подтверждённый gap в b04c2c0: `native_profile_channel.rs::Peer::system/capture`
(1635–1725) читает `/proc/<worker>/exe`; `Peer::socket` (1726–1790) сканирует
чужой fd table и вызывает pidfd_getfd. Fixed
`packaging/systemd/yonik-helper.service:28` оставляет только CAP_NET_ADMIN.
Cross-UID ptrace checks нельзя заменить Root UID, marker/env или session token.
Эти пути не являются рабочим System proof при pinned privileges. Gate остаётся
закрытым; CAP_SYS_PTRACE/packaging/ABI260 не меняются.

### Что уже верифицируется и чего это не доказывает

- `native_bootstrap::verify_pending/RuntimeScopeStamp` проверяют admitted worker,
  owner/kernel namespace custody и frozen binding; `RunRole::into_guard`
  передаёт owning lifetime. Это не текущий Xray executable FD и не flow owner.
- `worker::receive_native_payload` проверяет sealed image/config actual bytes;
  `RunHandoff::exec` (role_handoff.rs284–314) сверяет capsule/config digest, а
  `ProductionPermit::exec_run` (468+) владеет verified transport до actual exec.
  Это существующий trusted code path для доставки image, а не kernel
  аттестация instruction pointer после exec.
- `receive_verified_transport` (402+) уже проверяет ancillary credentials,
  YNKEXT01/challenge/task PID/start/frozen binding. Этот authenticated handoff
  можно удержать для отдельного pre-exec exchange, не меняя frozen frames.
- `KnownOwnerProof::checked` и serial RemoteLookup остаются единственным proof
  actual initiator ownership. Exec delivery/socket custody их не заменяют;
  unchanged tuple, receipt kind/id и original expiry20ms обязательны.

### Exec delivery proof без cross-UID proc

Worker удерживает duplicate существующего authenticated handoff FD до exec.
После native payload/staging, перед `command.exec`, он посылает отдельный
versioned YNKEXC01 record плюс **actual image/config readonly sealed FDs**, которые
использует этот consuming exec path. Helper независимо проверяет credentials
against admitted task PID/UID/start, exact nonce/session/invocation/generation/
epoch, record/config/manifest hashes, FD type/seals/size/hash against retained
WorkerPayload. Затем ACK разрешает только этот pending exec. Replay/другой
binding/лишние rights закрывают всё; Unknown сохраняет custody. Frozen role
record/FD counts и YNKEXT01/ACK не меняются — exchange идёт отдельным сообщением
после существующего payload ACK, на retained authenticated handoff.

YNKEXC01 record256 (big endian): prefix16 содержит
magic8/version u16=1/length u16=256/rights u16=2/reserved u16=0;
nonce32@16,digest32@48,session16@80,invocation16@96,generation8@112,epoch8@120,
taskPID4@128,reserved4@132,taskStart8@136,imageHash32@144,configHash32@176,
manifestHash32@208,imageBytes8@240,configBytes4@248,reserved4@252.
Config hash обязан совпасть с binding digest. ACK40 — YNKEXA01 + SHA256 всего
record. Exactly2 rights: image/config. Один pending exchange, existing admission
deadline, no renewal/replay; никаких owner receipts это сообщение не создаёт.

Результат называется `VerifiedExecDelivery`, а не CurrentImageProof: authority
выведена из source-verified consuming worker exec path + independent sealed FD
readback + same task pidfd/PID/start + последующего HELLO. До включения требуется
review, что между delivery ACK и exec нет alternate exec/spawn path, что
запускается именно проверенный sealed image и что fd/env/config custody exact.
Самопереданный Go image hash/FD без этой цепочки недостаточен. Если contract
требует независимого kernel current-executable measurement после exec, этот
delivery proof его не заменяет: такой режим остаётся Unsupported.

### Минимальная отдельная socket-proof extension

Runtime YNKCAP01 запрещает rights на каждом frame; existing four locators и
YNKEXT01 доставляют только один runtime endpoint. Поэтому нельзя тихо принимать
SCM_RIGHTS в OPEN_INGRESS или использовать pidfd_getfd fallback. Предлагается
отдельный bootstrap exchange **YNKPF001/version1/length128/rights1**, до HELLO:
prefix16, nonce32, digest32, session16, invocation16, generation8, epoch8.
Он доставляет один отдельный proof-channel FD от trusted helper. Все поля
сверяются с sealed launch record, credentials/pidfd; повтор/timeout/неизвестный
format даёт отказ. Старый Go consumer не считается совместимым. Это явная новая
versioned extension для root/Go review, не изменение frozen ABI/четырёх locators
и не разрешение ancillary в runtime frame decoder.

Bootstrap ACK ровно40 bytes: `YNKPFA01` + SHA256 всех128 bytes bootstrap record,
без rights. Helper посылает ровно один bootstrap, принимает exact ACK от admitted
task PID/UID в исходном admission deadline (дополнительно ≤1s). EOF, лишние rights,
wrong digest/peer/replay/timeout закрывают setup. Затем HELLO и runtime frames
не меняются; SCM_RIGHTS в runtime запрещены. Четыре locator env неизменны.

На proof channel admitted Go передаёт accepted socket через SCM_RIGHTS с exact
binding/request/source tuple/provenance. Полученный FD — actual kernel object,
а не новый FlowGrant. YNKSPF01/version1 record192: prefix16
(magic/version/length192/rights1/reserved0),binding80@16,nonce32@96,
runtimeRequestSequence8@128,monotonicProofId8@136,ingressIndex2@144,
provenance1@146,reserved1@147,tuple40@148,reserved4@188. Exactly1 socket FD;
для этой версии только acceptedTCP. Helper сопоставляет exact pending
OPEN_INGRESS sequence/tuple/ingress/provenance один раз, без добавления полей в
старый OPEN_INGRESS. FD/metadata credit резервируется до read/materialization,
pending≤64 с existing deadline; wrong/late/replay proof закрывает все rights.
Runtime и proof channels обслуживаются одним issuer loop; RemoteLookup по-прежнему
имеет единственного serial owner. Proof-channel EOF отзывает context.
Proof может прийти до OPEN: `Rendezvous` удерживает owned FD под exact request
sequence, но не создаёт source/owner/FlowGrant до matching OPEN. Обратный порядок
также допустим. Совокупно pending+ready proofs≤64, queued runtime frames≤64;
128KiB credit до создания очередей/чтения покрывает metadata и один fixed scratch
FD. Первоначальный deadline каждого pending сообщения ≤1s не продлевается другим
сообщением. ProofId строго возрастает; ноль/MAX, duplicate/late sequence и wrap
запрещены. Один `SystemChannel` ждёт readiness обоих FD и revoke Notify, без
нового owner reader или busy polling. Tokio UnixDatagram здесь владеет seqpacket
FD только для readiness/try_io; raw recvmsg сохраняет packet/ancillary grammar.
Порядок binding80 в новой extension: digest32,session16,invocation16,generation8,
epoch8; это явный новый layout, не копирование runtime header128.
Переданный FD — kernel object,
не child assertion о cookie/owner. Helper сам проверяет type/protocol,
getsockname/getpeername, SO_COOKIE/fstat, exact compiled ingress и неизменный
initiator tuple. Для namespace нужна **независимая** связь socket→netns:
SIOCGSKNS на полученном socket FD и сравнение actual nsfs identity с retained
RuntimeScopeStamp namespace. Existing CAP_NET_ADMIN применима только если
подтверждена относительно socket net->user_ns; иначе Unsupported, без новых
capabilities. Узкий safe `yonik_nsfs::socket_namespace::socket_namespace`
реализован в явно расширенном R12 ownership; fixed SIOCGSKNS, type/netns/CLOEXEC,
pure injected controls, без общего ioctl API.
Child-supplied namespace FD рядом с socket FD не доказывает эту связь.

Production callers: `receive_verified_transport` удерживает CLOEXEC duplicate
authenticated handoff до `RunHandoff::exec`; это сделано до `worker::serve_stream`
drop payload stream. Consuming full-profile exec проверяет exact program FD и
`run -c stdin:` args, ставит stdin из actual sealed config, передаёт readonly
duplicates actual image/config и ждёт YNKEXA01. Никакого alternate fallback.
`systemd_worker::start_native` после payload ACK вызывает `receive_exec_delivery`;
он проверяет peer/record/type/seals/hash против retained WorkerPayload, резервирует
executable budget до FD read и передаёт opaque VerifiedExecDelivery bounded queue.
`ProfileRuntime::start_system` удерживает token и его budget в SystemResources
до KnownClosed, включая ошибки bootstrap/HELLO и Unknown. Peer не читает чужой
exe/fd table: System использует retained delivery FD и stamp/pidfd/start/UID.
Local path сохраняет принятые R11 проверки и bootstrap не получает.

После independent socket/namespace verification helper делает обычный fresh
owner lookup инициаторного tuple и связывает flow с FD/cookie, source/provenance,
original destination, scope/branch/chain, expiry/cancel. Socket proof не заменяет
Known owner, optional ACL semantics или FlowGrant. Custody и revoke/cancel
сохраняют прежние правила; один flow не закрывает соседний physical session.

UDP дополнительно требует parent control association → actual UDP FD/cookie →
ephemeral endpoint → actual UDP initiator proof, с cancel при закрытии control.
Только переданного UDP FD недостаточно, чтобы доказать association provenance.
Trusted Probe/DNS paths также не выведены из этого предложения. Все эти gates
остаются закрытыми до отдельных producers/consumers и review.

## Service issuer после R12: exact c75a8e9 counterpart

Go source pin: c75a8e94be35c64c490706ce5c20ab256d9dbbb4, implementation API
332–430. Byte-exact DATA vectors перенесены в
`tests/fixtures/xray-profile-channel-v3/go-c75a8e9-service-grants.json`.
Wire layout не расширяется: PROBE8, AUTHORIZE class3 prefix20, GRANT56,
mappingVersion3/tableCount11, frozen ABI260 и four locators сохраняются.
Разрешённое Go convention уточнение: PROBE objectId=0 initial, live service
grantId для refresh; exact purpose/index/subject/resolver обязателен.

`run_issuer` вызывает `Issuer::service` для PROBE, отдельно от user AUTHORIZE.
Purpose1 выводит exact URL scheme/host/port/path, admitted subject и TCP root
scope/actual branch mask из table8+typed scope rows. Никакого caller URL или
arbitrary scope constructor. Purpose2 требует table2 physical hostname endpoint,
его actual owning subject и table5 system snapshot resolver (subject=None,
sourceDigest!=0). Probe URL из table8 этим endpoint index не подменяется.
Scope/branch/carrier/chain routes обходятся до terminal physical leaves; chain
remote не попадает в direct exceptions. Numeric Direct проходит тот же durable
ProfileRoutes replacement/fence и bounded refcounts. Domain physical/result
handoff остаётся Unsupported до independent authenticated RRset provenance.

Service grants хранятся отдельно от user FlowGrant, но IDs, общий grant cap,
dynamic byte credit, request cancellation и expiry общие. Service GRANT всегда
sourceFlow=0,required=false,ownerFresh=0,receipt=None. Это не OS attribution и не
снятие mandatory constraints: SystemAuthority проверяет retained runtime/image
scope, а ProfileRoutes::service независимо сверяет exact retained manifest,
active SessionArtifact, source/resolver guards и captured routes в serial backend.
LocalAuthority проверяет exact child и retained Prepared sources. До ACK нет
готового consumer; require_consumer и capability остаются false.

User DNS AUTHORIZE class3 требует live private sourceFlow, immutable original,
numeric exact resolver peer, canonical query, NONE subject/chain/stream/scope,
branch0 и OwnerNone. В System новый serial Known observation остаётся ≤20ms;
service grant ни на этом входе, ни при refresh не заменяет source flow.
Provider DNS detour выводится из resolver row subject и checked chain matrix,
без подмены system DNS. Retained resolver snapshot проверяется source fences;
его digest в row не является самостоятельным peer proof. Loopback/unspecified/
multicast DNS peer пока Unsupported: verified stub bind отсутствует. Existing
resolved Varlink ResolverPeer из resolver/socket.rs — proof другого Unix endpoint,
не proof UDP53, и не используется как замена. Numeric non-loopback DNS route
проверяется against independently captured/revalidated SessionArtifact route;
actual socket/RRset consumer guards обязательны и readiness этим не доказана.

## R14 System user DNS interop: attribution не обнуляется

Независимый Python struct.pack vector:
`tests/fixtures/xray-profile-channel-v3/system-user-dns-grant-r14.json`.
Содержит full AUTHORIZE/GRANT frames, refresh, Local/service controls и negatives.
Это synthetic DATA без owner authority. Production Rust authorizer не изменён.

GRANT56: status1@0,class3@1,required1@2,reserved0@3,grantId11 u64@4,
private sourceFlow7 u64@12,lease14ms u32@20,policyRevision23 u64@24,
ownerFresh15000000ns u64@32,ownerKind2(SidebandOperation)@40,reserved7@41,
ownerReceiptId9 u64@48. Header128: sequence31,replyTo20,objectId11;
session[1]*16,invocation[2]*16,digest[3]*32,generation4,epoch5.

Body56 hex:

```text
01030100000000000000000b00000000000000070000000e00000000000000170000000000e4e1c002000000000000000000000000000009
```

Refresh сохраняет private flow7/revision23/live grant11, replyTo21;
lease4ms/fresh5000000ns, ownerKind1(FrozenSent)/id10. Это второй допустимый tagged receipt,
а не утверждение, что synthetic fixture когда-либо была FrozenSent на transport.

```text
01030100000000000000000b000000000000000700000004000000000000001700000000004c4b400100000000000000000000000000000a
```

`required=false/fresh=0/owner=None` допустимы для service flow0 и Local user DNS;
они НЕ являются System user DNS response. Go R14 publishService correction
`fb206733`, сохранённый в `ff5b348`, разделяет эти ветки, сверяет private
flow/revision/pending reply и live refresh ID; R15/R16 закрыли SOURCE-совместимость.
Zeroed System owner tail, missing/over20ms freshness, None/unknown owner kind,
zero owner ID, foreign binding/objectId и truncation отвергаются Rust codec.
Wrong private flow/revision/pending sequence/refresh ID оставлены wire-valid
negative vectors: отказ обязателен в pending-consumer correlation, decoder не
может сам доказать private request authority. Actual Rust producer regression
`r14_actual_system_user_dns_producer_preserves_private_flow_revision_and_owner_tail`
берёт flow/revision из INGRESS_REPLY и проверяет System GRANT от run_issuer.

Existing `system-proof-extension-v1.json` остаётся exact PF001/PFA01/SPF01 vector;
PF001=128/rights1, ACK ровно40 `YNKPFA01`+SHA256 всего bootstrap. Runtime rights0,
четыре locators и frozen records не менялись. R14 UDP proposal ниже НЕ меняет v1.

## UDP proof v2: конкретный R14 draft для source review, НЕ implementation

Ни один UDP record/decoder/factory из этого раздела не реализован. V1 остаётся
TCP-only: `SocketRecord::encode` принимает protocol6, `Peer::socket` отказывает
provenance3. Нельзя послать UDP в старый YNKSPF01 или принять его как TCP proof.
Изменение wire допускается только после root sourcecheck этого draft и Go caller.

### Согласование версии и точки подключения

Предлагается отдельная версия proof extension: bootstrap `YNKPF002`128,
version2/length128/rights1/reserved0; оставшиеся nonce/binding поля как PF001.
ACK ровно40 `YNKPFA02`+SHA256 bootstrap, rights0. V1 ACK не принимается за v2.
Frozen runtime/ABI260/YNKROLE1/YNKEXT01/YNKLOC01 и четыре locators неизменны;
runtime frames по-прежнему rights-free. V2 proof channel понимает старый TCP
YNKSPF01 и явно перечисленные ниже UDP record kinds. Unknown kind/version,
duplicate/late/replay/wrap/EOF/лишние rights закрывают pending rights и revoke.
V1 peer не получает UDP capabilities; нет fallback с ошибочного v2 на Allow v1.

System caller: `ProfileRuntime::start_system → send_proof_bootstrap →
SystemChannel`; negotiate v2 только для готового установленного consumer.
Local caller: `host/local_profile_channel::Launch::start → start_local`:
image/actual child verified, bounded stdin delivered, затем bootstrap ACK/HELLO.
Ожидание ACK до Local stdin запрещено. Local mode исходит из consumed trusted
YNKLOC01/Host peer; он не System proof и не mode из env. Legacy/check ветка не участвует.

### Границы и credits до effects

- Active associations≤8; общий pending runtime+proof ledger≤64. Все counters
  ненулевые, monotonic, MAX/wrap запрещены, tombstones до конца invocation.
  Общий runtime/proof tombstone ledger ограничен min(negotiated caps[7],256)
  записями на invocation, совместно для всех associations и видов operations.
  Credit будущего tombstone и его metadata резервируется до socket/packet effect,
  не после завершения. Повторный переход той же operation не расходует вторую
  запись. При исчерпании новые effects запрещены; evict/reuse ID не допускаются.
  Reservation становится retained tombstone при любом terminal outcome;
  credit освобождается только после KnownClosed всей invocation. Этот bounded
  draft не обещает неограниченное число datagrams за invocation; безопасная
  compaction/watermark retirement потребует отдельного контракта до оптимизации.
- Datagram целиком, включая SOCKS UDP header, ≤65507 bytes. Нет fragmentation
  reassembly: RSV=0, FRAG=0, ATYP только IPv4/IPv6/domain; порт ненулевой;
  domain ASCII canonical≤253, header length10/22/7+nameLen (≤260).
  Несогласованная длина, zero-length/truncation/CTRUNC/unknown ancillary — отказ,
  packet не forward-ится. Исходный Destination парсит issuer из kernel bytes.
- На association один Peeked/ReadPermit, один exclusive Go receiver. Go не
  вызывает recv/peek до ReadPermit; issuer после permit не consuming reader.
  Cancel/revoke/close ждут join reader. Raw UDP FD не экспортируется к handlers,
  transport factories или callback. Запрещены recvmsg-конкуренты и socket-option
  mutation. У Go wrapper только logical receive/close; фактический socket FD
  двунаправленный, ограничения не выдаются за kernel read-only descriptor.
- **Один permit не ограничивает kernel queue.** До передачи duplicate factory
  задаёт SO_RCVBUF и проверяет effective readback≤128KiB, без SO_RCVBUFFORCE;
  включён overflow observation. Перед peek/permit readback повторяется.
  UDP_GRO off/readback обязателен; ancillary whitelist — не более
  одного SO_RXQ_OVFL u32, прочие ancillary отвергаются. Изменение overflow counter
  либо неизвестная форма metadata не получают consuming success.
  Очередь ядра может содержать несколько datagrams; каждый проходит отдельный цикл, FIFO
  head не считается доказанно consumed по одному ACK. Overflow/неизвестная
  queue/read semantics — Unknown/revoke. SO_RCVBUF — accounting threshold,
  не строгий packet-count/memory theorem; абсолютная kernel-memory граница
  этим API не доказана и не включается молча в decoded-metadata preflight.
- До socket/dup/SCM materialization резервируются association slot, обе стороны
  FD custody (control TCP+namespace, issuer relay+namespace, Go duplicate,
  pending rights scratch: шесть descriptor credits на association),
  один physical socket slot из existing128 и pending slot из existing64.
  До первого peek/read резервируются **оба** buffers65536 и metadata2048 на
  association: 133120 bytes; восемь —1064960 bytes. Это часть существующего
  aggregate8MiB preflight, не дополнительный budget; оставшиеся tables/frames/
  ledgers/SourceFlows тоже учитываются. До увеличения flow set — отдельный
  SourceFlow/FD/metadata credit; ≤256 flows/association и existing global caps.
  Эта пара buffers принадлежит ровно одному packet cycle от первого peek
  до завершения GRANT/отказа и освобождения private payload. ConsumedMatch
  сам по себе buffers не освобождает. Следующий peek/permit запрещён, пока
  previous payload не передан в отдельно credited downstream flow после GRANT
  либо не уничтожен при отказе/cancel. Сохранение payload после передачи требует
  downstream buffer credit до передачи; association buffers нельзя alias/reuse.
  Задержанный AUTHORIZE не позволяет начать второй cycle или overwrite buffers.
- Internal deadline каждого packet: min(request receipt+1s, session lease,
  control lifetime). Никакое ожидание queue, новый permit, ACK или renewal его
  не продлевает. Owner20ms — отдельный первоначальный expiry свежего lookup;
  его нельзя продлить packet lease. Control close/session revoke/EOF будят loop.
  Kernel data readiness обслуживает тот же issuer loop, без owner reader/poll loop.

Если root требует абсолютный hard bound kernel queued datagram count/memory,
данный SO_RCVBUF механизм его не доказывает: v2 admission остаётся закрытым до
отдельного проверенного ограничения. Это конкретный review limit, не Allow
при переполнении. Ни один overflow не превращается в новый allocation/grant.

### Точные предлагаемые records

Все integers big endian. Общий UDP prefix128: magic8@0,recordVersion u16=1@8,
length u16@10,rights u16@12,reserved0 u16@14,binding80@16
(digest32/session16/invocation16/generation8/epoch8),nonce32@96.
Binding/nonce сверяются с retained admitted run/manifest, а не с child assertion.
Runtime sequence и proof-operation/packet/permit/association IDs — разные namespaces.

| Magic / length / rights / direction | Поля после prefix128 |
| --- | --- |
| YNKUCS01 /192/1 G→I | operation8@128,proofId8@136,ownedSocksIngress2@144,command3@146,reserved1@147,initiatorTcpTuple40@148,reserved4@188; actual accepted TCP control FD |
| YNKUCA01 /160/0 I→G | operation8@128,controlSourceId8@136,actualControlCookie8@144,remainingNs8@152 |
| YNKUAQ01 /160/0 G→I | operationId8@128,controlSourceFlow8@136,expectedControlCookie8@144,reserved8@152 |
| YNKUAC01 /192/1 I→G | operation8@128,controlSource8@136,associationId8@144,actualSocketCookie8@152,family1@160,protocol17@161,reserved2@162,port2@164,reserved2@166,address16@168,reserved8@184 |
| YNKUPQ01 /160/0 G→I | association8@128,operation8@136,controlSource8@144,reserved8@152 |
| YNKURP01 /256/0 I→G | association8@128,packet8@136,permit8@144,cookie8@152,initiatorTuple40@160,datagramBytes4@200,headerBytes2@204,recvFlags2@206,fingerprint32@208,remainingNs8@240,reserved8@248 |
| YNKUCM01 /256/0 G→I | те же association/packet/permit/cookie/tuple/length/header/flags/fingerprint offsets; runtimeOpenSequence8@240,reserved8@248 |
| YNKUMR01 /192/0 I→G | association8@128,packet8@136,permit8@144,runtimeOpenSequence8@152,status1@160,reserved7@161,remainingNs8@168,reserved16@176 |
| YNKUCQ01 /160/0 I→G | association8@128,closeId8@136,controlSource8@144,reason2@152,reserved6@154 |
| YNKUCR01 /192/0 G→I | association8@128,closeId8@136,lastPacket8@144,pendingFlowCount4@152,status1@156,readerJoined1@157,goDuplicateCount2@158,originalCookie8@160,retiredRuntimeSequence8@168,reserved16@176 |

YNKUCS01 несёт ровно1 actual TCP FD, YNKUAC01 — ровно1 issuer-created UDP FD;
остальные records rights0. YNKUCS01 не совместим с YNKSPF01: это отдельный
control-only admission, не user OPEN с выдуманным wildcard original Destination.
ControlSourceId выделяется из общего non-reused source ID counter, но находится
в отдельном typed control ledger без outbound destination; AUTHORIZE не может
найти его как User SourceFlow. Command3 проверяет source-verified SOCKS handler;
одно это поле не authority. Actual TCP type/endpoints/cookie/namespace проверяет
issuer, System получает свой fresh Known control proof. Нельзя заменить UDP
source attribution этим control proof. Control close/EOF отменяют все association
permits; сигнал отмены не создаёт Allow. На control допускается одна association.
Tuple40 остаётся initiator→ingress, TCP orientation не меняется; UDP remote port —
actual issuer-bound ephemeral port, не owned SOCKS listener1080. Addresses IPv4
имеют zero tail. recvFlags bits0=TRUNC/1=CTRUNC, прочие0; success требует flags0.
YNKUMR01 status=Matched1/Deny2/Unknown3; Matched **не GRANT**, его reserved fields
не содержат sourceFlowId/grantId. YNKUCR01 status=KnownClosed1/Unknown3.
remainingNs≤1000000000, sender/receiver уменьшают по elapsed/RTT, не обновляют deadline.
Для close lastPacket=0 допустим только до первого packet; retiredRuntimeSequence —
watermark, не разрешение переиспользовать IDs. Retry не создаёт новый permit.

Fingerprint32 = SHA256(domain `YNK-UDP-PACKET-v1\0` + binding80 + nonce32 +
associationId8 + packetId8 + permitId8 + cookie8 + tuple40 + datagramBytes4 +
**весь datagram**, включая SOCKS header). Hash не логируется и не credential.
Host считает его из actual MSG_PEEK bytes; Go пересчитывает после actual recvmsg,
не копирует из permit. Metadata/namespace FD/cookie/child ACK по отдельности не
доказывают association или ownership.

### Состояния и consuming match до GRANT

1. `admit_control → create(controlSource) → Bound/Delivered`: issuer проверяет retained actual
   TCP SocketHold/cookie и live control, создаёт **свой** loopback UDP socket,
   удерживает namespace/FD, назначает association, отдаёт Go duplicate. Child
   не выбирает port/cookie/namespace. Factory bind — IPv4 127.0.0.1:0;
   tuple remote — actual port, IPv4 zero tail, без wildcard/dual-stack bind.
   ATYP IPv6 target не требует IPv6 relay. Это resource delivery, не user authority.
2. `peek(operation) → Peeked(packet)`: после credits/deadline issuer делает
   bounded MSG_PEEK, сам получает actual peer/flags, парсит original, сохраняет
   полный fingerprint и immutable provenance. Пустая queue ждёт readiness до
   того же deadline. Неустановленная namespace/peer связь даёт Unsupported.
3. `permit(packet) → ReadPermit`: выдаётся YNKURP01; producer передаёт только
   один outstanding permit. Go private reader потребляет ровно один datagram,
   проверяет cookie/bound endpoint/flags/peer/length/header и свой fingerprint.
   Payload пока остаётся private pending buffer, не dispatcher/outbound.
4. `consumed(YNKUCM01) + OPEN → ConsumedMatch`: один issuer loop сопоставляет
   actual-read receipt с retained Peeked tuple/original/bytes/hash и точным
   runtime OPEN sequence/provenance3. Каналы разные: OPEN before receipt и receipt
   before OPEN оба bounded pending; send order не считается receive order.
   Duplicate/foreign/late/mismatch не получает grant. Child receipt допустим
   только от source-verified exclusive actual-recv producer; echo permit hash
   или произвольный ACK не consuming proof.
5. `authorize(matched source, decision) → Grant`: лишь после ConsumedMatch
   проверяются fresh **UDP** initiator proof, original target, manifest policy,
   scope/branch/chain и durable numeric route fence. System требует собственного
   UDP Known observation≤20ms; TCP Known его не заменяет, retained control
   principal PID/start/executable должен совпасть. Local required=false не
   получает OS attribution; actual datagram proof независим от TCP, mandatory
   constraints не обходятся. Если они требуют недоступный proof — Unsupported.
   INGRESS_REPLY только создаёт private original flow; forwarding требует
   existing AUTHORIZE/GRANT19. До последнего match/GRANT **никаких forward/send**.

Relay socket — **logical** ingress resource; его reader остаётся Receive/Close/Join.
Outbound UDP использует отдельные D→C→chain checks/FlowGrant и guarded physical
factory; relay FD нельзя использовать для outbound target или выдать
association/control credential за outbound grant. Единственное разрешённое
обратное использование — закрытый ingress-response sink ниже.
SourceFlow связывает association+packet+actual UDP tuple+original, не TCP original.

### Обратный SOCKS UDP response без расширения wire

Private response sink использует тот же retained relay duplicate только для
ответа в существующий user flow. Это duplex-сторона принятого ingress, отдельной
issuer-send операции и нового wire selector/ACK не требуется. Constructor sink
доступен лишь после ConsumedMatch и private provenance3 receipt с class1 GRANT;
association/control/service grant сам по себе sink не создаёт.

- Адресат send — immutable initiator endpoint из actual UDP tuple этого receipt.
  Caller не передаёт destination, FD, namespace, cookie или произвольный WriteTo.
  TCP control tuple не заменяет UDP initiator. Никакого connect/dial через relay.
- Response context сохраняет exact sourceFlow/binding/generation/revision и его
  live logical grant bundle. Перед каждой отправкой действуют существующие
  cancel/expiry/renewal и System Known freshness fences; grant соседа не подходит.
  Долгое ожидание upstream response не продлевает исходный owner proof.
- Sink принимает только response соответствующего guarded downstream flow.
  На текущем numeric milestone SOCKS response endpoint обязан совпадать с его
  checked numeric target; payload.UDP не может выбрать другой адрес. Hostname,
  alternate endpoint или unsolicited response без отдельного proof запрещены.
  SOCKS header создаётся внутри sink, FRAG=0; raw datagram API не экспортируется.
- Buffer/byte/send-task credits резервируются до encoding/allocation/send в общем
  bounded budget. Отдельных неограниченных очередей или goroutine на packet нет.
  Передача request payload downstream и владение response buffers учитываются
  раздельно; новый Peek не освобождает ещё используемый response buffer.
- Cancellation/deadline охватывают manual nonblocking send и ожидание writable.
  Cancel одной association не закрывает соседей. После partial/неопределённого
  send нет автоматического retry; результат обрабатывается как terminal error.
- Close сначала запрещает новые response sends и отменяет ожидающие, затем
  CloseAndJoin ждёт все send/read/downstream tasks и actual duplicate close.
  До этих fences UCR KnownClosed запрещён; ошибка сохраняет sticky Unknown,
  retained custody/credits и прежние supervisor/durable retirement требования.

Pure caller regressions должны отвергать отправку до match/grant, чужой receipt,
подмену tuple/response endpoint, expired/cancelled grant, исчерпание credits и
send после Close; delayed send обязан задерживать KnownClosed. OS send wrapper
пока проверяется только компиляцией. Readiness gates и wire bytes не меняются.

### API завершения и доказательство закрытия duplicate

Предлагаемые private точки Rust в уже scoped модулях (пока не symbols):
`AssociationIssuer::create/peek/read_permit/consumed_match/authorize/retire`;
entrypoint — `SystemChannel/Peer::socket`, parent lifetime — `SourceFlow`;
Local factory — `host/local_profile_channel`. Go private
`AssociationReader.ConsumePermit/CloseAndJoin` должен владеть единственным
duplicate, payload не выходит до match и GRANT. Закрытие выдаёт typed
`GoDuplicateClosed` только после actual FD.Close success, receiver join,
pending-buffer retirement и закрытия всех принадлежащих association flows.
Этот constructor/consumer требует source review/installed-image gate; сам
YNKUCR01 со словами count0 не является достаточным proof.

`retire` сначала линейно запрещает новые permits/grants, отменяет waiters и все
SourceFlows/derived DNS/FlowGrants, выполняет existing durable rule retirement,
затем ждёт matching GoDuplicateClosed и закрывает issuer relay/namespace custody.
KnownClosed возможен только при: exact binding/closeId/cookie, actual Go duplicate
closed и reader joined, обе pending очереди пусты, все association flows и route
refs KnownClosed, issuer close подтверждён. `issuer.close()` сам по себе **не
отзывает Go duplicate**. Успешный arbitrary child ACK не освобождает FD credits.

Любой close error/timeout/недоказанный duplicate/непустой flow set ⇒ sticky Unknown,
context revoke, ledger/resources/credits остаются в existing retired runtime/
supervisor custody. Late ACK не очищает Unknown и не повторяет raw Close. Только
existing trusted verified unit/cgroup-empty (System) либо exact child reap/pidfd
death (Local), плюс durable retirement, могут завершить recovery/free. Закрытие
одной KnownClosed association не закрывает соседние logical flows/physical pools.

System factory независимо сравнивает actual socket→nsfs identity с retained stamp
через approved SIOCGSKNS. Namespace mismatch — Unsupported, без setns/new caps.
Local factory работает normal Host без daemon; SIOCGSKNS privilege не предполагается:
нужен retained own-thread namespace-at-creation proof и source-checked no-setns
factory. Child namespace FD вместо этого proof не принимается; невозможность
связать namespace — Unsupported. Ни factory, ни wire v2 до root review не включены.

### Rust SOURCE/PURE milestone UDP-v2 после R16

`profile_channel::udp_v2::{Record, Packet}` — fixed-size private DATA codec всех
десяти records таблицы выше. Decode сначала проверяет exact length/direction/rights,
затем canonical re-encode проверяет reserved bytes, binding/nonce и bounded fields.
Никаких allocations при decode. Независимый Python `struct.pack/hashlib` corpus:
`tests/fixtures/xray-profile-channel-v3/udp-proof-v2.json`; содержит bootstrap,
ACK, все десять records, whole-datagram fingerprint с различными TCP listener1080,
initiator32001 и UDP initiator32002/relay49152. Mode/authority из этих DATA не выводится.

`helper/native_profile_channel::AssociationIssuer<O: UdpOperations>` — настоящий
private issuer state, используемый production `SystemChannel` v2 dispatch и pure
injected operations. `handle` принимает Control/Associate/Peek/Consumed/Closed;
`progress/tick` обслуживаются тем же issuer loop через Tokio readiness, без нового
owner reader. `bind_source/check_grant/granted` разделяют matched original flow,
fresh UDP principal и actual successful runtime publication. `retire/cancel_flow`
удерживают relay/buffer/namespace custody; canonical Known ACK без независимого
`duplicate_closed` receipt не освобождает resources. Ошибки readiness/deadline
делают Unknown sticky и revoke; поздний ACK не восстанавливает issuer.

`InvocationHistory` — одна история на invocation для runtime sequence, proof
operation и заранее reserved close ID; общий cap `min(caps[7],256)`, без eviction.
Control IDs берутся из общего source counter, но хранятся в отдельном typed
ledger, без fake original destination/UserSourceFlow. Pair budget133120/association
занят до separately credited payload retirement; сам GRANT не освобождает buffer.
Второй Peek/Permit до этого возвращает Busy без socket/read/overwrite effect.

Production adapters скомпилированы, но не исполнялись: `KernelUdpOperations`
удерживает actual TCP FD/cookie/nsfs, использует существующий serial OwnerEndpoint;
`host/local_profile_channel::create_udp_relay` создаёт только normal Host loopback
socket с own-thread namespace custody. `yonik_nsfs::socket_namespace` экспортирует
только fixed `prepare_profile_udp/inspect_profile_udp/peek_profile_udp`, включая
RXQ_OVFL whitelist, truncation flags, GRO=0 и bounded receive-buffer readback.
Ни generic ioctl API, ни unsafe в yonik-linux, ни новые capabilities не добавлены.

**Admission остаётся закрытым.** `profile_proof_setup` выбирает v1, пока
`udp_v2_consumer_ready` возвращает Unsupported. Нельзя включить v2 только сменой
флага: `KernelUdpOperations::payload_retired/duplicate_closed` также закрыты до
source-verified Go ConsumePermit/CloseAndJoin counterpart. `consumed` ещё не
предоставляет самостоятельный consuming proof. Требуются actual provenance3 OPEN
adapter в `Peer::socket` с bounded OPEN↔Consumed rendezvous, общий runtime+proof
pending/FD-credit accounting до materialization, cancellation всех association
flows с durable rule retirement и передача Unknown relay ledger в supervisor/
exact-child retired custody. Local session пока не negotiates v2. Эти endpoints
не объявлены готовыми, user/DNS/Probe authority и gates не ослаблены.

Это bounded initial contract. После исчерпания общей истории новые effects
закрыты; безопасная watermark compaction и long-lived UDP readiness не доказаны.

### Следующее Rust подключение после d79a26fc: SOURCE/PURE, gates false

`Rendezvous::udp_proof/next/take` теперь сопоставляет provenance3 OPEN с actual
Consumed metadata в обоих порядках. Original, tuple, ingress и первоначальный
deadline совпадают побайтно; метаданные берутся из issuer Peeked cycle. На match
`SystemChannel::receive_proof` удерживает собственные relay/nsfs duplicates и
private `UdpBinding`, которые через `Peer::socket` попадают в `SourceFlow`.
`Authority::bind_ingress` сравнивает **actual UDP Known receipt** с retained TCP
principal; повторный lookup для подмены receipt или продления20ms не выполняется.
`Capsule::validate_associated_request` проверяет также immutable original.

`SidebandCredits` общий для runtime frames, proof frames, delivered/queued frames
и outstanding packet cycles: pending≤64, descriptor credits≤64. Это более
консервативный descriptor cap; association по-прежнему максимум8, шесть FD credits
перед factory/duplicate. Перед recvmsg резервируются pending1 и ancillary scratch16;
перед runtime read — pending1. Namespace/relay SourceFlow duplicates и временный
namespace probe имеют credit до effect. `DeliveryCredit` сохраняется после read
до фактической обработки/ответа, поэтому drain queue не образует второй budget64.
Пулы не расширяют aggregate8MiB и invocation tombstone256, не вытесняют записи.

`Channel::maintain` вызывается из `run_issuer` и `drain_before_publication`.
Actual control EOF запускает `AssociationIssuer::retire_control`, отменяет только
его SourceFlows через настоящий `Issuer::cancel_flow` и existing durable
`RouteAuthority::release`; ошибка сохраняет flow/grant/FD refs и Unknown custody.
Pending/ready proof и queued OPEN соответствующего actual relay endpoint
отменяются без изменения watermarks. ControlSource не принимается за user source
в runtime CANCEL. Закрытый control не регистрируется в readiness wait повторно.

Runtime GRANT success отмечается только после actual successful send. Runtime
Deny/known cancel отмечает terminal packet outcome; buffers остаются занятыми.
**Без нового wire:** следующий authenticated Peek служит release receipt только
для source-reviewed exclusive Go producer, который уже передал payload в
отдельно credited downstream flow после GRANT либо уничтожил его после отказа.
YNKUCR01 принимается как duplicate-close receipt только под тем же pinned
producer contract после CloseAndJoin, при пустом flow set и exact close/cookie.
Произвольный child ACK/Peek сам по себе не является этой authority.
`KernelUdpOperations::ready` требует одновременно закрытые сейчас
`udp_v2_consumer_ready` и `require_consumer`, плюс peer revalidation. Нельзя
открывать эти gates до source/parity проверки фактических Go release/close
producers и installed-image binding. Это конкретное требование к Go counterpart;
здесь не заявляется, что его source proof уже получен.

`ProfileRuntime::worker_closed` вызывается supervisor только после existing
all-empty fence; `rules_retired` — из backend durable retirement confirmation.
`ClosureFence` требует обе границы, прежде чем Drop освобождает boxed issuer,
UDP ledger, buffers и descriptors. Ошибка rules confirmation оставляет
`retired_profile` на месте. Local использует отдельное `confirmed_closed` после
exact child cleanup; System не может пройти через Local confirmation. Local v2
negotiation по-прежнему закрыта, нормальный Host factory сохранён.

Wire bytes/ten goldens/ACK hash d79a26fc не изменены. Никакие OS wrappers этого
подключения не исполнялись. До общей Go compatibility, service proof и production
acceptance полный P5/long-lived UDP readiness не заявляются.

### Внутренняя negotiation после root13a0bc26

System caller теперь требует `Peer::verified_udp_producer` после получения
VerifiedExecDelivery и до proof channel/bootstrap; `send_proof_bootstrap`
принимает private `VerifiedUdpProducer`, а не caller version/bool. Его `setup`
выбирает только PF002/PFA02 для exact launch binding; mismatch возвращает ошибку
без downgrade. KernelUdpOperations удерживает этот же proof и использует его
в ready/payload_retired/duplicate_closed. Public require_consumer не изменён.
Local start_local вызывает тот же installed-proof preflight после actual child
verification и до actor/HELLO. Local v2 exchange пока не завершён.

Конкретный blocker: `Peer::verified_udp_producer` не имеет legitimate production
constructor. Нужен trusted installed builder attestation producer, связывающий
accepted Go consuming/CloseAndJoin contract с actual executable identity,
sealed final config digest, manifest и exact launch/session/invocation/epoch.
Точки потребления: start_system после Peer::system и start_local после
Peer::local. BinarySnapshot/VerifiedExecDelivery доказывают custody, не current
image measurement. Adapter JSON/source hash/ACK/env не создают attestation.
Поэтому текущий constructor возвращает Unsupported до negotiation. Private
synthetic proof в pure tests проверяет только выбор wire/receipt branches;
он не production installed-image proof и не закрывает blocker.

Go native-full-profile-implementation.md actor/producer contract0ea9495 и root
pregrant correction da1c80b приняты как SOURCE prerequisite. Private payload
sniffing остаётся Unsupported, metadataOnly не даёт чтения payload. Ready gates,
Local v2 exchange и installed-image acceptance нельзя объявлять завершёнными
на основании этих Rust synthetic vectors.

### R26: минимальный trusted build/install contract — предложение

Принятая модель допускает proof происхождения exact запускаемого образа через
доверенный consuming launcher; непрерывное current-image measurement после exec
не требуется и не заявляется. Hostile same-UID вмешательство и произвольный exec
вне reviewed producer contract этим механизмом не покрываются.

Предлагается registry schema2 с optional `native_profile_producer` для Xray;
schema1 сохраняет legacy поведение без producer authority. Bounded typed record
содержит contract/version, accepted patchset/source digests, builder/toolchain/
build-input digests и final ELF digest. ELF digest обязан совпадать с entry.sha256
и actual retained/sealed executable. Unknown/missing contract, неподдержанный
patchset или mismatch запрещают producer proof. Build record не содержит заранее
вычисленных session/config/manifest значений.

Builder выпускает evidence после source/pins/build проверки. Authority появляется
только после установки доверенным поставщиком в existing root-owned
`/usr/lib/yonik/engines`, с прежними path/NOFOLLOW/ownership/mode guards.
Пользовательский JSON/env/engine-dir manifest/caller hash этого не заменяют.
Новая подпись/capability не требуется; фактическая установка сейчас не выполняется.

Registry возвращает opaque image-contract proof вместе с checked snapshot.
Launcher связывает его с final config digest, manifest и всем LaunchRecord;
System сверяет VerifiedExecDelivery, Local — actual retained executable и
consuming child path. Только эта совокупность mint-ит private VerifiedUdpProducer.
Mismatch не выбирает v1 fallback. Compile-only provenance не является runtime PASS;
public require_consumer/capabilities/builder readiness остаются закрытыми.

Дополнительные source точки: `helper/registry.rs` (schema/opaque proof),
`host/binary.rs` (связь image-contract с sealed custody), pure tests и existing
`tools/build_native_adapter.py`/tests. Пользователь разрешил оба дополнения:
registry/binary/builder и DNS caller-файлы с тестами. Negative controls: legacy/no-contract, untrusted
record, wrong ELF/patch/contract/launch/config/manifest; positive exact-image
binding проверяется без OS exec.

### Реализация protected producer binding после4ea6c087

Предыдущий R26 blocker superseded принятым trusted consuming-launcher contract.
Registry schema2 принимает optional `native_profile_producer`, schema1 не выдаёт
такой authority. Record имеет поля `contract="yonik-xray-profile-udp-v2"`,
`version=1`, `source_commit`, `source_sha256`, `patch_sha256`, `builder_sha256`,
`toolchain_sha256`, `build_inputs_sha256`, `elf_sha256`; digests — bounded
lowercase hex64/nonzero. Source commit закреплён на26.10.31; patch allowlist
закреплён root8c5fa41 на patch205b5337… после DNS review R27. Следующий patchset обязан
пройти root source review и обновить allowlist; semantic contract и exact
artifact digest не смешиваются. Наличие этого record не означает full readiness.

Production record читается только через existing protected root path walk,
NOFOLLOW/uid0/mode/nlink/size guards. `ProducerRecord::validate` private;
`ImageContract` opaque, без Deserialize/public constructor. Registry snapshot
прикрепляет contract к checked sealed BinarySnapshot; public user-path load
оставляет contract=None. System связывает protected entry hash с opaque
VerifiedExecDelivery, уже проверившим actual retained sealed image/config;
повторная полная копия executable для этого не нужна. Это consuming custody,
не continuous current-image measurement.

`Peer::verified_udp_producer` проверяет exact retained LaunchRecord, config hash,
capsule mode/manifest и image-contract, затем mint-ит private token. Local
вычисляет config hash из тех же immutable checked bytes, которые caller пишет
в stdin, и удерживает sealed config memfd до cleanup. Producer absence запрещает
Local spawn до configure/inheritance; legacy/check path producer не получает.
Local normal Host вызывает PF002/PFA02 exchange в dedicated owner thread;
parent сначала проверяет actual child и продолжает bounded stdin независимо
от ACK, затем owner ждёт HELLO с exact Local mode. Четыре locators и frozen FD
counts не изменены. Нет privileged Local daemon/System attribution.

Builder `--experimental-profile --engine xray --compile-only` требует готовый
offline clean source, применяет codec+full patch с exact source/callsite pins,
проверяет полный source tree/modules до/после build, исключает inherited
Git/loader overrides, сохраняет hashes actual Go driver/compile/link
и повторно проверяет их после build. Выход `native-profile-producer.json`
содержит artifact provenance; builder НЕ устанавливает root registry record.
Trusted provider отдельно проверяет final source review/evidence и устанавливает
schema2 entry вместе с exact ELF. Текущий patch pin — reviewed UDP source
prerequisite, не обещание полной DNS/P4/P5 semantics или production-ready ELF.
Public require_consumer/capabilities/builder_apply_enabled/Connect остаются false.

### CODEC2 BundleAcquire production dispatch (SOURCE/PURE)

`native_profile_channel::run_issuer` после exact ADMIT_ACK выполняет raw
Descriptor272/ACK40 через тот же owner endpoint, до ready. System сохраняет
`RuntimeScopeStamp::admission_deadline`; Local фиксирует deadline до setup.
HELLO/ADMIT/descriptor не продлевают его. SystemChannel читает setup напрямую
до rendezvous; после ACK retained `Negotiated` разрешает только bounded DNS
frames с exact launch/epoch. CODEC1, wrong launch/schema и unnegotiated DNS
отклоняются без fallback. Existing sender credential transport checks и запрет
unexpected rights сохраняются; DATA token не заменяет verified producer/Peer.

`helper/native_dns_bundle.rs` вызывается actual serialized dispatch для55/47,
возвращает56/48 с exact pending sequence. Bundle ID имеет отдельный issuer
counter/map; совпадение числа с ServiceGrant ID не связывает namespaces.
Root — live retained user-DNS class3 grant, exact private flow/original,
resolver/query/manifest/epoch. Начальный original DNS name пока принимается
только при exact совпадении с retained query: search expansion не выдумывается.
По ordered scope/branch issuer выводит subject/stream/chain/endpoint/carrier;
первый scope принадлежит resolver row, next input равен previous carrier,
mask и terminal leaf проверяются полностью. Physical domain leaf и resolver
без доказанного subject scope остаются Unsupported.

Каждый private `DnsHopPermit(bundle,index)` удерживает deadline и отдельный
route ticket, когда backend создаёт exception. Existing RouteAuthority →
ProfileRoutes проверяет свежий Known proof, captured routes и durable journal;
Chain не создаёт physical exception. Numeric Direct использует actual carrier,
а не logical input. Общий route-reference ledger4096 (existing ProfileRoutes
ticket bound) охватывает user/service grants и DNS bundles; unique firewall
exceptions по-прежнему ограничены durable aggregate cap128. Fixed path scratch,
memory/history и route credits резервируются
до installation; pending остаётся в общем runtime/proof rendezvous до reply.
Размер receive buffer2293 покрывает max BundleAcquire2164+Header128+sentinel;
legacy body limits не меняются. Дополнительный queue storage вычитается из
8MiB credit с учётом уже включённых preflight reservations, без двойного debit.

Initial revision1 и renewal exact revision сохраняют root/query/base/options/
original/path; expired/canceled bundle не возрождается. Serialized actor имеет
только один исполняемый renewal. ACK ограничен minimum root/session/owner и
request deadlines; retry send уменьшает remainingNs. Grant/root/ingress и
retained hop bindings проверяются перед publication. System user Known≤20ms
не продлевается ACK/новым bundle. Target8 и request cancel проходят общий drain
до Allow; root/flow cancellation отзывает dependent bundles. Tickets очищаются
по одному: успешно retired больше не освобождаются повторно; failure сохраняет
bundle, предыдущую renewal revision и credits в sticky Unknown custody.

Не закрыто этим cut: DNS network Reserve/Bind/Publish/Waiter/Numeric transport
vertical и protected StubBind policy. PROBE purpose2 flow0 не превращается в
user-DNS source: canonical55 сейчас допускает только AUTHORIZE class3 base,
а этот legacy decoder требует sourceFlowId>0. Для такого service acquisition
нужен отдельный согласованный contract, не fake flow/alias. Public readiness,
require_consumer, builder_apply/Connect остаются false; Go runtime parity и
полный P5/runtime acceptance этим SOURCE/PURE milestone не заявляются.

### DirectSocket DNS transport: Reserve → SCM → LogicalBind (SOURCE/PURE)

`native_dns_transport.rs` подключён к actual serialized `run_issuer` и
`SystemChannel` (он же Local owner channel). Canonical CODEC2 wire не меняется.
Поддержанный authority shape: manifest-bound USER-DNS class3 bundle, ровно один
Freedom Direct hop, nonloopback numeric resolver, TCP либо connected UDP.
Reserve35 role1 выдаёт отдельные Reservation/Exchange IDs; role2 сверяет parent
exchange, query/bundle/root/source flow+revision/epoch, original/query/base,
resolver/options/type, derived subject/scope/branch/carrier. Resource FD не
становится USER owner proof и не наследует accepted-TCP ingress provenance.

PhysicalBind52 остаётся raw192/FD1/credentials1 на existing proof endpoint.
Receiver проверяет actual sender и launch binding, владеет полученным FD,
делает kernel socket type/protocol/local/peer/cookie/inode/UID/SO_MARK checks,
получает actual socket nsfs FD через существующий SIOCGSKNS wrapper и сравнивает
с retained namespace stamp. System `ProfileRoutes::dns_socket` независимо
сверяет actual source address с captured route preferred_source, peer/port,
carrier/mark/worker UID и повторяет durable backend fence по retained ticket.
Нет ptrace fallback или новых caps. Local не получает System attribution:
недоступный SIOCGSKNS остаётся Unsupported, namespace claim от child не принимается.

Raw SCM и runtime reservation проходят bounded rendezvous в обоих arrival orders.
До совпадения нет PhysicalResourceId/ACK/use. PhysicalAck37 отвечает на исходный
Physical Reserve sequence; runtime pending35 сохраняется между Reserved36 и37.
LogicalBind38 Direct/count1 требует уже ACKed resource с тем же exchange/bundle/
query/path и full freshness. ACK39 создаёт отдельный retained DirectProof,
revision1, immutable resource membership и producerSequence. Kind2 Proxy и
guarded peerless UDP не превращаются в Direct proof.

Все pending/FD leases используют общий rendezvous64. Physical reservation заранее
оплачивает18 FD credits (retained pair + bounded16 scratch); receive отдельно
получает16 scratch credits до recvmsg, после pairing retained debit уменьшается
до2. Это консервативный bounded admission, не обещание64 concurrent resources.
Memory precredits покрывают retained maps/FD facts до materialization; Reservation
заранее оплачивает собственный и будущий Resource/Proof history entry. Temporary
history claim удерживается до чтения raw packet, возвращается на WouldBlock,
commit-ится в общем invocation ledger; history256 не compact/evict/reuse.
R37 retired-request fence применяется до Reserve effects. Cancel drain учитывает
уже полученные SCM rights до публикации ACK. Pending ADMIT renewal не разрешает
PhysicalAck; после slow kernel/backend checks выполняется новый deadline fence,
Known≤20ms и original reservation expiry не продлеваются.

CODEC3 добавляет отдельный protected DNS producer contract и normal retirement
path ниже. Без него Retire45/46 остаётся Unknown custody report: Request45 не
является independent closed proof. FD/namespace, credits, bundle и durable tickets
удерживаются до existing actual-worker-closed + rules-KnownClosed supervisor fence.
Cancel после live published Physical reservation не выдаёт KnownClosed.
Wrong/replayed/late SCM закрывает unexpected rights и отзывает context; очищенные
known-only reservations не отзывают соседний bundle. Append43/44, ProxiedLogical,
PROBE flow0, loopback StubBind и hostname bootstrap остаются Unsupported.
Publish/Waiter реализованы следующим bounded cut ниже.
Public flags/protected allowlist/readiness не меняются.

### CODEC3: protected Direct DNS release и consuming receiver close

`registry::ProducerRecord` schema2 принимает optional `dns_release` с exact
contract=`direct-dns-consuming-close-join-v1`, version1,
contract_sha256=SHA256(ASCII contract + NUL),
schema_sha256=SHA256(`YONIK-DNS-V2-CODEC-3` + NUL). Остальные source/patch/
builder/toolchain/build-input/image поля принадлежат тому же protected record.
Все прежние root-owned/NOFOLLOW/identity/entry hash/sealed image проверки
сохраняются; optional поле не даёт DNS capability старому UDP record.
`DNS_REVIEWED_PATCH=None`: actual factory/Conn ownership audit ещё не принят,
поэтому production `ImageContract::check_dns` закрыт. Digest не добавлен в
allowlist этим implementation. Fake tests явно инъецируют reviewed pin.

`SystemChannel::dns_producer` (также Local shared channel) сверяет Peer,
bound LaunchRecord, retained config hash и decoded capsule manifest до CODEC3
setup ACK. `VerifiedDnsProducer` не является current-image measurement.
Его private release anchor связывает exact retained proof/resource/bundle/
query/root/source/revision/epoch/derived path с authenticated launch. Никакой
child bool/ACK/env или обычный UDP token не заменяет protected DNS contract.

Retire Proof требует ACKed LogicalBind и отсутствие pending reservation reply;
irreversible release снимает единственный Direct ref. Proof Allow не закрывает
receiver FD. Resource Retire требует actual sent Proof ACK, отсутствие pending
bind/reply и прежний binding. Narrow nsfs consuming-close API закрывает owned
socket и netns ровно по одному разу, без retry raw FD даже при EINTR. Unknown
поглощает ошибки и сохраняет ledger/custody; числовые FD не переиспользуются.
Terminal results оплачены existing object/history/memory до effects; повтор
write(false)/Retire возвращает тот же result, не повторяя release/close.
FD credits и terminal physical reservation transition commit-ятся только после
actual Resource ACK send. Затем отдельные cancel physical reservation → parent
reservation → exchange; tombstones не evict/reuse. Bundle отдельно закрывает
route tickets/durable firewall; Resource ACK их не освобождает.

Cleanup window фиксируется как исходный physical expiry +1s, ограничивается
session; он не продлевается RPC/retry. Expired USER grant не разрешает use или
GRANT, но retained root/bundle obligations доступны cleanup до этого deadline.
Deadline/uncertain close не выдаёт KnownClosed. Append/Proxy/новые consumers
этим cut не добавлены; actor владеет ровно одним Direct resource ref.

Builder experimental compile-only пишет отдельный
`native-profile-dns-release-candidate.json`: envelope `install_authority=false`,
`requires_factory_ownership_review=true`, candidate record с теми же final ELF/
source/build hashes. Это review evidence, не protected install record; builder
не устанавливает registry и не утверждает выполнение DNS contract старым patch.
Для production нужен root-reviewed exact DNS patch pin и trusted install provider.

### USER DirectSocket Publish/Waiter: SOURCE/PURE, без Numeric grant

`native_dns_rrset.rs` подключён к serialized `run_issuer` через DNS dispatch.
Поддержаны только ProviderQuery/DnsWire, nonloopback numeric DirectSocket,
USER-backed class3 bundle, provider table5 без System snapshot source. Wire,
CODEC3 hash и corpus неизменны. Publish40 проверяет exact query/grant/exchange/
proof/current revision/единственный frozen resource, resolver/subject/carrier,
epoch/original lookup/options и повторяет independent kernel/backend resource
fence до публикации. Один proof допускает один Publish, без replay/resurrection.

Transcript не является authority сам по себе. Optional protected record
`dns_wire` отдельно связывает `direct-dns-bound-request-response-v1`, version1,
contract_sha256=SHA256(ASCII contract + NUL), schema_sha256=CODEC3 hash с теми же
source/patch/builder/toolchain/build-input/final-image полями. Constructor
`VerifiedDnsWireProducer::mint` требует retained image/config/manifest/exact launch
через existing Peer/registry custody path. `dns_release` этот token не создаёт.
`DNS_WIRE_REVIEWED_PATCH=None`: production mint закрыт до root-reviewed actual
producer contract, который подтверждает exact request и complete response от
этого bound resource/peer/query, без подмены cached/child transcript. Ни builder
pin, ни protected install record автоматически не обновлены этим cut. Pure
положительные tests явно инъецируют reviewed record; runtime proof не заявляется.

Parser без allocation: DNS ID/flags/opcode/rcode, один IN A/AAAA question,
exact lookup/qtype, bounds12..512/12..32768, backward compression pointers с
depth16, CNAME path≤32, total RR≤512, members≤256. В ANSWER допускаются только
owners checked CNAME path; A/AAAA только terminal owner/exact qtype/unicast.
Адреса coalesce в source order, TTL — минимум related CNAME/address TTL;
TTL0 не создаёт receipt. Дополнительные RR не создают members. EDNS0 без
неизвестных option payloads проверяет flags/DO/payload; unsupported EDNS options
дают отказ. UDP response ограничен advertised payload (512 без EDNS); полный
32768 frame проверяется для TCP. Unknown grammar не становится live fallback.

Published41 выдаёт immutable ProducerRRset DATA, не waiter/grant. Absolute data
expiry — min(exchange creation + actual DNS TTL, original session/source epoch
lifetime); conservative exchange timestamp предшествует send и не продлевается
поздней публикацией/cache hit. Первый owner deadline не превращается в TTL.
Каждому waiter нужны свой новый bundle/root/private flow и Reserve35 role3;
contextId0 не создаёт socket/exchange. WaiterBind53 проверяет собственные
reservation/query/root/source/revision, matching data name/qtype/options/resolver/
derived route и fresh serial owner/subject. Deadline ограничен original waiter
reservation/root/Known≤20ms, data и session, повтор ACK его не продлевает.
Отдельный WaiterReceipt54 не заимствует original flow/grant publisher/соседа.

Cancel request/Producer5/Waiter6/bundle/root отзывает соответствующие dependents
до ACK; cancel одного waiter/flow сохраняет соседний. Known transport retirement
не удаляет base DATA; Unknown/global source revoke закрывает дальнейшие операции.
State/history/memory precredits предшествуют materialization; terminal IDs не
evict/reuse. Metadata остаётся bounded до invocation teardown, history256 не
объявляется long-lived throughput readiness.

Runtime scratch теперь допускает Header128+Publish33679. Permanent RX metadata
reserve256KiB сохранён. Queued payload — owned bounded slice с отдельным debit
из общего buffer budget ДО allocation/copy; 64 максимальных frames заранее не
аллоцируются. Drain queue использует тот же budget; aggregate8MiB/pending64/FD64
не увеличены. Future wakeup пропускает expired authority и использует retained
cleanup deadline, не превращая cache retention в owner-freshness busy loop.

Numeric42 для одного guarded USER Direct consumer реализован следующим cut ниже.
Class3 DNS DATA само по себе не повышается до USER authority.
ProxiedLogical/Append/Hosts/flow0/bootstrap/Stub policy и новый System snapshot
transcript этим cut не реализованы; public gates false.

### USER NumericAuthorize42 → durable GRANT19: один guarded Direct consumer

`dns_bundle::dispatch` направляет Numeric42 в `dns_rrset::dispatch_numeric`
единственного `run_issuer`. Доступны только parentClass1/use1/ProviderQuery,
live ACKed private WaiterReceipt и immutable A/AAAA member. Private constructor
`checked_numeric` проверяет waiter/reservation/DATA/bundle/root/source revision/
epoch/manifest, точный canonical original hostname и source flow, member address,
исходные port/protocol и checked native subject/scope/branch/chain/stream.
Только terminal Freedom Direct без next допускается; DNS transport carrier не
подменяет original user carrier. Loopback/link-local/ненумерический destination
не становится user route. Обычный AUTHORIZE18 не получает новый constructor;
его codec/validation сохранены. Borrowed View42 accessors читают уже validated
canonical base и compact destination, не создавая authority.

В этом initial subset canonical class1 base сохраняет
`original==effective==immutable original hostname`; отдельный compact target
обязан равняться выбранному RRset member с original user port/carrier. Legacy
rewriting original в IP запрещён. После полного chain-of-checks opaque
`CheckedNumeric` допускает один собственный numeric user grant. DNS class3 root,
hop permit, query string, child IP и ProducerRRset сами route authority не дают.

`dns-wire-v2.md:501–506` не задаёт quota/reuse/refresh для нескольких dials или
fallback member grants. Этот cut консервативно разрешает один effectful Numeric
attempt на waiter и один terminal numeric leaf на исходный flow. Attempt ID и
flow narrowing необратимы до teardown; retry после effects, fallback и legacy
AUTHORIZE refresh этого flow Unsupported. Для следующего dial нужен новый
private flow/root/bundle/waiter. Расширение multi-dial semantics требует root
interop решения; новых wire fields/hash здесь нет.

До owner lookup/effects оплачиваются shared history/memory/route credits.
`Authority::owner` независимо выдаёт fresh user proof и проверяет original
tuple/subject/receipt; System требует Known≤20ms, Local required=false/fresh0
без OS attribution. Expiry=min(waiter, original reservation, DATA, DNS root,
session, target policy≤1s, original user owner proof). Backend не продлевает
proof: после `Authority::route(Direct(member),userProof,source,tuple)` повторно
проверяется тот же proof/parent/expiry, без нового lookup для спасения старого.
Production call идёт через existing `RouteAuthority::check` →
`ProfileRoutes::check_route` → captured numeric route/durable policy replacement
и fence. DNS resource ACK не закрывает этот отдельный user route ticket.

Pending grant заранее удерживает собственные ticket/credit custody. Known
rollback отменяет его ровно один раз; failed/uncertain backend/release/write
делает Unknown sticky и сохраняет grant/backend journal до supervisor fences.
Перед каждым send/retry drain обрабатывает queued cancel; late expiry не даёт
Allow. GRANT19/56 сохраняет class1/source/policy revision и actual receipt
namespace; Header.reply — exact pending42, objectId — этот user GrantId.
Caller обязан вычесть RTT; ни GRANT lease, ни queue не обновляют Known deadline.

Grant содержит private waiter/member dependency. Target1 original request,
Producer5/Waiter6, reservation/bundle/root/source cancel и expiry вызывают durable
retirement dependent user tickets до Known ACK. Один waiter не отзывает DATA
или sibling user grant. Terminal attempt/history не reuse/evict; caps остаются
pending64/FD64/history256/aggregate8MiB и existing route/firewall limits.

Production transcript pin/allowlist остаются прежними/None; factory SOURCE
eligibility не является installed authority. Positive tests используют только
injected reviewed record и fake route/owner/capture operations. Core/Host/network/
OS wrappers не исполнялись, public gates false, runtime acceptance не заявляется.

### USER ProxiedLogical + Append: CODEC3 SOURCE/PURE cut

CODEC4 schema-provenance prerequisite: `ImageContract` теперь удерживает separate
optional DNS provenance (schema3/4, exact V1 contract, DirectUserDns scope,
source patch и его exact review), не erased bool. `DnsCapability` не имеет
public constructor: mint сверяет image и current descriptor schema, channel
сохраняет capability вместе с exact launch и повторяет schema/contract check при
wire/release use. System setup возвращает None для отсутствующей current-schema
capability; fallback к descriptor1/2/3 отсутствует. Config/manifest/launch и
consuming exec custody checks сохранены, current-image measurement не заявляется.
Root53 reviewed Direct3 pins сохранены только как3. Optional record4 grammar
распознаётся, но отдельный CODEC4 review pin None; mixed3/4 record отвергается.
UDP eligibility независима от DNS. Positive pure fixtures inject-ят explicit
synthetic record4 с другим source patch и отдельным review, без UDP authority;
это не install approval и не reinterpretation Direct3 record. Bootstrap/Hosts
root/context реализация остаётся следующим unit, public gates false.

### CODEC4 typed roots и role-dependent reservations: SOURCE/PURE

`dns_bundle::roots` подключён к `run_issuer` через существующие Acquire55,
BundleGranted56, Reserve35/Reserved36 и Cancel47 target8. Wire/schema/corpus не
менялись. Registry удерживает discriminated UserDns/BootstrapService/HostsPath,
единый nonreusing context allocator и оплаченные tombstones до конца invocation.
Renewal требует exact variant/revision/query/full path, не продлевает исходный
deadline. ACKed context становится usable только после успешного send56;
Reserve, полученный до ACK, получает request tombstone при drain.

BootstrapService требует live purpose2 service selector, полный checked native
parent path и snapshot role4/source/asset/epoch. Новый private
`Channel::bootstrap_source` возвращает independent retained `roots::Source`:
`parent(Parent)`, `snapshot(LaunchRecord, SnapshotRef)`, `question(...)`,
`hosts(...)`. Parent включает typed root, exact launch/query/selector/original и
все ordered scope/branch rows. Source должен проверять actual live consumer
parent и held source custody; bytes/hash/child statement этим интерфейсом не
становятся proof. Default production factory возвращает None. Нет reviewed
CODEC4 bootstrap/Hosts producer pin; Direct wire/release/logical capability не
подставляется вместо этого scope. Positive driver tests inject-ят отдельные
source facts, не install/image attestation.

Network context отдельно удерживает `DirectSystemTransportPermit` только для
captured numeric nonloopback resolver peer. Backend вызывается как
`RouteRequest::Dns`, parent proxy/hostname не становится DNS route. Parent carrier
и DNS transport carrier сохраняются раздельно. Exchange/Physical/Waiter Reserve
проверяют exact context/root/query/epoch/Probe8/full frontier; flow0 не вызывает
owner backend и не создаёт USER authority. Permit ticket освобождается отдельно
от parent hops; uncertain durable release сохраняет context/ticket/credits и
делает issuer Unknown без повторного release.

HostsPath не создаёт service grant, route, DNS exchange или TTL. Metadata Reserve
role3 требует один ACKed context по query; после повторной source revalidation
и independent row/member/key selection выдаётся новый SourceObservationId.
Observation удерживает full parent path, exact snapshot/original/revision и
min(source/context/session/request) deadline. Изменение source до публикации
не выдаёт observation. Request/reservation/context cancel отзывает только свои
observations и освобождает pending credit; sibling context остаётся живым.
Все context/observation allocations оплачиваются общими memory/history/pending
budgets, network permit дополнительно route credit; лимиты не увеличены.

Это законченный roots/reservations cut, не полный bootstrap transport vertical:
Bootstrap PhysicalBind/LogicalBind/retirement требуют отдельного проверенного
consuming wire/close producer scope и backend captured-DNS socket validation;
нынешний USER Direct close/transcript scope для них не используется.
Bootstrap/Hosts Publish, Waiter/Numeric и actual parent-open conjunction остаются
следующим unit. Public readiness/Connect/require_consumer и production mint
по-прежнему закрыты; OS wrappers и runtime acceptance не исполнялись.

### CODEC4 Hosts Publish и независимый Waiter: SOURCE/PURE cut после R61

`run_issuer → dns_bundle::dispatch → dns_rrset::dispatch` теперь принимает Hosts
Publish40/DNHOST02 и WaiterBind53. `roots::publish_hosts` сверяет prefix/tail с
ACKed retained observation: query/epoch/source/asset/row/key, точный ordered
member-index vector, immutable original port/carrier и полный physical path.
Ранее проверенный Source повторно проверяет actual parent, held snapshot и
выбор row/members до публикации. Foreign fields отклоняются до Source callbacks;
ошибка проверенного source делает только соответствующий context sticky-invalid,
сохраняя R61 renewal ordering. Один observation выпускает не больше одного DATA
producer; replay/late-cancel не возвращают его в исходное состояние.

`HostsProducer` и `HostsWaiter` — отдельные retained records, без фиктивного DNS
`Binding`, resolver peer, packets, TTL или TransportProof. Их ID allocators общие
с network RRset/waiter namespaces; kind41 остаётся DATA-only, exchange0.
SourceObservation/reservation/context/producer/waiter не alias-ятся по raw ID.
Publish remaining ограничен исходными observation/context/source/session и
request deadline; revalidation, cache hit и заблокированный send не продлевают его.

Первый и каждый следующий waiter требуют собственный ACKed HostsPath context с
новым query и fresh metadata Reserve35 role3. Publisher reservation не является
waiter authority. `bind_hosts_waiter` проверяет exact waiter query/root0/flow0/
revision0, одинаковую source/asset/row/member/key/full-frontier DATA identity и
собственную live source/parent revalidation. Context не переиспользуется для
второго waiter даже после cancel. Kind54 возвращает отдельный WaiterReceiptId,
sourceKind2/purpose3; deadline — min(DATA, own observation/context/source/session,
pending Bind). Никаких USER owner calls, service grants или numeric routes.

Readiness при drain различает ACKed SourceObservation и ACKed network proof:
Hosts не подставляет proof0. Pending Publish/Bind cancel обрабатывается до ACK;
write error делает issuer Unknown и удерживает DATA, observation/context и pending
credit. Typed cancel5 отзывает DATA derivatives; cancel6 только свой waiter;
cancel7/8 своего waiter reservation/context не убивает соседний context. Общие
history/pending/memory caps оплачиваются до capture/allocation; terminal records
не compact/reuse. Wire/schema/CODEC4 corpus не изменены.

Завершён Publish+Waiter cut. Numeric42 use2 пока Unsupported: индексы observation
не являются independent numeric-member proof или BootstrapPhysicalPermission.
Следующий unit должен связать actual held member, mandatory numeric route и
live original-parent conjunction на consuming open, не повышая flow0 до USER.
`Channel::bootstrap_source` по-прежнему None до legitimate reviewed CODEC4
producer binding; Direct3/wire/release records не наследуются. Positive tests
используют injected source facts через настоящий issuer loop. Go R60 source
прочитан для shapes; stateful Rust↔Go execution/runtime acceptance не проводились.
Network Bootstrap transport/close, production pins и public gates остаются закрыты.

### Hosts Numeric use2: отдельная BootstrapPhysicalPermission SOURCE/PURE

`run_issuer → dns_rrset::dispatch_numeric → roots::dispatch_hosts_numeric` теперь
обрабатывает canonical Probe8/parentClass3/use2. Только live ACKed Hosts waiter с
точным retained selector/full physical path/source epoch и original port/TCP
carrier допускает попытку. Ordinal из42 переводится в retained ordered snapshot
member index; private `Source::member(Parent, SnapshotRef, row, index)` возвращает
actual held-source address и expiry. Default implementation Unsupported, production
`bootstrap_source` остаётся None: metadata/hash/child IP не создают такой proof.
Source snapshot, row/member choice и original parent повторно проверяются до
effect, после backend и при publication; исходные leases не продлеваются.

`BootstrapPhysicalPermission` хранится отдельно от USER grants и service roots,
не участвует в AUTHORIZE18/Probe refresh. Exported grant IDs используют общий
неповторяемый allocator, но context/observation/producer/waiter — иные typed
namespaces. Один effectful attempt на waiter, без renew/replay/fallback. До
backend оплачиваются memory/history/route credits; placeholder и one-shot marker
сохраняют custody при uncertain effect. Private service authority вызывает existing
`RouteAuthority::service(Direct)` только после source/member проверки: System
использует manifest/session/network fence, mandatory numeric/LAN policy и durable
desired-rules install с существующим aggregate cap128; USER owner lookup не нужен.
Local не получает System attribution. Общие bounds не повышались.

GRANT19 остаётся byte-exact class3/flow0/required0/fresh0/ownerNone с текущей
policy revision и min(source/context/observation/waiter/session/member) lease.
Это permission для exact numeric member/original hostname+port/carrier/frontier,
а не общий class3 grant. Consuming open/read/write отдельно требует original live
parent conjunction; source63179d9 содержит этот private raw TCP consumer, но здесь
его execution/OS behaviour не подтверждается. UDP и network-bootstrap receipts
этот issuer path не принимает. Full checked path сохраняется даже если consuming
raw-leaf implementation пока поддерживает более узкий набор transport settings.

Close32 target3 → CloseAck34 использует отдельный permission retirement; он не
отзывает одноимённый raw context ID. Cancel1/5/6/7/8 и expiry через common actor
отзывают соответствующие derivatives, затем release durable ticket один раз.
KnownClosed освобождает route credit; terminal permission/one-shot tombstone не
переиспользуется. Backend/write uncertainty или провал post-send fence сохраняет
ticket/context/pending custody как Unknown и globally revokes issuer; повторный
cleanup не выдаёт KnownClosed и не повторяет uncertain release. Actor wakeup
учитывает более короткий permission deadline.

Pure actual-driver controls покрывают полный Host context→observation→Publish→
waiter→42→durable fake route→19 и Close32/34, оба режима, IPv6, wrong member/port/
carrier/selector/namespace/epoch/parent, precredits, delayed backend/send, queued
cancel до/после effect, replay, sibling ticket isolation и Unknown cleanup.
Никаких sockets/proc/OS wrappers не запускалось. Wire/schema/corpus/allowlists,
registry/builder и public gates не менялись; legitimate reviewed Source/record
binding и runtime/Go pair acceptance остаются отдельными необходимыми gates.

`dns_transport_binding` выводит из всего live checked bundle два разных target:
logical resolver peer и actual numeric physical frontier. Последний следует
carrier→nextInput через manifest path; Physical Reserve/SCM сверяет terminal
scope/subject/branch/endpoint/hop и actual peer/socket/source/netns/route ticket.
Resolver не подставляется вместо proxy first hop. Hostname physical frontier,
loopback, peerless UDP, service flow0 и bootstrap здесь Unsupported.
System `RouteAuthority::dns_socket` принимает typed optional dynamic ticket:
Some проверяет retained dynamic route, None — только exact captured non-DNS
static route из SessionArtifact после существующего session/network fence.
Обе ветки сверяют peer/port/carrier/preferred source/worker UID/socket mark;
namespace независимо проверяется retained socket evidence. None сам proof не
создаёт и не означает отсутствие проверки. Local attribution не добавлена.

`run_issuer → dns_bundle::dispatch → logical_dns/append_dns` обслуживает CODEC3
38/39/43/44. Retained proof — distinct `Direct(resource)` либо
`Proxied(Box<ProxyResources>)`, ordered union≤64 и private LogicalLineage с exact
binding/exchange/producerSequence. Direct count1/kind1 сохранён; чужой kind,
resource/query/bundle/epoch/frontier и direct proof для proxy отвергаются.

Append требует текущую ACKed revision, sequence1 затем строго +1, один pending,
новые distinct ACKed resources того же immutable binding. Fixed-capacity union
оплачен до allocation; physical FD/pending/memory/history precredits прежние.
Все старые/новые kernel facts и весь bundle повторно fence-ятся после backend.
До ACK resources retained, но новая revision не usable; successful send commit
меняет revision, original expiry не продлевается. Lost/uncertain ACK удерживает
custody и запрещает Publish/новый Append. Queued cancel drain предшествует Append
effects и каждому send/retry. Приём Publish/Append до ACK оставляет request denial
tombstone: очередь не делает раннее использование допустимым после ACK.

Publish freeze требует exact current ACKed revision/union и отдельный logical
lineage anchor. После Publish Append запрещён. Strict RRset parser и separate
waiter/USER Numeric authority сохранены. Proxy Numeric consumer не добавлен.
Proof retirement проверяет все retained refs/pending/reservations и protected
consumer joins; receiver не закрывается в Proof фазе. Resource phase consuming
close каждого socket/ns handle происходит один раз, credits освобождаются после
его ACK. Общий cleanup deadline=min всех original resource cleanup windows,
без owner expiry renewal. Partial close/uncertain send — sticky Unknown,
не повторный raw close и не KnownClosed. Bundle route tickets отдельно.

**Конкретный remaining producer seam:** `Channel::dns_logical_producer` по
умолчанию возвращает None; `VerifiedDnsLogicalProducer` не имеет production
constructor. `registry.rs` сейчас знает только direct-dns-bound-request-response-v1
и direct-dns-consuming-close-join-v1 (`DNS_WIRE_REVIEWED_PATCH=None`). Они не
mint-ят logical token. Нужен отдельно reviewed protected installed contract,
связанный existing retained image/config/manifest/exact launch custody, который
подтверждает actual handler/stream→query/exchange lineage, ordered physical
union/revisions, plaintext request/response и consuming-close/all-task joins.
После такого source review его trusted producer подключается к этому Channel
endpoint; wire/layout менять не требуется. Child ID/FD/hash/ACK и Direct record
эту authority не заменяют. Ни registry/builder/pins, ни Go здесь не изменены.
Pure driver inject-ит отдельный logical token только как fake source fact;
это не installed proof. Public gates и production mint остаются закрыты.

### StubBind: bounded listener observation, не service authority

`helper/resolver_stub.rs` отделяет retained sampled observation от policy issuer.
`native_profile_channel::reject_unproved_stub` вызывает закрытый
`require_protected_policy`; loopback остаётся Unsupported до появления
легитимного protected resolver policy producer. DATA/UID/unit name/hash не
создают StubBind authority. CODEC-2 BundleAcquire/Granted здесь не реализованы.

`attribution/broker/kernel.rs::ListenerDump` требует полный IPv4 и IPv6 dump
с terminal DONE, без interrupted/filtered/truncated/foreign сообщений.
Общий предел — 65536 просмотренных строк и 64 кандидата одного порта;
candidate credit проверяется до разбора атрибутов. Сохраняются kernel UID,
cgroup ID, inode, cookie, адреса, state и IPv6-only. Основание — Linux v6.12
`net/ipv4/inet_diag.c`: INET_DIAG_CGROUP_ID=21, SKV6ONLY=11; последний
выдаётся для IPv6 LISTEN/CLOSE. Отсутствующий атрибут, включая connected UDP,
закрывает путь. Wildcard, dualstack overlap, несколько совпадений/reuseport,
чужой cgroup/UID, remote tuple и неполная visibility не принимаются.

Compile-only `listener_census` проверяет namespace собственного diag socket
через существующий safe SIOCGSKNS wrapper и retained netns identity.
`kernel_sample` сверяет retained cgroup2/root-owned directory identity и
64-bit inode/cgroup ID. Source factory резервирует из общих invocation ledgers
4 FD, 1 pending и 65536 bytes до effects. Pure injected source проверяет
manager/invocation/source epoch/Local-vs-System до и после census, freshness
20ms и исходный expiry. Ошибка revalidation sticky; retained handles/credits
не освобождаются самим отрицательным результатом. Это sampled observation,
не remote listener pin, user attribution или DNS grant.

Конкретный оставшийся producer gap: `systemd_worker.rs::verify_installed`
проверяет только защищённые yonik-worker/check units; `registry.rs::Entry`
описывает engine/image producer, а не resolver service policy. Ни один из них
не доказывает exclusive/nondelegated resolver cgroup, запрет foreign socket
passing/socket activation и допустимый host namespace/view. Минимальное
дополнение — trusted protected resolver policy issuer, выдающий непрозрачные
проверенные service facts: authenticated manager unique owner, exact reviewed
unit contract/invocation, UID, retained cgroup2/netns identities, source epoch
и указанные ограничения socket custody. Его наблюдение нужно повторно
проверять вокруг полного census. Без этого private UnitEvidence не имеет
production constructor; registry/packaging policy в данном cut не меняются.
