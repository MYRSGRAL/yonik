# P4: launch/admission и original-flow/grant consumer

Это SOURCE/COMPILE/PURE milestone, не завершение P4 и не runtime acceptance.
Follow-up применяется после existing native-broker-codec к pinned Xray26.10.31.
Builder gate остаётся выключенным до transport/grants/DNS-query integration.
Frozen wire/bootstrap, ABI260, upstream commit и dependencies не изменяются.

## Production caller

`main/run.go::startXray` при наличии хотя бы одного private locator выбирает
отдельную ветку, без fallback после ошибки. Она принимает только один bounded
stdin JSON (до65536 bytes), отвергает confdir/другие config paths/test/dump и
вызывает `PrepareProfileLaunch` до `core.LoadConfig`/`core.NewWithContext`.
Parser получает те же bytes, чей SHA256 сравнивается с sealed launch record.
`prepareProfileServer` — общий production caller для pure factory-order tests.
`profileServer.Start` повторяет fence до feature Start; Close сначала отзывает
context, затем закрывает features и только после подтверждённого cleanup — FD.
При ошибке construction/cleanup сохраняется Unknown custody до child stop/reap.
`ProfileRuntime.Revoke` ставит stop fence без освобождения FD;
`RevokeUnknown` сохраняет sticky Unknown, который `Close` не превращает в
KnownClosed. Внутренние terminal states Closed/Unknown различаются явно.

Legacy path остаётся отдельным и не получает нового context/admission/grants.
Check-only с full-profile locators отвергается до Run admission и constructors.
Само наличие locator выбирает parser, но не создаёт полномочий.

## Locator и launch record

Все четыре locator обязательны, decimal FD>=3, без aliases/повторов:

- `YONIK_PROFILE_CONTROL_FD`: private AF_UNIX/SOCK_SEQPACKET channel;
- `YONIK_PROFILE_LAUNCH_FD`: sealed memfd, ровно192 bytes;
- `YONIK_PROFILE_PEER_PIDFD`: retained Host/supervisor pidfd;
- `YONIK_PROFILE_ASSET_ROOT_FD`: retained controlled directory FD.

FD потребляются однократно и возвращаются в CLOEXEC. Входное окружение допускает
только LANG=C и эти locator names. Нет mode/credential из JSON/tag/env value.
Seals требуют WRITE/GROW/SHRINK/SEAL; actual record size/type проверяются отдельно.
Sender credentials проверяются на каждом runtime frame, вместе с live pidfd,
PID/starttime и binding. Rights/unknown ancillary/duplicate credentials/TRUNC/
CTRUNC отвергаются; все доставленные rights закрываются даже при ошибке.

Record layout: magic8@0,version1 u16@8,length192 u16@10,rights u16@12,
reserved0 u16@14,nonce32@16,configDigest32@48,session16@80,invocation16@96,
generation u64@112,epoch u64@120,hostPID u32@128,workerPID u32@132,
hostStart u64@136,workerStart u64@144,manifestHash32@152,reserved0[8]@184.
Все integers big endian. `YNKEXT01` требует rights=1, root sender и exact
current worker PID/start. `YNKLOC01` требует rights=0, worker PID/start=0;
sender UID — normal Host UID. Local record никогда не принимается за System.
Parent counterpart обязан проверить actual child pidfd/PID/start и HELLO после
spawn; pre-spawn нулевые Local worker fields не доказывают child identity.
Порядок без deadlock: Host проверяет executable image и actual child, передаёт
bounded stdin, затем ждёт HELLO; Go читает stdin перед HELLO. Ждать HELLO перед
передачей stdin нельзя. Frozen System bootstrap env и ABI260 не меняются.

## Codec и state

Runtime header YNKCAP01/version1 —128 bytes; frame<=65536. Sequence начинается
с1, строго +1; gap/replay/wrap/binding mismatch отзывает канал. Go поддерживает
HELLO1, ADMIT2, ADMIT_ACK3, OPEN_INGRESS16, INGRESS_REPLY17, AUTHORIZE18,
GRANT19, RENEW21, CANCEL32, REVOKE33 и CLOSE_ACK34. PROBE20/DNS class3 пока
не создают service authority; неизвестные сообщения fail closed.
Initial deadline1s; session lease<=60s отсчитывается от HELLO send, renewal —
от RENEW send. ACK не продлевает deadline. Один reader/writer и один renewal;
неверный/опоздавший ACK не обновляет состояние. Manifest при renewal неизменен;
новый admissionId монотонный, existing immutable rows не копируются в ledger.
REVOKE/EOF/peer death/expiry отменяют context; CLOSE_ACK сообщает Unknown,
поскольку reader не может утверждать завершение feature cleanup.

ADMIT header128: mappingVersion3 u16@78, tableCount11 u16@120; прочие поля
по revision2.1. Table prefix(type,count,byteLength) занимает8 bytes;
byteLength включает все row prefixes/payloads, исключает table prefix.
Row prefix(rowLength,reserved0) занимает4 bytes; rowLength — только payload.
11 tables и hash domain следуют capsule-mapping.md/resolver-snapshot-contract.md.
SnapshotRef payload76; YNKDNS header120. Transport/proxy/scope/action enums
отдельны от network TCP6/UDP17. Устаревшие mapping/tableCount не принимаются.

Проверяются row bounds до materialization, subject/scope/stream/endpoint/chain
indices, carrier→next input, DAG/path<=256, aliases/owned mode, required flag,
resolver/source refs и asset aggregate. Row caps:256/512/1024/256/64/16/4/1/
512/16/1; static unique leaves<=128. Caps могут только уменьшаться относительно
4096/128/128/64/8388608/30000/4096/256. Metadata/buffer preflight резервирует
512KiB fixed state +3*encoded capsule bytes, retained snapshot bytes и5MiB
flow ledger credit, внутри общего8MiB budget. Временный DAT category index2MiB
и streaming buffer32KiB освобождаются до создания flow ledger: preflight берёт
максимум стадий, не создаёт второй независимый8MiB budget. Dynamic strings
receipt/grant учитываются сверх fixed credit до allocation.

## Assets

До Allow ACK открываются только `r-<sha256>.dat` и `dns-<sha256>.bin` через
retained rootFD/openat(NO_FOLLOW), с type/owner/mode/nlink/size/hash и before/
after stamps. Assets<=16 unique, aggregate<=64MiB. Snapshot<=2MiB проходит
полный bounded layout/parser, flags/order/search/options/family/alias checks;
effective peers<=3, duplicates сохраняются. System resolver rows обязаны
соответствовать snapshot peers, включая TCP fallback. Live resolver не вызывается.
DAT streaming parser проверяет pinned protobuf schema, type/category, UTF8,
CIDR prefix, enum/boolean/duplicate/unknown fields. Bounded category index
содержит до65536 SHA256 keys; overflow даёт denial до роста контейнера.

До core parser устанавливается controlled asset-root. Дополнительно existing
`filesystem.NewFileReader` получает closed reader factory, допускающую только
exact owned paths и возвращающую independent SectionReader над retained FD.
Глобальные native asset search paths не дают fallback на чужие contents.
Отдельный cursor каждого consumer не меняет retained FD offset; revoke запрещает
дальнейшие reads. Snapshot object остаётся private, query hooks ещё не подключены.
Runtime DAT basename соответствует `ExternalRef::tag` и `emit.rs:238`;
catalog source basename остаётся `<sha256>.dat`. Bare runtime alias отвергается.
Snapshot сохраняет uppercase hostname/search/domain по pinned netgo
`dnsconfig_unix.go::ensureRooted`; hosts aliases остаются lowercase canonical
keys по `net/hosts.go`. Hosts literals включают unspecified/multicast data,
но не IPv4-mapped IPv6. Physical destinations и resolver peers проходят отдельный
строгий `profileIP`/destination check: hosts data не создают разрешение socket.
Table9 mask0 разрешён только со всеми Absent branch fields; попытка AUTHORIZE
любой branch отклоняется. Provider protocol table10 не равен owned kind:
System SOCKS/HTTP alias может ссылаться на owned TUN, никогда на Probe.

## Production original-flow и grant hooks

`ProfileAccept(context.Context,net.Conn,string)(context.Context,error)` вызывается
из owning TCP/UDP inbound worker с actual socket. `ProfileOpenOriginal` выдаёт
private receipt отдельно для SOCKS TCP, HTTP CONNECT и каждого plain HTTP
keep-alive request. `ProfileAssociateUDP` фиксирует actual UDP association tuple;
`ProfileOpenOriginal` разделяет receipts по destination внутри association.
`ProfileOpenTUN` принимает только System и owned TUN row. Lifetime принадлежит
connection/request/association context, не секундному TTL. Закрытый UDP receipt
не воскресает до завершения association. Owned inbound `v1.mux.cool` запрещён.

Dispatcher вызывает `ProfileDispatchEntry` до pipe allocation, сохраняет native
sniff/forced/default/balancer selection и затем `ProfileSelectRoute`. Handler
проверяет exact selected subject/effective target; `ProfileAuthorizeHandler`
вызывается после единственной actual `profileMuxDecision`, используемой native
mux/xudp Dispatch. Bool из capsule не заменяет actual decision. `ProfileGuardLink`
повторяет grant checks на logical read/write, включая data+EOF и UDP payload
destination. Потеря receipt не заменяется session credential.

AUTHORIZE v3 prefix20: sourceFlowId u64@0,class1@8,reserved0@9,subject u16@10,
chain u16@12,stream u16@14,scope u16@16,branch u8@18,reserved0@19; затем
immutable original Destination,effective Destination,resolverFFFF,queryLength0,
ownerKind0/reserved7/ownerId0. Только authenticated issuer может вернуть
INGRESS_REPLY24/GRANT56 по revision2.1. Counters request/sourceFlow/grant раздельны.
GRANT exact outstanding scope нельзя перенести на другой receipt. Lease<=1000ms
от send time, clamp к session deadline на send; session renewal старый grant
не продлевает. System required1, ownerFreshNs<=20ms с вычитанием всего RTT;
FrozenSent1 и SidebandOperation2 сравниваются вместе с ID, одинаковое число
разных kinds не смешивается. Local required0 и ownerNone/id0/fresh0.

Единственный monitor читает/пишет channel, обслуживает session renewal и bounded
flow queue64. Ingress4096/grants4096/tombstones256 могут только уменьшаться caps.
Request и будущий tombstone резервируются до enqueue/allocation. Refresh
коалесцируется; idle CONNECT обновляет grant до expiry, без продления старого
deadline до ответа. Cancel одного flow/grant не отменяет соседей; late response
не публикуется и получает targeted cancel. Retired watermark не пересекает live
pending hole. EOF/revoke/peer death отменяют весь ledger. Unknown CLOSE_ACK
не выдаёт authority и не доказывает physical cleanup.

`Handler.Dial`/`internet.Dial` проверяют D; `DialSystem` проверяет C до redirect.
`ProfileChain` проверяет source scope/branch/action/edge, exact endpoint, next
subject/input/branch mask до pipe allocation и direct nextHandler.Dispatch.
Next input=C, original network остаётся immutable. UDP logical link cache
разделяется по private receipt. Physical session ownership/pools и DNS grants
ещё не подключены: existing physical guard и contextless DNS fail closed.

## Открытый вопрос counterpart: tuple orientation

Go `profile_flow_hooks_linux.go::ProfileAccept` кодирует original initiator в
local[8]/localPort[4], ingress в remote[24]/remotePort[6], по owner-flow смыслу.
`ProfileAssociateUDP` сохраняет actual ephemeral association port. Независимый
Rust9b1bba9 `profile_channel.rs::Capsule::validate_request` требует для non-TUN
`tuple.local_port == ownedPort`; его messages vector использует socket-local
orientation. Нужен root ответ: какой orientation нормативен для acceptedTCP и
associatedUDP и как issuer нормализует его для owner lookup. Fixed tuple40
не менялся; consumer и fake producer не выдают реальную authority. До согласования
этот pairing не объявляется совместимым. TUN source→destination проверяется
отдельно. Ослаблять peer/endpoint/owner проверки ради parity нельзя.

## Golden и counterpart

`full-profile-fixtures/launch-admission-v3.json` — независимый Python-encoded
synthetic Local record/11-table ADMIT, без actual authority. Та же fixture входит
в upstream patch как common/yonikbroker/profile-launch-vectors.json и проверяется
Go decoder и independent Go fake producer. Rust builder может использовать её
для exact-byte parity; System issuer обязан строить mode2/required1 hash заново.
Hash включает все11 tables, но не admissionId/lease/previousHash, как в contract.

Rust/root integration: передать sealed record и controlled assets до exec;
сверить HELLO nonce/mode/binding/actual child identity; послать authenticated
ADMIT(replyTo=1); считать admission committed только после Allow ACK с exact
manifestHash/admissionId. При renewal сохранять manifest hash и scopes; не
продлевать старые grants через session lease. Optional ACL/owner proofs, durable
direct policy и original-flow receipts принадлежат назначенному issuer.

Независимые Rust9b1bba9 fixtures local-minimal/system-chain-default-reject/
system-chain-probe/resolver-snapshot-v1 сохранены byte-exact под own fixtures и
в patch. Capsule DATA tests не являются source/asset ACK proof для synthetic
System snapshot ref. Следующие части P4: authenticated issuer/durable direct
policy, session physical ownership/pools, mux worker context, Hysteria/gRPC/
XHTTP guards, UDP/probe/DNS service grants и pinned snapshot query engine.
Gate остаётся false; full runtime acceptance не выполнялся.
