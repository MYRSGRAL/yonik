# P4: admission, original-flow/grants и transport ownership

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
GRANT19, PROBE20, RENEW21, CANCEL32, REVOKE33 и CLOSE_ACK34. Служебная authority
возникает только после authenticated GRANT exact класса; admission её не выдаёт.
Неизвестные сообщения fail closed.
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
разделяется по private receipt. Physical ownership и transport pools подключены
отдельной веткой ниже; contextless DNS/service grants остаются fail closed.

## Session-owned physical factory и transport pools

`ProfileTransportPool(ctx,kind)` принимает только private live logical grant;
actual kind Tcp1/Grpc2/Xhttp3/Hysteria4 сравнивается с active table4 stream.
Raw UDP не использует configured stream. `internet.Dial` проверяет actual
protocol selector; другие transports и alternative system dialer отвергаются.
XHTTP browser dialer не получает owned authority; final-mask outbound listen
callbacks также запрещены. Это не изменение frozen bootstrap/env/ABI260.

Key=SHA256(domain+NUL,session,invocation,digest,manifestHash,generation,epoch,
subject,scope,branch,chain,pathDigest,exact table4 kind/security/fingerprint,
effective logical destination,physical endpoint). Config bytes уже связаны с
issuer intent digest до parser; actual handler/factory берёт stream settings из
того же parsed config. Provider tag и stream-settings pointer не key/authority.
`ProfileChain` накапливает отдельный path digest по actual checked transitions.

Private pool registry≤128 и physical sockets≤128 принадлежат runtime, а не
первому flow. Global native caches используются только legacy веткой. gRPC,
Hysteria и XHTTP получают session-owned clients из private registry. Отдельный
общий resource cap≤128 резервируется ДО constructor HTTP client/mux worker;
это не128 на каждый XmuxManager. Все bounds могут только уменьшаться capsule
caps. Metadata этих fixed arrays включены в существующий5MiB credit; decoded
capsule/snapshot/flow strings не получают второй8MiB budget. Runtime protocol
buffer/load acceptance этим SOURCE/COMPILE/PURE milestone не доказывается.

`ProfilePool.Context(callback)` сохраняет actual callback deadline/cancel,
проверяет registration, foreign runtime и immutable pool identity и заново
выбирает live grant этого scope/key. Ни копия opaque value, ни нулевой pool,
ни session credential не создают authority. Первый owner receipt не переносится
на следующего consumer. `SessionContext` задаёт physical lifetime runtime;
проверки user stream/request/send остаются у его собственного logical grant.

`guardedSystemDial` выбирает отдельный `ProfileDialPhysical` до socket runner:
reserved physical slot, D/C/endpoint/current grant, runner, повторный fence до
publication. Session revoke/EOF/peer death/lease прекращают open/reuse/I/O.
Отмена одного logical receipt не закрывает shared physical sockets/clients.
Failed close делает session закрытой для новых effects; socket reference и
Unknown custody сохраняются, `ProfileRuntime.Close` не освобождает asset/FD
custody после ошибки transport cleanup.

Guarded UDP capability `ProfilePacketConn`/`PacketConnForTransport` используется
в system factory, memory/final-mask factory, Hysteria и XHTTP H3. Она проверяет
actual peer на ReadFrom/WriteTo, возвращает guarded PacketConn, не raw socket.
Неизвестный connection type даёт typed denial вместо panic. FinalMask view
сохраняет внутренний guard; old TCP-chain FakePacketConn не становится profile
UDP escape. Legacy branch остаётся отдельной.

Native mux actual picker/factory создаёт session-bound worker вместо Background,
с synthetic TCP v1.mux.cool как прежде. На каждый logical Dispatch проверяется
свой grant; cancel закрывает только mux Session. Worker close/cleanup освобождает
свой bounded resource slot. gRPC callback получает private pool handoff;
отдельный RPC cancel/Close не закрывает ClientConn соседей. Hysteria проверяет
grant до каждого tcp/udp open/reuse, сохраняет required InterConn concrete API
и привязывает close logical stream к его ctx. XHTTP H1/H2/H3/xmux и upload retry
проверяют pool/logical identity; owned requests не используют WithoutCancel.
Cancel одного HTTP request не помечает shared client как transport failure.
TCP/raw UDP/gRPC/XHTTP logical connections повторяют checks на read/write.

Оставшиеся закрытые пути явно возвращают `ErrProfileUnsupported`: domain
physical dial до pinned snapshot query/peer proof. Numeric pooled Chain
подключён последующим milestone ниже. Обычный redirect продолжает проверять
carrier→next input; конечный pool разделяется по накопленному chain path.
Нельзя выдать source FlowGrant за полномочия всех последующих scopes. Snapshot
queries, DNS/Probe grants и resolver provenance hooks — следующий milestone;
admission не создаёт service grants и live DefaultResolver fallback отсутствует.

## R9: H1 operation lifetime и resource custody

R9F1: `DefaultDialerClient.PostPacket` передаёт тот же private logical ctx и
`c.profileGate` в H1 I/O участок. Owned checkout эксклюзивен: request deadline
применяется к manual read/write, cancel закрывает только заимствованный H1.
Callback остановлен и join-нут до возврата socket следующему consumer.
После blocked response/body и непосредственно перед payload write повторяется
logical gate. Все прежние ответы и ответ текущего request должны быть полностью
прочитаны и подтверждены статусом200 до reuse. Short/failed/unconfirmed write
не повторяется на другом H1 и не возвращается в pool. Неопределённый outcome
не превращается в успешный request. Owned H1 теперь ждёт ответ текущего request;
legacy H1 сохраняет прежнюю ветку. HTTP2/H3/shared client cancellation не меняется.

R9F2: private Go signature теперь
`ProfilePool.NewResource(func(context.Context,func(error))(ProfileCloser,error))`.
Retirement callback сообщает окончательный результат actual cleanup, а не
уведомление «Close начат»; XHTTP и mux передают возвращаемую ошибку. Wire,
locator names и frozen ABI260 не меняются.

До factory выделяется bounded `profileResourceCustody` slot: Pending→Active→
Closing→KnownClosed/Unknown. Shutdown snapshot содержит reservation, даже когда
factory ещё заблокирован, и ждёт его ready/result. Pending входит в общий cap,
не учитывается дважды. Factory error с nonnil value и late return после revoke
проходят один managed cleanup до возможного освобождения slot. Callback во
время Pending/Closing не освобождает custody. Actual Close error сохраняет
value, reservation и ошибку; поздний callback(nil) и повторный Close не очищают
Unknown и не повторяют raw Close. Новые opens/reuse блокируются session fence.
При KnownClosed slot освобождается ровно один раз с проверкой identity reservation.

RED сохранён на985013a: broker source byte-exact; H1 body только механически
выделен в private helper для injected pure gate без изменения I/O/auth semantics.
Controls воспроизводят cancel→late response→payload write и потерю late resource
при Close error. GREEN использует тот же production caller и отдельные controls
для blocked read/write, partial/неподтверждённого H1, early retire, pending cap,
late factory, factory error+value, sticky Unknown и successful cleanup.
Это только correction двух findings; DNS/probe/pooled-chain readiness не меняется.

## R9F2: async mux cleanup

`common/mux/client.go::DialingWorkerFactory.createWorker` создаёт managed state,
retirement callback, cancel и processDone до запуска fetchOutput/monitor/process.
Private constructor принимает pure runner для управляемого порядка задач.
Внутренние process/fetch/idle paths вызывают только `requestClose`; managed
`ClientWorker.Close` ждёт окончательный результат monitor, legacy Close сохраняет
signal-only поведение. EOF до возврата constructor не теряет callback/state.

Monitor запрещает allocation, пробуждает session.done до join Dispatch, закрывает
session endpoints и owned link, затем ждёт input/fetch/process exit. Удалённые
logical sessions сохраняют failed cleanup leaves. Ошибка cleanup остаётся в
retained final result и повторный Close её не заменяет. `finished` публикуется
после actual cleanup и join, перед retirement callback: reentrant Close из
callback не ждёт monitor самого себя. Произвольный внешний callback, выполняемый
самим process, не должен вызывать ожидающий managed Close; owned internal paths
используют только requestClose. Picker/group shutdown снимает picker lock до
ожидания Close и сохраняет aggregate error; закрытый picker не создаёт workers.

`common/yonikbroker/profile_cleanup.go::ProfileCleanupResource(any) error`
принимает явный `ProfileCleanup() error` или error-returning Close. Для exact
in-memory transport/pipe Interrupt синхронно закрывает pipe; reader postcondition
проверяется ReadMultiBuffer, writer — Close. Void-only Interrupt произвольного
типа не является доказательством: выполняется best effort и возвращается
`ErrProfileCleanupUnknown`. Flow reader/writer передают cleanup underlying value,
не маскируя отсутствие proof. Legacy Close/SessionManager API не изменены.
Ошибка операции Proxy.Process сама по себе не подменяет результат cleanup.

RED на exact6918221 воспроизводит ранние Close/retire при задержанном actual
session/link cleanup, потерянный error и ложный успех void Interrupt. GREEN
использует реальные constructor/monitor/Close/Dispatch с fake endpoints и
управляемым runner; отдельно проверяет delayed process exit, early EOF,
process-error stop без self-wait, picker lock и retained session error.
Broker reservation и H1 correction сохранены byte-exact относительно6918221.
Это исправление оставшегося mux finding, не завершение transport/P4.

## DNS/Probe consumer и pinned snapshot queries

SOURCE/COMPILE/PURE результат; issuer service paths ещё закрыты, gate=false.
Подключены `features/dns/localdns/client.go::LookupIPWithContext`,
`app/dns/nameserver_local.go::QueryIP` и `app/observatory/observer.go::probe`.
Local resolver выбирает только retained decoded YNKDNS01. После authenticated
owned launch process latch запрещает live fallback callers без private context;
latch не содержит runtime и не создаёт полномочий. Legacy path остаётся прежним.
Owned local nameserver не пишет query/IP в свой DNS log.

Snapshot view сохраняет files/DNS order1..4, ordered search/ndots, first-three
peers включая duplicates/defaultNS из exporter, attempts/timeout, rotate,
single-request, use-vc, trust-ad и EDNS0. Files aliases индексируются O(n log n),
без live hosts/NSS/hostname/env чтений. Параллельные A/AAAA имеют разные grants
и sockets; TCP fallback получает новый grant для TCP row того же peer.
DNS ID/question/class и actual numeric RemoteAddr/protocol проверяются до
публикации. CNAME/RRset связан с owner name, цикл/неоднозначность отвергаются.
Response≤65535, records≤256, CNAME path≤16; overflow отвергается до decoded rows,
без truncation. Нет resolver cache/singleflight, authority callers не объединяется.
RRset остаётся data: он не создаёт physical endpoint exception.

Admission preflight отдельно учитывает snapshot index128KiB и возможность хотя
бы одного query. Private query scope резервирует768KiB до allocation, делит
pending cap≤64 и общий8MiB; после cancel credit удерживается до выхода lookup.
Actual DNS factory резервирует custody до dial в existing object ledger;
service и user sockets делят physical cap. Wrong peer/error/revoke после factory
закрывают ресурс; Close error остаётся Unknown и сохраняет объект.

### Exact service wire counterpart для Rust

Header, mappingVersion3/tableCount11 и ABI260 не меняются. Все поля big endian.
`full-profile-fixtures/service-grants-v3.json` и embedded
`common/yonikbroker/profile-service-vectors.json` содержат независимые Python
vectors; это DATA без authority.

- `PROBE=20`, body8: purpose u16@0,index u16@2,subject u16@4,resolver u16@6.
  Purpose1: table8 index, exact expanded subject, resolver=ffff; GRANT class2.
  Purpose2: table2 physical hostname endpoint, exact owning subject, table5
  system resolver row; GRANT class3. Caller hostname не добавляется в body.
  Search candidates выводятся consumer только из endpoint+verified snapshot;
  произвольного service DNS hostname API нет.
- `AUTHORIZE=18` class3 сохраняет existing v3 prefix20: sourceFlowId@0,class3@8,
  reserved0@9, subject/chain/stream/scope=ffff@10/12/14/16, branch0@18,
  reserved0@19. Далее immutable original Destination, exact numeric resolver
  Destination, resolverIndex u16, queryName(u16+canonical ASCII≤253), затем
  OwnerReceiptKind=None/reserved7/id0. Source flow — live private receipt.
- `GRANT=19` body56 прежний; class/sourceFlowId/revision сверяются с pending.
  Probe/bootstrap sourceFlowId=0, required=0, ownerFreshNs=0,
  OwnerReceiptKind=None/id0, revision=manifest.policy. Local USER DNS тоже
  required0/fresh0/None. Это не снимает manifest/mandatory/active-ACL constraints.
  System USER DNS AUTHORIZE class3 требует live private original receipt,
  совпадение pending receipt/flow/revision и required=1; freshKnown 1..20ms
  от исходного send time минус RTT. FrozenSent=1 и SidebandOperation=2 —
  разные typed owner namespaces, id ненулевой; reserved7=0. Unknown/expired/
  чужой owner не публикуется. Повтор того же kind/id не продлевает observation;
  перед DNS I/O freshness проверяется, при остатке ≤5ms нужен refresh.
  Session credential и DNSGrant не дают user transport authority.
  Exact encoder Rust abf5c2435dd71b272c8f064b155267c52fde9809, полный
  System YNKCAP01 GRANT с owner tail включён в service-grants-v3.json;
  producer не должен обнулять mandatory attribution ради decoder.
- ObjectId=0 при initial request; refresh использует тот же kind/body с
  ObjectId=live grantId. Это private consumer convention для counterpart:
  Rust должен принять refresh PROBE20 exact purpose/index/subject/resolver,
  либо отказать. Закрытый/expired grant не возрождается. Lease≤1000ms от
  monotonic send time минус RTT, bounded session deadline; renewal session
  не продлевает старый grant. CANCEL/grant IDs, tombstones и ledger caps общие
  с user grants; отдельного бесконечного service ledger нет.

Probe URL/tag только сверяются с manifest до PROBE. Actual handler выбирает
branch, затем private grant один раз связывается с этим scope/stream/chain.
User original receipt API не принимает ProbeGrant, а transport API отвергает
DNSGrant. Observatory request/dial сохраняют callback cancellation и min deadline,
не запускают late dial goroutine через task.Run, не следуют redirects. Cancel
закрывает только logical probe, shared physical session остаётся session-owned.

### Исходный gap R13: exact DNS result (outer caller закрыт ниже)

`ProfileDNSQueryContext(ctx,name) (context.Context,func(),error)` резервирует
private per-query state, но не разрешает I/O. `ProfileLookupSnapshot` требует
authenticated DNS grants. `ProfileCheckDNSAnswer(ctx,name,ips) error` проверяет
именно этот query context, snapshot, original receipt, live service grants и
принадлежность каждого IP проверенному RRset; разрешает только narrowing
provider IP filters. Однократный result нельзя перенести на соседний query,
caller или использовать после cancel. Detached/Background не получает authority.
Без внешнего query scope localdns выполняет такую проверку внутри своего caller.

Новый source gap: `app/dns/dns.go::LookupIPWithContext` (текущие261–273) передаёт
в guard только ctx, без query/result, и не несёт per-query token через
`lookupIP`. Сам файл отсутствует в явном upstream ownership перечне задания.
Его не меняли. Старый `CheckAfterDNS(ctx)` остаётся deny для full-profile,
а не использует общий completion bit на ingress. Минимальный root diff:

```go
query, release, err := hooks.ProfileDNSQueryContext(ctx, domain)
if err != nil { return nil, 0, err }
defer release()
ips, ttl, err := s.lookupIP(query, domain, option)
if err == nil {
    if guardErr := hooks.ProfileCheckDNSAnswer(query, domain, ips); guardErr != nil {
        return nil, 0, guardErr
    }
}
```

Нужны также отдельные provider-cache waiter/service hooks: snapshot не заменяет
provider DNS. `app/dns/nameserver.go::Client.QueryIP`195–230 содержит existing
query/IP debug logs при provider expected/unexpected filters; owned suppression
там требует этого дополнительного caller scope. Ни cache grant, ни эти logs
не объявлены закрытыми текущим local snapshot milestone.
Default localdns выбирает только table5 subject=None. Internal DNS-subject rows
не заимствуются по совпадению peer: для них нужен typed caller binding.

Independent resolver-peer capture/ownership proof остаётся обязанностью issuer
до GRANT; numeric RemoteAddr проверка consumer его не подменяет. Rustb04c2c0
отказывает service paths, следовательно production I/O не получает allow.
Physical domain dial остаётся Unsupported: нет authenticated RRset→numeric
endpoint proof handoff. Snapshot выдаёт RRset без live source-address probes.
Отдельный wire gap: purpose2 индексирует table2, а hostname probe URL находится
в table8. DNS для direct probe URL, не являющегося physical endpoint, этим
индексом не кодируется. Consumer не переиспользует probe index как endpoint
index и не принимает user FlowGrant вместо service parent; этот путь closed
до отдельного согласованного typed reference/purpose для counterpart.
Полная parity RFC6724 preference из Go net/addrselect.go14–58 (srcAddrs делает
DialUDP) требует отдельного trusted route/source projection, отсутствующего
в YNKDNS01. Live netgo sorting/DNS fallback ради неё не выполняется.
Native provider DNS/proxy paths ещё не завершены; numeric pooled chain описан ниже.

Следующая System integration по exact Rusta049da5fddbde79f43e8f621c7a77c65bc63535c:
fixture `tests/fixtures/xray-profile-channel-v3/system-proof-extension-v1.json`
и соответствующий system-completion-api.md, без выдумывания нового layout.
Один pre-HELLO YNKPF001/128bytes/rights1
с отдельным proof FD и ACK YNKPFA01+SHA256 record. Затем runtime rights-free;
YNKSPF01/192bytes actual acceptedTCP FD связывается с pending OPEN/request seq,
proofId и tuple. Go consumer этой extension описан ниже. UDP association
по-прежнему Unsupported без independent association proof; TCP proof не UDP proof.

## Numeric pooled chain: private per-logical bundle

`Handler.Dispatch` после `ProfileAuthorizeHandler` вызывает
`ProfilePrepareChain(ctx, choose func(tag string, target Destination)(mux bool,error))`
до `ProfileGuardLink`, proxy Process и native mux Dispatch. Production choose
получает следующий exact native Handler из existing outbound.Manager и вызывает
тот же `profileMuxDecision`, который использует actual Dispatch. Foreign handler,
reject или branch вне table3 nextBranchMask дают denial; mask не выбирает mux.

Wire не расширяется: AUTHORIZE18/class1/sourceFlowId@0, subject@10, chain@12,
stream@14, scope@16, branch@18, затем immutable original и effective endpoint.
Root и каждый выбранный hop получают отдельный GRANT19 того же private source.
Rust abf5c243 `native_profile_channel.rs:425–608` уже проверяет exact root и
frontier `(sourceFlow, nextScope, branch, sourceEndpointIndex)`; предыдущий grant
удерживается. Go не подставляет grantId в поле chain (это table3 index).

Preflight идёт по actual carrier→next input, не меняя original network/tuple.
Bundle≤256 связывает private parent/next grants; лимиты операций64/grants4096,
aggregate metadata и fixed5MiB credit прежние. Дополнительные links учитываются
в fixed metadata sizing; standalone ledger entry ограничен272 bytes.
Pool key дополнен ordered selected hop scope/stream/chain/branch/effective target.
Ни один hop grant и ни один sourceFlowId не входят в shared pool как authority.

Reuse/send проверяет весь bundle именно текущего explicit consumer; соседний
live grant не заменяет его expired/cancelled hop. Каждый System hop проверяет
собственную owner freshness. После всех renewal RPC последний atomic fence
проверяет весь путь снова, без продления20ms ожиданиями следующих hops.
Only private session factory context выбирает live bundle для physical lifetime.
Redirect переносит его выбранный hop в existing nextHandler.Dispatch, где actual
mux decision повторно сверяется; новый grant от имени session не создаётся.
Physical chain link проверяет live pool, user logical link — свой bundle.
Отмена одного user не закрывает shared link соседнего consumer; revoke fences все.

Любой hostname physical leaf остаётся Unsupported до authenticated RRset→numeric
endpoint proof. Child DNS answer и snapshot RRset не повышаются до такого proof.
DNS outer pending files, provider cache/resolver peer proof, UDP System proof и
runtime readiness этим batch не объявляются завершёнными. Gates остаются false.

## System acceptedTCP proof consumer

Counterpart — exact Rusta049da5fddbde79f43e8f621c7a77c65bc63535c и Root614dfa4
(cancel correction без wire change). Independent fixture скопирована byte-exact
в `full-profile-fixtures/system-proof-extension-v1.json` и embedded
`common/yonikbroker/profile-system-proof-v1.json`; DATA не являются authority.

`openProfileRuntime` после sealed launch/config/peer validation, до HELLO и
features, в System mode принимает ровно один YNKPF001128/rights1. Credentials,
pidfd/liveness, nonce/digest/session/invocation/generation/epoch обязательны.
Proof endpoint проверяется как отдельный connected AF_UNIX/SOCK_SEQPACKET с
expected SO_PEERCRED, CLOEXEC и SO_PASSCRED; duplicate runtime socket отвергается.
ACK ровно40 bytes YNKPFA01+SHA256 record, rights0. Initial deadline сохраняется
в `admitProfileUntil`: bootstrap/HELLO/ADMIT не начинают новый timeout. Local
не потребляет bootstrap и не получает System proof. После bootstrap runtime
receiver остаётся rights-free. Cmsg parser идёт по одному header и сохраняет
rights prefix для cleanup при повреждённом suffix; лишние/unknown/truncated
ancillary отвергаются. Proof channel не имеет входящих штатных сообщений:
любые bytes/rights/EOF/HUP вызывают fence/revoke и cleanup.

`app/proxyman/inbound/worker.go::tcpWorker.callback` вызывает `ProfileAccept`
до stats wrapper. Broker получает actual connection через `syscall.Conn` /
`RawConn.Control`, выполняет F_DUPFD_CLOEXEC и проверяет duplicate TCP tuple через
getsockname/getpeername/SO_PROTOCOL/SO_TYPE. Сравнение с Go tuple повторяется
при proof send. Нет env-number, TCPConn.File, unwrap/stat API расширения,
pidfd_getfd, proc/exe fallback или child-supplied namespace FD.
Duplicate — inspect/SCM-only private interface без Read/Write/raw getter.
F_DUPFD сохраняет kernel access flags socket; O_RDONLY socket capability здесь
не заявляется. Никаких payload operations через duplicate нет.

Accepted slot и256 bytes FD metadata credit резервируются до duplicate. Actual
kernel object удерживается до закрытия connection context, а не одного HTTP
request. Каждый OPEN получает новый proofId и exact request sequence. После
runtime OPEN existing single actor отправляет YNKSPF01 body192 и ровно1 FD:
binding80=digest32/session16/invocation16/generation8/epoch8@16, nonce32@96,
request8@128,proof8@136,ingress2@144,provenance2@146,reserved0@147,
initiator tuple40@148,reserved4@188. Local=initiator, remote=ingress.
Proof не создаёт Known owner и не заменяет FlowGrant.

Pending requests≤64 и tombstone reservation прежние; System preflight добавляет
128KiB proof metadata credit. EAGAIN оставляет pending operation с исходными
proofId/sequence/deadline. Более поздний proof не обгоняет ранний ID; cancel
разрешает пропустить неотправленный ID, но никогда не отправить его позднее.
Zero/MAX/wrap/replay отвергаются. Разные каналы могут быть прочитаны Rust в любом
порядке: sender не требует нового acknowledgement или polling owner actor.
INGRESS_REPLY Allow не публикуется до proof send и после caller cancellation.
Proof health входит в System publication/live fences. FD cleanup сериализован
с отправкой, не допускает close/reuse numeric FD race; Close error sticky,
handle/credit остаются в custody и session отзывается. Повторный Close не
превращает Unknown в KnownClosed.

Pure controls используют fake SCM bytes, RawConn.Control и FD operations, без
actual sockets/ioctl/netpipe/proc/core execution. Они проверяют wire/hash parity,
bootstrap mismatch/credential/count/deadline, Local separation, malformed cmsg
cleanup, FIFO/EAGAIN/cancel, original deadline, EOF publication fence, partial
export, same-object retention, Unknown и wrap preflight. Existing control
fixtures явно моделируют уже проверенный System proof; это не production bypass.
System UDP association возвращает Unsupported; tuple vectors остаются data,
UDP positive control использует отдельный Local mode без OS attribution.

Gate остаётся false. DNS outer files pending permission не изменены;
provider-cache/internal DNS и resolver-peer/RRset handoff не завершены.
Numeric pooled chain consumer подключён выше; Actual System end-to-end/runtime
acceptance не выполнялся.

## Детерминированный R8 contract: tuple orientation

Go `profile_flow_hooks_linux.go::ProfileAccept` кодирует original initiator в
local[8]/localPort[4], ingress в remote[24]/remotePort[6], по owner-flow смыслу.
`ProfileAssociateUDP` сохраняет actual ephemeral association port. Root/R8
подтвердил эту initiator orientation по frozen kernel owner lookup/cold fixture.
Для acceptedTCP issuer отдельно проверяет remote_port==ownedPort. Проверка
Rust9b1bba9 local_port==ownedPort ошибочна и исправляется Rust writer в active
issuer WIP; Go tuple не переворачивается. Fixed tuple40/ABI260 не меняются.
Для associatedUDP issuer обязан удерживать проверяемый binding actual UDP
association endpoint к owning ingress/session/sourceFlow и его lifetime.
Нет такого binding — explicitly Unsupported. TCP tuple/owner не подменяет UDP
tuple/owner; port1080 нельзя подставить вместо actual ephemeral49152.
Cross-language `full-profile-fixtures/original-flow-v3.json` фиксирует unequal
ports: TCP12000→1080 и UDP12001→49152, initiator192.0.2.10→ingress127.0.0.1.
Это grammar/source fixture без authority; TUN source→destination проверяется
отдельно. Peer/endpoint/owner mandatory checks не ослабляются ради parity.

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
System snapshot ref. Source consumers numeric pooled chain, service grants и
snapshot query engine описаны выше. Остаток P4: интеграция issuer/durable direct
policy, DNS outer/provider cache, authenticated resolver-peer/RRset endpoint
handoff и отдельно утверждённое UDP issuer association binding.
Gate остаётся false; full runtime acceptance не выполнялся.

## UDP v2: первый закрытый Go source milestone

Контракт — UDP v2 ba1/ceb в system-completion-api.md; exact counterpart
`d79a26fc0979b6fadb7aa01cf1f4d362565ada26` (раздел729+). Это partial source,
не installed consumer/runtime readiness. `receiveBootstrap` явно отвергает
PF002 до ACK; Rust admission также остаётся v1. Local v2 не подключён.
Frozen ABI260/четыре locators/launch records/runtime rights0 не менялись.

Pure authenticated bootstrap consumer различает PF001/PFA01 и PF002/PFA02.
PF002=128,version2,rights1; ACK40=YNKPFA02+SHA256 exact128. V1 bytes прежние.
UDP prefix128: magic8,version1@8,length2@10,rights2@12,reserved0@14,
binding80@16 (digest/session/invocation/generation/epoch),nonce32@96.
Records (length/rights, G=Go,I=issuer): UCS192/1 G→I, UCA160/0 I→G,
UAQ160/0 G→I,UAC192/1 I→G,UPQ160/0 G→I,URP256/0 I→G,
UCM256/0 G→I,UMR192/0 I→G,UCQ160/0 I→G,UCR192/0 G→I.
Magic каждого: YNK + указанное трёхбуквенное имя + 01. Поля/offsets совпадают
с exact Rust fixture; decoder не аллоцирует, проверяет direction/rights/reserved.
Cookie — opaque nonzero u64 (MAX допустим), остальные counters MAX запрещают.
Control/packet ingress — IPv4 loopback; fingerprint ненулевой, flags0.

`udp-proof-v2-rust-d79a26f.json` скопирован byte-exact и embedded как
`profile-udp-proof-v2-rust.json`. Go проверяет все10 records/re-encode, PF002,
ACK hash и whole-datagram fingerprint; `udp-proof-v2-source-vectors.json` —
второй независимый Python corpus. Это DATA, не FD/owner/closure authority.

`profileInitUDPBudget` требует private consumed System PF002/ADMIT binding,
до flow operations резервирует32768 bytes из existing8MiB. Production его пока
не вызывает. В shared ledger≤min(caps7,256) retained entries хранятся runtime
и proof operation IDs/packet/permit/sequence, без eviction/reset/compaction.
`c.operation` и state proof reservations используют общий cap/pending≤64.
Association≤8, pair65536+65536+metadata2048=133120 резервируется до factory.
Private injected receiver имеет только Receive/Close/Join, без FD/Write/Peek API.
ConsumePermit эксклюзивен; проверяет actual peer/cookie/bound endpoint/flags,
RCVBUF≤128KiB/GRO0/overflow и весь hash/header/length. Это проверка наблюдений
будущего source-verified OS wrapper, не доказательство hard kernel queue bound.
Matched не выдаёт user authority и не освобождает payload. Только terminal
denial + явный RetirePayload либо close очищают буферы; следующий peek до этого
закрыт. Close ждёт actual Receive и Join, повтор возвращает final result;
ошибка сохраняет receiver/credit и sticky Unknown. Local Closed state сам по
себе не публикует UCR/KnownClosed и не доказывает issuer/durable cleanup.

Реальный `socks.Server.processTCP` выбирает `profileHandshakeBeforeUDPFactory`
для System profile: native auth/address/TCP response helpers сохранены, но
command3 вызывает `ProfileAdmitSOCKSUDPControl` ДО native handshake5 listener.
Этот endpoint пока всегда Unsupported; даже nil control ACK не даёт success,
child port/socket не создаются. Local legacy и SOCKS4/TCP проверены pure parity.

Остаток перед readiness: actor control-only exchange и operation rendezvous,
общий accounting всех channel/close operations, заранее reserved close IDs,
6 FD credits/association и physical128/pending64 до SCM materialization;
actual issuer FD delivery/inspection и exclusive OS receive/queue readbacks;
provenance3 OPEN↔Consumed, verified private SourceFlow/UDP Known≤20ms/GRANT,
separately credited downstream payload retirement, exact flow/durable retirement,
GoDuplicateClosed receipt и supervisor Unknown custody. Никакой из этих
недостающих proofs не заменён TCP owner, metadata cookie или session credential.

Name-policy gap закрыт root correction7f1f5a8139ecd7f06e64b483b44c627ae2f99654.
Его shared corpus `udp-original-destination-v1.json` перенесён byte-exact в owned
fixtures и embedded Go test:17cases проверяют packet/runtime grammar и original
bytes без canonicalization. Дополнительно обнаружен и исправлен Go runtime
`profileDestinationValue.valid`: IPv4 literal в family3 ранее проходил
`profileDomain`; теперь IP-as-domain отклоняется, как packet parser и Rust.
`Example.INVALID` сохраняет uppercase. Corpus/record parity не снимают admission gate.

## UDP v2: actor + issuer FD delivery, source-only

Base792928b; counterpart a2e1a64489b8dd01e0096d413c278c7c39330386.
Новых wire bytes/layout/enums нет: PF002/PFA02 и10 records d79 неизменны.
`receiveBootstrap` по-прежнему отвергает PF002 до ACK. Local v2 не negotiates.
Builder/runtime/issuer/UDP consumer readiness gates остаются false.

Production source chain:
`socks.Server.processTCP → profileHandshakeWithUDPDelivery →
ProfileOpenSOCKSUDPControl → profileUDPActor.submit → ProfileRuntime.monitor`.
Monitor — единственный proof reader/writer: `tick` отправляет UCS с actual
retained TCP object; `receiveUDPProof` принимает UCA; следующий tick отправляет
UAQ; UAC проходит exact binding/operation/control/cookie/credentials/rights
decoder и `profileInspectUDP` до private association publication.
UCA cookie относится к actual TCP control; UAC cookie — к отдельно созданному
UDP relay (`native_profile_channel.rs`, Associate → ops.relay → Associated).
Их равенство не требуется: UAQ сохраняет TCP cookie, inspection сравнивает
actual delivered UDP SO_COOKIE с UAC. Pure control использует различные cookies.
Каждый control exchange проходит полностью до начала следующего, поэтому UAQ
не оказывается позади более нового UCS operation. EAGAIN не пропускает очередь.
TCP proof v1 сохраняет прежний runtime path; v2 input не смешивается с runtime
rights-free frames. ACK никогда не является UserSourceFlow или UDP owner proof.

Private actor states: queued0 → ControlSent1 → Acked2 → AssociateSent3 →
Delivered4; cancel/failure → Retained5. Deadline фиксируется до первого send,
remaining сужает его с вычетом RTT, queue/ACK не продлевают lifetime.
Request reservations: три retained history entries (control/associate/будущий
close), шесть FD slots,133120 bytes и один existing physical pending slot до
первого I/O. История≤min(caps7,256), requests≤8; ID reuse/eviction отсутствуют.
Close reservation — private capacity slot, не выдуманный issuer closeID.
Общий FD ledger включает proof-channel duplicate, accepted TCP duplicates,
association reservations и16 scratch rights; общий pending≤min(caps3,64).
Runtime и proof recv резервируют scratch/pending до allocation/SCM receive.
Ancillary capacity v2 ограничена CmsgSpace(16*4), поэтому отсутствие credentials
не может материализовать больше16 прав. Unexpected FD закрывается; close error
удерживает handle/credits и sticky Unknown. Physical pending учитывается тем же
session cap≤128, что numeric transport factories; отдельного расширения нет.

OS boundary `profileInspectUDP/profileOSUDPReceiver`: actual DGRAM/UDP,
nonblocking+CLOEXEC, unconnected IPv4 loopback bound endpoint, SO_COOKIE,
SO_RCVBUF≤128KiB, GRO0/RXQ_OVFL1. Receive только после exclusive ConsumePermit,
с context/deadline, bounded nonblocking read/poll и проверкой peer/ancillary.
Нет Write/Peek/raw-FD export; issuer relay не передаётся legacy dispatcher.
Close закрывает actual duplicate, Join ждёт reader; wrapper скомпилирован,
никогда не исполнялся. Pure controls используют injected FD/receiver.

SOCKS success branch читает полный authenticated UDP request до control effect;
ответ содержит только inspected issuer loopback endpoint. Partial request,
nil/foreign/domain endpoint, naked ACK не дают success. TCP/Local legacy
handshake bytes сохранены. После success пока только owning TCP lifetime:
нет Peek/Receive/forward до следующего OPEN/Consumed/GRANT milestone. Revoke
отменяет private control context и закрывает owning TCP consumer; отмена одной
ассоциации закрывает/joins только её relay, соседний control остаётся live.
Поздний UAC отменённого pending request закрывается без inspection/publication;
повторное late delivery запрещено.
Authenticated UCQ закрывает/joins только matching relay и удерживает issuer
closeID в заранее reserved третьем history slot (namespace3). Replay closeID
отклоняется; ACK/KnownClosed не отправляется до durable retirement producer.

**Остаток этого UDP подключения:** provenance3 OPEN↔Consumed, private original
receipt и actual AUTHORIZE/GRANT, отдельно credited downstream transfer/retire,
issuer CloseRequest/GoDuplicateClosed с durable flow retirement. До этого actor
не отправляет UPQ/UCM/UCR и не публикует KnownClosed. Даже успешный local
CloseAndJoin оставляет actor history/FD/physical credits retained; Close сообщает
Unsupported final retirement. EOF/bad packet/session revoke удерживают Unknown
custody. Это консервативная конечная capacity, не long-lived UDP readiness.
Root supervisor/rules fences не подменяются child ACK. DNS outer два файла
по-прежнему не изменены; resolver provenance/provider cache остаются закрытыми.

## R23F2: kernel namespace binding перед UAC publication

Base — root correction d0e8644e12d263336a371666bf6cc06ead9da7d6.
R23F1 `tick/retireCancelledLocked` и regression function сохранены byte-exact.
Новый обязательный `profileUDPActor.namespace` вызывается в matching UAC branch
до `inspect` и `profileNewUDPAssociationReserved`. Production launch связывает
его с `profileKernelSocketNamespace`; nil callback закрывает delivery.
Actual anchor — тот же retained accepted TCP control FD, который передан в UCS;
snapshot handle берётся под flow mutex. Второй handle — actual received UAC FD.
Оба читаются только через private `withFD`, без export raw integer/namespace FD.

Первичный pinned contract: Linux6.12,
`adc218676eef25575469234709c2d87185ca223a`:

- [sk_getsockopt, SO_NETNS_COOKIE](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/net/core/sock.c#L1951)
  возвращает namespace cookie socket с exact u64 length, без capability check
  в этой option branch. Это отдельное значение от SO_COOKIE.
- [setup_net](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/net/core/net_namespace.c#L322)
  назначает cookie при создании namespace через общий generator;
  [struct net](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/include/net/net_namespace.h#L156)
  хранит его как written-once property.
- [do_sock_getsockopt](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/net/socket.c#L2234)
  сохраняет security/BPF policy boundary. Ошибка API/LSM/seccomp/unsupported
  приводит к typed Unsupported; capabilities не расширяются.

`profileRequireSameSocketNamespace` требует два live handles, kernel reader,
два ненулевых значения и их равенство. Значения не приходят из UAC/JSON/env,
не кэшируются как session credential и не сравниваются с current thread netns.
SIOCGSKNS/proc/setns не используются. Guard доказывает равенство namespace
двух actual sockets относительно уже trusted control/listener scope; он не
заменяет Rust nsfs/stamp verification, user attribution или UDP FlowGrant.

Pure injected reader controls: mismatch при неизменном valid UAC cookie,
missing callback/reader/control/relay, zero/error/closed handle, matching success,
opaque nonzero MAX и failed FD close retaining Unknown custody. Denial происходит
до receiver factory/association/Endpoint, поэтому SOCKS success недоступен.
Existing type/protocol/flags/cookie/loopback/queue/GRO/overflow inspection остаётся.
OS getter/receiver не исполнялись; runtime/kernel compatibility здесь не PASS.
Wire, frozen ABI260, capabilities/dependencies и все readiness gates прежние false.

## UDP consuming producer и private duplex response (SOURCE/PURE)

Base `bbaa9896d8f7e9f0ef9972bfd52cdee806b744a8`, включая утверждённый
контракт обратного SOCKS response. Runtime bootstrap/admission gates закрыты.
Новых record/selector/ACK нет: d79/a2e десять records и runtime v3 сохраняются.

`proxy/socks/server.go` после verified delivery/success вызывает
`ProfileUDPControl.Serve(dispatcher.DispatchLink, controlRead)`.
Single existing monitor вызывает `profileUDPActor.producerTick`; только этот
actor пишет UPQ/UCM/UCR и читает proof replies. Receive начинается лишь после
exact URP, через прежний exclusive `ConsumePermit`. Actual UDP tuple, original
SOCKS bytes/fingerprint/cookie остаются immutable. `openConsumed` создаёт private
provenance3 receipt и OPEN, связывая его sequence с UCM. Оба порядка OPEN/Match
разрешены; AUTHORIZE невозможен до обоих подтверждений. Match не является GRANT.

Настоящий `dispatcher.DispatchLink` выбирает native handler/branch, existing
`ProfileAuthorizeHandler` и `ProfilePrepareChain` получают class1 logical bundle.
`ProfileGuardLink` только после полного bundle передаёт request в отдельную
credited downstream copy. Numeric effective UDP endpoint обязателен. Затем новый
Peek допустим, но response buffer прежнего flow остаётся отдельно retained.
Hostname/child resolver answer/Probe/DNS grant не создают user authority.

Private response writer привязан к тому же receipt, bundle/revision и checked
numeric target. `payload.UDP` обязан совпасть с target. SOCKS FRAG0 кодируется
внутри sink; actual recipient — UDP initiator tuple receipt, никогда TCP tuple.
OS wrapper использует nonblocking send на том же retained duplicate и повторяет
namespace/type/cookie/queue checks и logical grant gate перед syscall/writable
retry. Только EAGAIN с нулём bytes повторяется; partial/uncertain send сохраняет
Unknown custody. FD/WriteTo/адресный API не экспортируются.

До allocation резервируются producer8192 и downstream237568 bytes на flow
(request/response/sniffer buffers и overhead) в общем8MiB budget; mux logical
input task дополнительно4096 до goroutine. Flow count и retained runtime/proof
history ограничены прежним общим cap≤256. Slot/ID не переиспользуются и не evict.
Новый Peek не освобождает response/task credits. Это конечная capacity,
не long-lived readiness. Managed mux constructor/monitor cleanup и R9 H1/broker
semantics сохранены; добавлена только registration per-logical input task.

Close запрещает новые sends, отменяет собственные receipts/tasks, закрывает
actual duplicate и ждёт receive/control/downstream/send joins. Runtime cancel
entries сохраняют association ID и typed Known ACK в общем retained ledger.
UCR statusKnown+joined публикуется только после durable UCQ, всех собственных
runtime cancellation ACK, actual CloseAndJoin и отсутствия cleanup error.
Late Permit после cancel только фиксирует monotonic history без Receive/OPEN;
late Match не публикует authority. Unknown ACK/error/revoke/uncertain cleanup
не освобождают custody и не превращаются в KnownClosed при повторном Close.
Child UCR не заменяет Rust supervisor/worker/rules fences.

Pure controls используют реальные broker/runtime/handler guards с fake issuer,
receiver и dispatch link: оба OPEN/Match порядка, pre-match/pre-grant refusal,
две разные UDP initiator ports, foreign receipt/tuple/cookie/revision/endpoint,
expired owner refresh→Unknown, late grant/cancel/typed denial, read mismatch,
history exhaustion, delayed send blocking KnownClosed, uncertain send и
logical task joins. OS wrappers и main не исполнялись. Producer/consumer
counterpart SOURCE review и интеграция остаются обязательны перед opening gates.
DNS outer два файла, provider cache/resolver-peer provenance не изменены.

## Разрешённый DNS outer caller

Base `4ea6c087925ba6045bcfeba26cc31685b3b474b0`. После явного расширения scope
`app/dns/dns.go::LookupIPWithContext` передаёт original domain без изменения
через `ProfileDNSQueryContext` → `lookupIP(query,domain,option)` →
`ProfileCheckDNSAnswer(query,domain,ips)`. Private `profileDNSLookup` позволяет
инъекцию этих трёх функций только package tests; production использует broker
напрямую. Release отложен до завершения проверки и выполняется на error/deny.
TTL/IP не возвращаются при отказе guard. Snapshot check остаётся one-shot,
с exact query/RRset/private source/live grants; provider/cache result без этого
proof отказывается. Local snapshot не назначается вместо provider policy.

`Client.QueryIP` передаёт owned-latch в private `queryIP` только для suppression
четырёх domain/IP debug logs. Фильтры expected/unexpected/prior/unprior и
legacy log statements сохранены. Этот bool не выдаёт DNS authority.
Pure caller injection проверяет порядок/scope/result/release и отказ checker;
Client tests исполняют оба режима фильтрации с fake server и захватом logs.
Семантические wrong-query/IP/replay/cancel/service freshness controls остаются
в real broker pure tests; caller injection не является issuer proof.

Не закрыты internal DNS-subject binding, independent loopback resolver-peer
proof, provider/cache waiter authority и physical hostname RRset handoff.
System class3 required/Known≤20ms не изменён. Wire/ABI260, UDP/R9–R25 guards
и все глобальные readiness/builder gates сохранены; runtime не исполнялся.

## DNS completion: текущая независимая producer часть

Classic UDP/TCP callers используют strict request/response matching до cache
update: ID, единственный IN A/AAAA question, class/type, bounded CNAME membership,
TTL и exact frame extent. UDP callback дополнительно сохраняет private exchange
identity и logical DNS destination; это не physical peer/netns proof. TCP worker
держит query custody до завершения I/O/Close. Его собственный deadline управляет
cleanup, даже если parent query ещё live. Dispatcher, UDP reader и managed mux
input резервируют task/buffer credit до allocation/goroutine; Unknown cleanup
удерживает resource/query/credit и отзывает runtime. History не переиспользуется.

Cache guards удерживают только immutable DATA: без legacy IPRecord provenance,
истёкшего absolute expiry, serveStale/TTL1 и WithoutCancel. IP bytes каждого
waiter копируются отдельно. Этот шаг не создаёт ProducerRRsetId/WaiterReceiptId:
существующий outer answer guard продолжает отказывать без собственного proof.
DNS query context не проходит обычный USER AUTHORIZE даже при совпавшем target.

Canonical CODEC-1 pin: Rust `6dc32a1533f03a701cc0ecc08819476e66d61071`,
`full-profile-fixtures/dns-v2-canonical.json`, SHA256
`5703a0f556ec76158d79c196f4896c19b13ff05f44570fadfe2408c961e30ae5`.
Go DATA preflight/encoder проверяет 76 positive, 164 negative bodies,
14 negative envelopes и 6 snapshot role rows; JSON integers читаются RawMessage
напрямую в uint64. PhysicalBind остаётся raw192 без Header128; runtime DNS
frames — Header128/rights0, отдельный SCM packet — FD1/credentials1. Typed
authority из этих DATA helpers не следует.

Для mapping4 production launch после ADMIT_ACK синхронно посылает Descriptor272,
получает exact ACK40 и лишь затем создаёт flow actor/monitor. Deadline — прежний
initial admission deadline, без renewal. OS boundary аутентифицирует credentials
и pidfd peer; DATA codec получает уже проверенный rights-free payload. Unexpected
rights закрываются с сохранением Unknown custody при cleanup error. Proof
bootstrap до HELLO и ABI260 не изменены. Mapping3 сохраняет прежний launch.

Полный DNS vertical ещё закрыт. Root подтвердил отсутствие legitimate выдачи
DNSBundleId в CODEC-1. Новый нормативный CODEC-2 `4bc87da` добавляет BundleAcquire55
и BundleGranted56 с issuer-owned hop permits; до canonical codec/goldens эти
kinds здесь не сериализуются и не принимаются. Нет alias grantId→BundleId,
class3→USER fallback или выдачи provider permission по tag. Остаются actual
bundle/PhysicalBind/append/Publish/WaiterBind, StubBind и numeric durable handoff.
Internal `proxy/dns` subject остаётся Unsupported и вне текущих изменений.
Global runtime/consumer/builder gates остаются false.

## CODEC-2 и private DNS bundle consumer

Canonical pin `a7a9544e233689659a5df5a39f90d01def4c3239`; corpus SHA256
`10d798ffd45f7d250e4c3f38c02b9f394671d1f9ee4871cdcd39b9d042e59359`:
86 positive, 218 rejected bodies, 17 rejected envelopes. Старые 76 records
сохранены; descriptor требует CODEC-2 schemaHash, CODEC-1 fallback отсутствует.
Kind55/56 и Cancel target8 реализованы по canonical layout без новых полей.

Classic UDP/TCP producer вызывает `ProfileDNSExchangeContext` с exact packed
request до dispatcher/dial. Private query сохраняет original bytes отдельно
от canonical DNS identity. Question/class/type/options/payload и bounded wire
проверяются до root class3 RPC; root grant принадлежит одному private exchange,
не соседнему waiter или pool. USER FlowGrant из parent context очищается,
immutable original receipt остаётся source. System USER DNS сохраняет mandatory
Known≤20ms из старого service consumer; legacy service/R14 wire не меняется.
Owned `toDnsContext` сохраняет cancellation, копирует mutable Outbounds и
отключает service payload sniffing до bundle admission, не меняя user Content.

`Handler.Dispatch` использует отдельный `ProfileDNSPrepareHandler` перед
legacy AUTHORIZE/PrepareChain. Root decision — actual native mux decision;
следующие decisions получены через тот же `h.profileBranch`. Producer удерживает
полный ordered scope/branch path, logical targets и carrier transitions.
Remote hostname промежуточного proxy не становится physical leaf. Issuer
сам восстанавливает subject/stream/chain/frontier и выдаёт собственные hop permits.

BundleAcquire идёт через существующий runtime actor/flowQueue; новых channel
readers/writers нет. BundleGranted проверяет exact pending sequence, root grant,
query/epoch/count, ID/revision и live private source. Initial revision1; renewal
сохраняет ID и весь binding/path, требует exact revision и один pending request.
Остаток отсчитывается от исходного send, ограничен root/session/context/owner
deadline; старый bundle обязан оставаться live до ACK. Новый ACK не продлевает
старый System owner receipt и не возрождает expired/canceled bundle.

Opaque DNS bundle находится в private context. `ProfileDNSBundleGuard` и
DNS branch `ProfileChain` проверяют тот же logical consumer, private original
receipt/query, весь live bundle/root, path index, subject, target и actual branch.
Это не USER/Probe FlowGrant и не session credential. Callback не заимствует
bundle соседнего query. Caller route/session values сохраняются при handoff.

До effects резервируются общие pending/history/memory и hop credits. Initial
RPC резервирует request и оба возможных cancel; renewal — request/cancel,
а bundle удерживает собственный close credit. History также заранее учитывает
каждый hop/revision; codec bound256 не обещает256 live permits поверх cap.
History≤min(caps7,256) общая с
runtime/proof ledger; IDs не compact/evict/reuse. Hop credits разделяют caps0
с обычными grants, aggregate memory≤8MiB. Base credit48KiB+512 bytes/hop,
retained metadata32KiB и4KiB/renewal ограничивают живую/retained custody.

Cancel target1 относится к pending request, target8 — к issuer bundle, target7
по-прежнему Reservation. Pending/late ACK не публикует permission; успешный
late bundle удерживается только для retirement. Known request-cancel оставляет
tombstone: поздний Allow отвергается, rejected ID сохраняется как sticky Unknown.
Known cleanup требует завершения pending cancel и bundle cancel ACK; Unknown
удерживает metadata/query/credits. Runtime cleanup агрегирует этот результат,
не выдавая KnownClosed после одного неподтверждённого действия. Соседний bundle
не отменяется. Bundle ACK не является доказательством закрытия Go FD: этот cut
ещё не создаёт DNS physical resource.

Граница milestone закрыта: `ProfileDNSForwardReady` после bundle guard возвращает
Unsupported до отдельного PhysicalBind/LogicalBind proof; raw physical dial из
DNS context запрещён. Actual Rust issuer/service policy, DirectSocket resources,
StubBind, append/resource guards, RRset Publish/WaiterBind/cache authority и
numeric durable route handoff остаются следующими частями DNS vertical.
Здесь поддержан USER-backed classic routed producer с единственным подходящим
manifest resolver row. Service flow0/internal DNS/ambiguous resolver не получают
выдуманный bundle. Public readiness/require_consumer/builder gates остаются false.
