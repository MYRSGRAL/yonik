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
physical dial до pinned snapshot query/peer proof, pooled source с action=Chain
до per-logical grants каждого hop при reuse. Обычный redirect продолжает проверять
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

### Незакрытая caller интеграция: exact DNS result

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
Pooled chain-hop grants и native provider DNS/proxy paths ещё не завершены.

Следующая System integration по exact Rusta049da5fddbde79f43e8f621c7a77c65bc63535c:
fixture `tests/fixtures/xray-profile-channel-v3/system-proof-extension-v1.json`
и соответствующий system-completion-api.md, без выдумывания нового layout.
Один pre-HELLO YNKPF001/128bytes/rights1
с отдельным proof FD и ACK YNKPFA01+SHA256 record. Затем runtime rights-free;
YNKSPF01/192bytes actual acceptedTCP FD связывается с pending OPEN/request seq,
proofId и tuple. В этом commit bootstrap/proof channel не менялись. UDP association
по-прежнему Unsupported без independent association proof; TCP proof не UDP proof.

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
System snapshot ref. Следующие части P4: authenticated issuer/durable direct
policy, per-logical pooled chain hop grants, UDP issuer association binding,
probe/DNS service grants и pinned snapshot query engine.
Gate остаётся false; full runtime acceptance не выполнялся.
