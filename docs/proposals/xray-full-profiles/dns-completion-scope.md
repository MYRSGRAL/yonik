# Завершение DNS: разрешённый implementation scope

Цель — сохранить DNS и physical hostname semantics семи профилей, включая
provider DNS через proxy. Direct-only lane не считается выполнением этой цели.
Никакой публичный resolver, подмена provider DNS или child-supplied IP не нужны.
Пользователь разрешил реализацию перечисленных исходников и pure-проверки после
R31 SOURCE recheck. Runtime readiness, сеть, запуск ядра/служб и установка
этим разрешением не предоставляются.

## Bootstrap, разрывающий cold-start цикл

Pinned `transport/internet/system_dialer.go:52–59,178` использует
`net.ResolveUDPAddr`/`net.Dialer.DialContext` для physical destination.
`dialer.go:242–243,251–281` отдельно обрабатывает explicit socket domain strategy
и dialerProxy; отсутствие стратегии сохраняет системное разрешение физического
first hop. Captured system resolver в этой ветке сохраняет исходное поведение,
а не заменяет provider DNS для пользовательских запросов.

Для каждого фактического hostname physical leaf добавить закрытое requirement
`PhysicalFirstHopBootstrap`: exact subject/table2 endpoint, hostname bytes,
port, TCP/UDP carrier и checked chain frontier. Не включать remote hostname,
который provider protocol отправляет следующему proxy для remote resolution.
Provider JSON и GUI не выбирают произвольный bootstrap target или resolver.

Host/helper захватывают system snapshot даже если у provider DNS app нет
localhost requirement. Источник тот же: retained root-owned NSS/hosts/resolv
и netgo env policy из resolver-snapshot-contract.md, без live fallback.
System resolver rows имеют bootstrap-only purpose; app DNS/rules не меняются.
Existing purpose2 bootstrap_query уже связывает запрос с subject/endpoint;
новый RRset receipt обязан сохранить эту связь до numeric physical open.

Bootstrap использует собственный service grant, Direct DNS transport proof
и при loopback отдельный StubBind. Он может разрешать только exact first-hop
hostname, не пользовательские адреса и не расширение Direct policy. Ответ
проверяется по DNS ID/question/CNAME/RR membership/epoch/TTL; source hosts
имеет отдельный typed snapshot receipt, а не synthetic DNS wire response.
SNI, transport settings и original hostname сохраняются. Все numeric members
проходят captured route/mandatory policy/durable installation до GRANT/open.
Snapshot/stub epoch change отзывает bootstrap receipts и производные grants.
Для synthetic fixtures используется explicit fake captured resolver/RRset;
production не получает fake seed и не требует ручного копирования IP из child.

### Обязательный bootstrap binding (R31)

`PhysicalFirstHopBootstrap` создаёт System resolver requirement независимо от
наличия Application localhost requirement. Capsule mappingVersion4 сохраняет
tableCount11 и размеры rows; table11.count=1 при любом из двух requirements.
В table11.sourceFlags bit0 по-прежнему hosts-absent, bit1 — ApplicationSystemDNS,
bit2 — PhysicalFirstHopBootstrap; остальные0. Хотя бы bit1/bit2 обязателен для
System rows. Mapping3 не принимает новые bits и не используется для DNS_V2.
Manifest hash связывает flags и единственный sourceDigest/assetHash. System
rows table5 ссылаются на этот sourceDigest. Bootstrap-only не разрешает app DNS;
Application-only не разрешает physical bootstrap без requirement для endpoint.

Issuer независимо выводит checked physical frontier из tables2/3/9 и удерживает
`BootstrapBinding`: exact launch/manifest, purpose2, subjectIndex, endpointIndex,
originalHostname bytes, port, actual carrier6/17, scopeIndex, branch, ordered
chain path, System resolver identity и source epoch. Endpoint обязан быть
hostname фактического physical leaf; отсутствие frontier или remote proxy
resolution даёт отказ. Caller не выбирает другой hostname, endpoint или purpose.

Retained RRset/WaiterReceipt хранит этот binding целиком. Его source — tagged
union `BootstrapDns` или `BootstrapHosts`, не произвольный slice IP:

- BootstrapDns дополнительно связывает query/question и qtype/options,
  resolverRow/transportProofId/revision, request ID, строгий CNAME/RR membership,
  numeric members и absolute expiry=min(DNS TTL, source/session expiry).
- BootstrapHosts связывает единственный table11 snapshot(sourceDigest/assetHash),
  exact hosts row и member indices, pinned-netgo lookup key, epoch и monotonic
  sourceObservation deadline. Исходный hostname не заменяется lookup key.
  Observation lease≤1s и session/source lifetime; до нового lease issuer
  повторяет retained-source revalidation и выпускает новый receipt. DNS TTL
  не выдумывается; source replacement отзывает старые receipts. Это отдельный
  typed source record, не synthetic DNS response/transportProofId.

NumericAuthorize V2 сохраняет prefix16: version u16=2, member u16, WaiterReceiptId u64,
baseLen u16≤1024, use u8, parentClass u8; затем canonical base и numeric Destination
≤23 bytes, body≤1063. use=1 LogicalDestination не принимает Bootstrap receipt;
use=2 PhysicalFirstHop принимает только exact BootstrapBinding. ParentClass
должен совпадать с исходным user/probe/DNS bundle, его scope/path/frontier и
freshness; bootstrap service не повышается до user authority. Reply/derived
numeric grant сохраняет исходный class и private use discriminator, не заменяет
original logical target. Issuer сверяет binding/member/port/carrier/frontier,
epoch/expiry и revalidation ДО durable route installation/GRANT/open; открывать
socket без live parent и соответствующего numeric proof нельзя.

## Общий provider transport proof

Private exchange runner сохраняет исходный provider route. DirectSocket
использует issuer-retained actual socket; ProxiedLogical — private logical
lineage выбранного handler/stream плюс retained actual first-hop resource set
и полный class3 service-chain bundle. Physical proxy peer не считается DNS peer.
Факт кодирования logical DNS target и чтения plaintext доверяется только exact
protected reviewed producer; issuer независимо сверяет graph/path/grants,
actual physical socket facts/netns/source/route и lifecycle.

Query scopes и class3 children не превращаются в class1 user receipts или probe
authority. Shared pool не выдаёт authority; каждому waiter нужна свежая derivative.
Cache хранит данные/immutable source provenance с absolute TTL/epoch, не чужой grant.
Expired/serveStale/replay/cancel не продлевают TTL и не разрешают publication.

Отдельная versioned DNS transport extension сохраняет ABI260. Typed namespaces:
reservation, physical resource, DNS bundle, logical exchange, StubBind, RRset,
waiter receipt, TransportProofId. SCM Bind передаёт actual FD с credentials после reservation ACK;
resource/lineage append подтверждается до handshake/send. Publish ссылается только
на issuer-retained union proof, затем отдельный numeric authorization проверяет
RRset member/port/carrier/full path. Предложенные layouts R29 требуют review до кода.

### Resource revisions и append-before-use (R31)

Следующие V2 правила нормативны и заменяют неоднозначное frozen set в R29.
PhysicalBind fixed192: magic8=`DNSPHY02`, version u16@8=2, length u16@10=192,
flags u32@12=0; configDigest32@16, session16@48, invocation16@64, generation
u64@80, sourceEpoch u64@88, launchNonce32@96; exchangeReservation u64@128,
queryId u64@136, DNSBundleId u64@144, physicalReservation u64@152;
resolverRow u16@160, pathRow u16@162, carrier u8@164 (6/17), physicalKind
u8@165 (TCP1/ConnectedUDP2/GuardedPeerlessUDP3), mode u8@166 (Local1/System2),
zero u8@167; canonical numeric first-hop Destination с zero padding до24@168.
Все identity/row/kind поля точно совпадают с issuer reservation; IDs ненулевые,
pathRow — checked physical frontier. GuardedPeerlessUDP допустим только с exact
reviewed endpoint guard, не как kernel peer equality. Bind не выбирает resource
ID: issuer выдаёт новый PhysicalResourceId в ACK, права ровно1 FD+credentials.
Это V2 PhysicalResource record, не старый Direct DNS socket record.

LogicalBind ACK создаёт TransportProofId с revision1 и ordered immutable resource
vector. LogicalBind поле u64@56 — remainingNs≤1s, не переносимый absolute clock;
issuer вычитает elapsed/RTT и ограничивает original reservation deadline.
Frozen означает неизменность каждой revision, не запрет новых bounded revisions.

AppendResources V2 body fixed48 + count*8: version u16@0=2, flags u16@2=0,
count u16@4=1..64, zero u16@6; exchangeId u64@8, TransportProofId u64@16,
expectedRevision u64@24, appendSequence u64@32, remainingNs u64@40≤1s;
далее ordered issuer PhysicalResourceIds. Total union≤64, body≤560. Один append
pending на proof, sequence начинается1 и строго +1 без wrap. expectedRevision
должна равняться текущей; additions уникальны внутри vector и относительно всех
старых revisions, live и bound тому же query/bundle/epoch/path. Общие credits
резервируются до append effect; каждый resource уже прошёл PhysicalBind ACK.
Issuer атомарно публикует revision+1 и ACK с exact proof/exchange/sequence/new
revision. Go не использует новые resources до проверки этого ACK. Lost/ambiguous
ACK не вызывает retry/reuse sequence; cancel/retire/Publish запрещают append.
Duplicate/reordered/stale append отвергается без изменения текущей revision.

DNS_V2 Publish использует fixed144 вместо V1 fixed128: version=2, прежние поля
до127; transportProofId u64@120, proofRevision u64@128, purpose u8@136
(ProviderQuery1/BootstrapDns2/BootstrapHosts3), sourceKind u8@137
(DnsWire1/HostsSnapshot2), zero u16@138, frontier u16@140, carrier u8@142,
zero u8@143. DNS wire tail прежний; maximum body33679. Publish допускается один
раз после всех append ACK, только для текущей exact revision, затем набор
замораживается до retire. Receipt сохраняет именно эту revision/ordered set.
BootstrapHosts не подставляет transport: transportProofId/revision=0, DNS
request/response lengths=0, источник отдельный bounded typed snapshot record
с полями BootstrapHosts binding выше. Его wire layout и positive/negative
goldens закрепляются отдельно до реализации codec; V1 его не декодирует.
Retire/cancel закрывают все revisions и pending append без resurrect.

FD64/pending64/aggregate8MiB и исходные deadlines общие; credits до effect/SCM.
Retire/join отделены от cache lifetime, Unknown сохраняет custody. Shared neighbor
не закрывается отменой waiter. QUIC migration/reconnect/resource replacement
требуют нового admission до use. Compaction history256 — отдельная незавершённая задача.

## Loopback StubBind

Root-owned resolv.conf не является proof сервера. Нужны authenticated system
manager и protected resolver service policy, retained service epoch/cgroup/netns,
полный bounded INET_DIAG socket set с endpoint/UID/cgroup/cookie/state и проверкой
IPv4/IPv6/wildcard/reuseport ambiguity. Missing/partial/stale/replaced proof
закрывает путь; не подменять stub публичным resolver. Local применяет это лишь
при собственной проверке host manager/namespace/mount; не притворяется System.
R31 подтверждает SOURCE feasibility kernel/cgroup фактов для target64bit без
новых capabilities, условно на доступность manager/mount/namespace/LSM.
Фактическая host visibility не проверялась; непрерывный listener pin не обещается.

## Минимальное дополнение ownership и проверки

Новые Go точки сверх двух уже разрешённых DNS callers:
`app/dns/{dnscommon,cache_controller,nameserver_cached,yonik_exchange,nameserver_udp,nameserver_tcp}.go`
и adjacent pure tests. Остальные необходимые seams уже в P4 scope: broker,
UDP dispatcher, outbound handler, mux, gRPC/XHTTP/Hysteria, physical dialer.

Rust: существующие profile_channel/issuer/profile_intent и tests; дополнительно
`attribution/broker/kernel.rs` только для общего bounded listener parser/dump,
новый private `helper/resolver_stub.rs` с module declaration; engine native
graph/validate/intent для bootstrap-only requirement и соответствующие tests.
Пользователь отдельно разрешил эти upstream/helper/kernel исходники и tests.

Сначала SOURCE review контракта, затем согласованный bounded wire/codec и goldens,
Direct/Proxy/StubBind producers, per-waiter cache receipts и numeric leaf handoff.
Fake-only acceptance покрывает все семь roots и bootstrap cycle, wrong bindings,
source/stub epoch replacement, duplicate/rights/credit overflow, class separation,
delayed route install, cancellation/Unknown/join и сохранение hostname/SNI.
Без core/Host/GUI/network/services/OS-wrapper исполнения, новых deps/caps или установки.
