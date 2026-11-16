# DNS_V2: согласованный HostsSnapshot wire tail

Статус: root принял layout с коррекцией полного retained path вместо chainRows[4].
Это specification для codec/goldens, не production authority или runtime PASS.
Нормативные PhysicalBind192, Append48+8N, Publish144 и
NumericAuthorize16 из dns-completion-scope.md сохранены. Runtime gates false.
Этот документ не разрешает V1 fallback или synthetic DNS response.

## HostsSnapshot tail: единственный layout

### Общий Publish prefix144 и Published48

Ниже exact V2 specification: прежний candidate находился в artifact
`p4-dns-nextcut-f36/next-cut.md`, не в существующем Rust codec. Переназначать
bytes0..119 независимо в двух implementations нельзя.

| Offset | Publish поле (BE) |
| --- | --- |
| 0 | version u16=2 |
| 2 | flags u16=0 |
| 4 | resolverRow u16 |
| 6 | subjectIndex u16 |
| 8 | endpointIndex u16 |
| 10 | qtype u16 |
| 12 | queryId u64 |
| 20 | serviceGrantId u64 |
| 28 | exchangeId u64 |
| 36 | sourceEpoch u64 |
| 44 | sourceDigest[32] |
| 76 | snapshotAssetHash[32] |
| 108 | questionLen u16 |
| 110 | requestLen u16 |
| 112 | responseLen u32 |
| 116 | reserved u32=0 |
| 120 | TransportProofId u64 |
| 128 | proofRevision u64 |
| 136 | purpose u8: ProviderQuery1/BootstrapDns2/BootstrapHosts3 |
| 137 | sourceKind u8: DnsWire1/HostsSnapshot2 |
| 138 | reserved u16=0 |
| 140 | frontier u16 |
| 142 | carrier u8 |
| 143 | reserved u8=0 |

DnsWire tail — original lookup-name bytes[questionLen], затем exact packed DNS
request[requestLen] и response[responseLen], без padding/trailing bytes. Bounds:
question1..255, request12..512, response12..32768; body≤33679. Строка без NUL;
lookup-name bytes не переписывают original hostname. Strict DNS parser проверяет
один IN question/qtype A1 либо AAAA28 и соответствие request/response, а не только
размеры. Captured search/alias expansion проверяется по reservation/snapshot;
произвольное другое имя недопустимо. Query/grant/exchange/proof/revision ненулевые
и совпадают с issuer-retained records. Source epoch соответствует reservation.
sourceDigest — exact resolver source digest; Provider без snapshot имеет zero,
System source ссылается на table11 и его assetHash; у Provider assetHash=zero.
Resolver/subject относятся к exact DNS reservation и manifest.

ProviderQuery: endpoint/frontier=FFFF, carrier6/17 совпадает с DNS transport
resolver row; это не разрешение выбрать произвольный application target.
BootstrapDns: endpoint/subject/frontier/carrier совпадают с physical BootstrapBinding;
DNS transport protocol отдельно определяется resolver row/TransportProof.
System source требует нужного manifest role: ApplicationSystemDNS для
ProviderQuery, PhysicalFirstHopBootstrap для BootstrapDns. HostsSnapshot zero
rules и отдельный tail заданы ниже. Purpose/sourceKind смешивать нельзя.

Kind41 Published fixed48 BE: version u16@0=2, status u8@2
(Allow1/Deny2/Unknown3), reserved bytes3..7=0; ProducerRRsetId u64@8,
exchangeId u64@16, sourceEpoch u64@24, remainingNs u64@32,
memberCount u16@40=1..256, reserved bytes42..47=0.
Allow: ProducerRRsetId ненулевой, exchange/source epoch точно соответствуют
Publish (exchange0 только HostsSnapshot), remaining>0 и не больше absolute
data/source/session expiry. DNS data lifetime ограничен actual uint32 DNS TTL,
не первой waiter authority; Host data — observation lease≤1s. Consumer вычитает
elapsed/RTT. Deny/Unknown: bytes3..47=0. Header.reply обязан совпасть с pending
Publish sequence. ACK создаёт только base data/source provenance; первый и
каждый следующий waiter отдельно выполняют WaiterBind53/WaiterBound54.

Publish purpose=3/sourceKind=2 использует этот tail после fixed144; request,
response lengths и transportProofId/proofRevision строго0. Никакого TTL,
DNS ID, qtype, resolver peer или DNSBundle вместо snapshot observation.
Все integers BE. Reserved bytes строго0. Строки без NUL/padding.

| Offset | Поле |
| --- | --- |
| 0 | magic[8]=DNHOST02 |
| 8 | version u16=2 |
| 10 | total tail bytes u16=128+keyLen+originalLen+2*memberCount |
| 12 | flags u32=0 |
| 16 | table11 sourceDigest[32] |
| 48 | table11 assetHash[32] |
| 80 | sourceEpoch u64, exact live invocation epoch |
| 88 | sourceObservationId u64, issuer-issued/nonzero/nonreused |
| 96 | remainingNs u64, 1..1000000000 |
| 104 | snapshotIndex u16=0, table11.count=1 |
| 106 | hostsRow u16, exact retained decoded snapshot row |
| 108 | memberCount u16=1..16 |
| 110 | keyLen u16=1..253 |
| 112 | originalLen u16=1..253 |
| 114 | subjectIndex u16, exact BootstrapBinding |
| 116 | endpointIndex u16, exact table2 physical leaf |
| 118 | scopeIndex u16, exact BootstrapBinding |
| 120 | branch u8, checked actual branch |
| 121 | carrier u8=6/17 |
| 122 | port u16, nonzero/exact original endpoint |
| 124 | reserved u32=0 |
| 128 | pinned-netgo canonical lookup key[keyLen] |
| next | immutable original hostname[originalLen], case/bytes preserved |
| next | ordered distinct member indices[memberCount] u16 |

Maximum tail666, Publish body810. Indices относятся к exact retained asset,
не к producer-supplied address vector. Source/asset hashes только matching:
без retained source FDs, identity revalidation и issuer observation отказ.
Canonical key обязан совпасть с pinned lookup original hostname; hostsRow alias
сравнивается с этим key. Member indices должны быть внутри addresses данной
строки и сохранять исходный порядок. Table11 mapping4 обязан иметь bit2;
Application-only bit1 не разрешает bootstrap. Bootstrap endpoint/subject/
scope/branch/carrier независимо выводятся issuer из closed graph.
Observation удерживает полный ordered checked chain path и все остальные поля
BootstrapBinding. Дублировать/усекать path в tail нельзя: прежнего лимита4 здесь
нет. Issuer сверяет exact binding observation и Publish/query, включая path
и actual physical frontier; один совпавший scopeIndex не заменяет этой проверки.

В Publish prefix для HostsSnapshot: resolverRow=FFFF, qtype=0, serviceGrantId=0,
exchangeId=0, question/request/response lengths=0, transportProofId/revision=0.
QueryId остаётся ненулевым и точно bound observation; original находится в этом
tail, не в DNS question bytes. Source epoch/digests, subject/endpoint и
frontier(scopeIndex)/carrier prefix точно совпадают с tail и observation.
Source authority здесь — snapshot observation, не фиктивный DNS exchange/grant.

SourceObservationId выпускает issuer только после retained-source revalidation
для exact purpose2 BootstrapBinding/query/options/lookup key и retained row.
Producer его не выбирает. Один observation допускает один Hosts Publish;
повтор/replay отвергается. RRset/cache derivative не переиспользует observation
как fresh permission; parent class/use/freshness проверяются отдельно.
remainingNs — переносимый остаток, не чужой monotonic
timestamp. Issuer удерживает собственный absolute deadline и ограничивает его
min(original observation, source/session expiry, now+remaining-elapsed/RTT).
Publish/receipt/cache/новый waiter этот deadline не продлевают. Новая observation
требует новой revalidation и нового ID; replacement epoch отзывает старые
receipts. Нет DNS TTL, synthetic request/response или transportProofId=observation.

Unknown/expired observation, mixed sourceKind/purpose, nonzero DNS lengths,
wrong snapshot role/index/hash/row/key/member/frontier, trailing/truncated tail,
duplicate/reordered member indices и ненулевые reserved дают typed denial до
numeric route/durable install/GRANT. Decoder preflight проверяет весь размер,
counts и indices до materialization; общие pending64/FD64/8MiB без отдельного
overflow credit. NumericAuthorize use2 сохраняет exact bootstrap binding;
use1 и повышение service flow0 до user запрещены.

## Реализация codec

### Producer data и отдельный cache waiter

Для DNS_V2 Kind40 Publish → Kind41 Published возвращает ProducerRRsetId:
immutable данные/source provenance, НЕ waiter authority. Поле u64@8 прежнего
Published body48 имеет этот typed смысл. Каждый waiter, включая исходный,
выполняет Kind53 WaiterBind → Kind54 WaiterBound до использования результата.
ProducerRRsetId и WaiterReceiptId — разные namespaces даже при равных числах.

DNS Reserve для каждого waiter удерживает canonical question/qtype/options,
purpose/use, resolver/snapshot/source epoch, exact launch/manifest, source-flow
и его revision, checked path/frontier/parent class и fresh class3 grant либо
HostsSnapshot observation. Reservation может быть waiter-only: она не создаёт
transport/socket и не заимствует исходный query/grant. Cache HIT без новой
reservation/authority не получает WaiterReceipt.

WaiterBind fixed64 BE: version u16@0=2, flags u16@2=0, zero u32@4;
waiterReservationId u64@8, ProducerRRsetId u64@16, serviceGrantId u64@24,
waiterQueryId u64@32, sourceFlowId u64@40, sourceFlowRevision u64@48,
remainingNs u64@56=1..1000000000. Все reference fields точно совпадают с
issuer reservation. Для HostsSnapshot serviceGrantId=0, source observation
проверяется в reservation; у user-derived DNS sourceFlowId/revision ненулевые,
у service/bootstrap flow0 оба0. У network DNS serviceGrantId ненулевой.

Issuer проверяет base producer provenance/TTL/epoch и совпадение canonical
question/options/resolver/source kind/purpose/route identity с новой reservation,
а fresh waiter authority — только по её собственному live query/flow/grant.
Первый publisher/grant/flow не подставляется второму waiter. System user DNS
сохраняет required Known≤20ms; bootstrap/flow0 не повышается до user. Успешно
retired transport может оставить base RRset до absolute expiry, Unknown/revoked
source — нет. Hosts observation и DNS TTL не продлеваются cache hit/WaiterBind.

WaiterBound fixed64 BE: version u16@0=2, status u8@2
(Allow1/Deny2/Unknown3), flags u8@3=0, zero u32@4;
WaiterReceiptId u64@8, ProducerRRsetId u64@16, waiterReservationId u64@24,
waiterQueryId u64@32, sourceEpoch u64@40, remainingNs u64@48,
memberCount u16@56=1..256, sourceKind u8@58, purpose u8@59, zero u32@60.
Allow IDs ненулевые, epoch/source kind/purpose точны; remaining ограничен
original waiter deadline, base expiry, source observation/session и live grant,
на consumer дополнительно вычитается elapsed/RTT. Deny/Unknown: bytes4..63=0.
Header.reply и pending operation связывают ACK с exact WaiterBind sequence;
неверный/late/duplicate ACK не публикует receipt и не продлевает сроки.

NumericAuthorize V2 поле u64@4 называется WaiterReceiptId, НЕ ProducerRRsetId;
размер prefix16 не меняется. Проверяются fresh parent class/use/source flow,
query/resolver/path/frontier/member/epoch и remaining authority. WaiterReceipt
связан с единственным query result: нельзя перенести его в соседний query,
заменить source flow или употребить как общий cache grant. Допустимые numeric
member grants остаются bounded отдельными grants с тем же live parent/binding.

DNS_V2 Cancel target5 — ProducerRRset (лишь owning producer либо issuer epoch
revocation); target6 — WaiterReceipt (лишь owning waiter). Cancel pending Bind
использует существующий request-sequence target, а не угадывает ещё не выданный
receipt ID. Cancel waiter не отзывает base/соседей; cancel/revoke base инвалидирует
derived receipts. IDs/replay tombstones учитываются в общих budgets. Host source
observation выпускается только issuer на Hosts Reserve после revalidation,
не отдельным child ACK. Все Kind53/54/target5/6 запрещены без DNS_V2 negotiation.

Root подтвердил этот исправленный tail. Один canonical codec commit закрепляет message kinds, descriptor/ACK/cancel,
все positive/negative goldens и no-downgrade. Go не должен независимо выбирать
другой HostsSnapshot layout. До завершения codec/parity/review production
decoder/admission остаётся закрытым; существующий ABI260 не меняется.

Основание: dns-completion-scope.md разделы «Обязательный bootstrap binding
(R31)» и «Resource revisions и append-before-use (R31)». Отдельная observation
не подменяет DNS transport, StubBind или user Known<=20ms.
