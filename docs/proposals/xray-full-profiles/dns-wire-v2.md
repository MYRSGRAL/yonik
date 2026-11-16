# DNS_V2: согласованный HostsSnapshot wire tail

## Canonical operation envelope и negotiation

Все integers BE. DATA codec не создаёт authority. Runtime Header128 остаётся YNKCAP01
version1 с exact launch binding; это не frozen ABI260 role frame. DNS_V2 kinds:
35 Reserve,36 Reserved,37 PhysicalAck,38 LogicalBind,39 LogicalAck,40 Publish,
41 Published,42 NumericAuthorize,43 Append,44 AppendAck,45 Retire,46 Retired,
47 Cancel,48 Canceled,52 PhysicalBind,53 WaiterBind,54 WaiterBound,
55 BundleAcquire,56 BundleGranted.
Requests35/38/40/42/43/45/47/53/55 идут producer→issuer, ACK идут обратно;
PhysicalBind52 — producer→issuer на proof channel: ровно raw DNSPHY02/192,
БЕЗ runtime Header128. Число52 — enum/corpus discriminator, не поле этого
proof packet. Runtime decoder отвергает wrapped Header128+PhysicalBind.
Runtime rights/credentials0;
PhysicalBind ровно1 rights+1 credentials. Truncation/лишние rights — отказ;
закрытие unexpected FD остаётся обязанностью receiver, не borrowed DATA codec.
objectId=0, sequence ненулевой/nonMAX; request.reply=0, ACK.reply ненулевой и
сравнивается с exact pending sequence, без публикации на duplicate/late ACK.

Descriptor272: magic DNSNEG02@0, version u16=2@8, length u16=272@10,
flags u32=0@12; exact encoded LaunchRecord192@16; schemaHash32@208;
mapping u16=4@240, tables u16=11@242, aggregate u32=8388608@244,
FD u16=64@248,pending u16=64@250,resources u16=64@252,
RRmembers u16=256@254,history u16=256@256,reserved14=0@258.
schemaHash=SHA256 ASCII `YONIK-DNS-V2-CODEC-3` + один NUL byte. После первого
canonical commit изменение field/offset/семантики требует нового CODEC-N/hash;
этот identifier нельзя переиспользовать для несовместимого parser.
ACK40 = ASCII DNSACK02 + SHA256 exact Descriptor272. Descriptor и ACK rights0.
Codec negotiation token — только DATA matching; issuer обязан независимо
проверить protected producer/launch/manifest и собственную readiness.
Missing token, wrong version/schema/mapping/caps/launch/hash → deny, без V1
fallback. Legacy Frame decoder отвергает весь DNS kind set и descriptor magic.

### Порядок setup и граница CODEC-1

После proof bootstrap выполняется прежний HELLO → ADMIT → ADMIT_ACK. Producer
после отправки ADMIT_ACK, а issuer после его точной проверки переходят в отдельную
setup-стадию на существующем runtime endpoint: producer отправляет raw Descriptor272,
issuer отвечает raw ACK40. Оба сообщения без Header128 и SCM_RIGHTS/credentials.
Этот обмен завершает единственный setup reader/owner до передачи endpoint monitor;
до успешного ACK запрещены DNS features и другие runtime sends. Proof bootstrap
до HELLO, frozen bootstrap и FD counts не меняются. Все стадии используют исходный
абсолютный admission deadline без продления. Missing/bad/late ACK, лишние ancillary,
cancel/revoke или ошибка передачи запрещают запуск monitor и требуют существующий
cleanup с сохранением Unknown custody; fallback отсутствует.

Исторический CODEC-1 проверяет форму DNSBundleId, но не задаёт его issuance. Legacy
AUTHORIZE18/GRANT19 class3 выдаёт ServiceGrantId, а не полный DNS chain bundle;
приравнивать эти namespaces либо выпускать bundle на child запрещено. До отдельного
canonical acquisition/ACK, связывающего issuer-issued bundle с exact query/private
source, root service grant и всеми выбранными class3 hops, production network
Reserve остаётся Unsupported. Reserve/Reserved echo не является issuance. Новый
acquisition layout и его schema/hash закрепляются отдельным canonical commit;
DATA roundtrip CODEC-1 не подтверждает готовность этого production перехода.

### CODEC-2: выдача полного class3 bundle

Canonical CODEC-2 использует schemaHash SHA256 ASCII
`YONIK-DNS-V2-CODEC-2` + NUL, при прежних descriptor/version/ABI. CODEC-1
не принимает следующие kinds. Codec/goldens проверяют только DATA; до реализации
issuer authority и межъязыковой проверки этот раздел не разрешает negotiation
или network Reserve в production.

BundleAcquire55 — producer→issuer, обычный Header128/request.reply0/rights0.
Body fixed72 + canonical class3 base + original name + pathCount*4, максимум2164:
version u16@0=2,flags u16@2=0,zero u32@4;
rootServiceGrantId u64@8,queryId u64@16,sourceEpoch u64@24,
renewBundleId u64@32 (0 только initial),remainingNs u64@40 (1..1s);
baseLen u16@48 (1..815),pathCount u16@50 (1..256),qtype u16@52 (1/28),
queryOptions u16@54,udpPayload u16@56,originalLen u16@58 (1..253),
resolverRow u16@60 (неFFFF),zero u16@62.
expectedBundleRevision u64@64 (initial0, renewal exact retained revision).
Base — прежний canonical AUTHORIZE class3, со всеми legacy FFFF/zero rules;
query/resolver/private source binding должен совпадать с retained root grant.
Original name имеет прежнюю Reserve grammar и сохраняется без подмены. EDNS
options/payload имеют прежние Reserve правила. Tail после base/name — ordered
rows: scope u16@0 (неFFFF),branch u8@2 (0/1),zero u8@3. Первый row — actual
root handler decision; остальные — решения того же native chooser для каждого
последующего logical handler, включая промежуточные remote-host hops. Child
не передаёт subject/chain/frontier/stream/action/carrier и не назначает hop grants.

Issuer проверяет live root class3 ServiceGrant с exact resolver/question/private
source/revision/epoch и текущей owner freshness. По каждому scope/branch он
независимо восстанавливает subject, table3 chain, stream, endpoint, action и
carrier из exact retained manifest; next input равен previous carrier. Native
branch ограничивается manifest mask. Root должен принадлежать разрешённому
resolver route; path обязан точно закончиться на terminal leaf без пропусков,
лишних rows, циклов или remote-host promotion в physical leaf. Если current
manifest не позволяет установить root/path binding, результат Unsupported.

До Allow issuer выполняет отдельную class3 authorization/route installation
каждого hop и сохраняет ordered private DNSHopPermit records в новом DNSBundle.
DNSHopPermit не является user class1 grant или экспортируемым ServiceGrantId:
его identity — issuer-retained (DNSBundleId, path index), со своим route ticket,
deadline и cancellation state. ServiceGrantId сам эти permits не заменяет.
Physical resource или logical stream публикуется только после полного bundle;
partial failure требует retirement всех уже созданных tickets, Unknown сохраняет
custody. DATA path, tag, child bool и самостоятельно выданный ID authority не дают.

BundleGranted56 — issuer→producer, exact pending55 reply/rights0, body fixed64:
version u16@0=2,status u8@2 (Allow1/Deny2/Unknown3),bytes3..7=0;
DNSBundleId u64@8,rootServiceGrantId u64@16,queryId u64@24,sourceEpoch u64@32,
remainingNs u64@40,pathCount u16@48,zero6@50,bundleRevision u64@56.
Allow требует nonzero/nonMAX IDs/revision, count exact request1..256 и
remainingNs>0, ограниченный minimum всех hop/root/session/owner deadlines.
Producer вычитает полный request RTT и проверяет live root private receipt;
System user owner не получает новый срок20ms от ACK. Deny/Unknown bytes3..63=0.

Initial выдаёт новый bundleId/revision1. Renewal требует exact live bundle,
того же root/query/options/original/source/path; возвращает тот же ID/revision+1
без wrap, после обновления каждого permit и общего заключительного freshness
fence. На bundle допускается только один pending renewal; duplicate/reordered
request или stale expected revision отвергается до effects. Expired/canceled
bundle не возрождается. BundleGranted не выдаёт RRset
или WaiterReceipt. Reserve35 network roles ссылаются на этот exact bundle и
root grant; чужой query/path/epoch/root отвергается. Каждому waiter нужен свой
bundle, даже при общем cached ProducerRRset. Hosts bundle0 не меняется.

Go хранит opaque live bundle вместе с actual ordered native decisions в private
DNS context и использует DNS-specific guards для каждого handshake/send/reuse;
legacy class0/1 ProfilePrepareChain не превращается в class3 authority. Каждый
guard проверяет matching path index и весь live bundle/root; explicit logical
consumer не заменяется соседом shared pool. Resource Bind/Append и LogicalBind
сверяют этот же bundle/path. Remote DNS proxy peer не становится resolver peer.

Cancel47 получает отдельный target8 DNSBundle; target7 остаётся Reservation.
Bundle cancel/revoke отзывает все его hop permits и dependent exchanges/resources/
waiter authority с durable retirement до KnownClosed; соседние bundles и общий
ProducerRRset не отзываются. Root/source/epoch revoke каскадно отзывает dependents.
Acquire/renewal и все permits заранее резервируют общие pending/history/memory/
route credits; pathCount256 не увеличивает существующие aggregate caps. Каждый
новый hop учитывается до effects, исчерпание даёт отказ до installation.

## Routine bounded records

Следующая coordinated revision для service bootstrap и полного Hosts path
закреплена в [CODEC4 contract](bootstrap-service-codec4.md); текущий CODEC3 её
не принимает. Kinds/offsets не расширяются, schema/no-downgrade обязательны.

### Canonical revision CODEC-3: DirectSocket release receipt

Этот контракт требует coordinated schemaHash SHA256 ASCII
`YONIK-DNS-V2-CODEC-3` + NUL без fallback на CODEC-2. До реализации typed producer
binding и CODEC-3 admission обычный DirectSocket Retire остаётся Unknown.
Новые kinds/layouts не вводятся: Retire24/Retired40 сохраняются. Caller receipt
сам по себе не является kernel measurement или producer authority.

Protected build/install record должен отдельно связывать reviewed
`direct-dns-consuming-close-join-v1`, его contract digest, exact source/patch/
toolchain/build inputs и final ELF digest с negotiated schema и exact launch.
Существующий UDP producer contract автоматически DNS capability не выдаёт.
Decoder, caller hash/env/JSON или произвольный child ACK opaque released proof
не создают. Issuer создаёт private typed release proof только из проверенного
protected record, authenticated launch и retained proof/resource binding.

Pinned Go DirectSocket factory/Conn не допускает неучтённых aliases/dup/tasks.
Stopping запрещает новые factory/Read/Write, отменяет context, закрывает actual
underlying Conn и sender duplicate и join-ит все task owners. Только после
подтверждённого localDone и завершения pending send/cancel допускается Retire.
Uncertain close/join запрещает receipt и удерживает Unknown custody.

Порядок строго Proof4 → Resource3 → physical Reservation7 → parent Reservation7
→ Exchange2, каждый следующий RPC только после exact предыдущего Allow ACK.
Proof Retire фиксирует irreversible ProducerReleased, запрещает use и снимает
все proof consumers/refs после их подтверждённого release/join. Proof ACK Allow
не утверждает закрытие physical receiver FD. Resource Retire требует terminal
proof, отсутствие refs/pending bind/reply/tasks; затем consuming close retained
socket и namespace handles. Только подтверждённый cleanup даёт Resource Allow.
Состояние published physical reservation переводится в terminal before cancel,
иначе её прежний live-resource guard не может быть обойдён. Route tickets и
durable firewall bookkeeping закрываются отдельно существующим bundle lifecycle;
Resource ACK их retirement не подменяет. Reverse order не получает Allow.

Terminal IDs/revisions не переиспользуются. Результат cleanup неизменен и
оплачен history/memory до effects; write(false)/повторная отправка не повторяет
release/close. Unknown поглощает дальнейшие попытки и сохраняет custody/error;
повторный raw close по числовому FD после uncertain close запрещён. Shared
FD64/pending64/history256/8MiB caps и постоянный RX reserve сохраняются.

Authority expiry запрещает новое use/GRANT, но не запрещает закрывать retained
obligations. Terminal cleanup ACK допустим в исходном bounded cleanup window≤1s
после проверки identity/record/retained state; он не продлевает grant/owner proof
и не возрождает flow. Loss/late ACK, failed close/join/release или timeout не
считаются KnownClosed и не разрешают возврат producer credits. Stop сохраняет
terminal result/неопределённые custody до supervisor fences.

Common request prefix8: version u16=2@0, flags/reserved bytes2..7=0, кроме
явно перечисленных fields. Common ACK prefix8: version u16=2@0,status u8@2
(Allow1/Deny2/Unknown3), bytes3..7=0. Deny/Unknown ACK bytes3..end=0, кроме
Retired Unknown, где разрешён exact custody report, описанный ниже.

Reserve fixed96 + original/query/base: role u8@2 (Exchange1/Physical2/Waiter3),
zero bytes3..7; queryId8,bundleId16,serviceGrantId24,
sourceFlowId32,sourceFlowRevision40,sourceEpoch48,remainingNs56 (все u64);
resolverRow u16@64,subject66,endpoint68,scope70,qtype72;
purpose/sourceKind/carrier/parentClass/use/branch u8@74/75/76/77/78/79;
originalLen/queryLen/baseLen u16@80/82/84,zero u16@86;
Для Exchange/Waiter: queryOptions u16@88 (RD/CD/DO/EDNS/AD bits0..4),
udpPayload u16@90,zero u32@92. Для Physical эти8 bytes — nonzero
parentExchangeReservationId u64@88, options берутся из retained parent.
Затем exact original bytes, canonical query bytes, canonical base.
Total≤1024; original1..253,query0..253,base1..1024; все суммы до allocation.
Network source: query>0,qtype1/28,bundle/grant nonzero,resolver!=FFFF.
Hosts только role3: purpose3/source2,qtype0,resolverFFFF,
bundle/grant/queryLen/options/payload0.
EDNS absent → udpPayload0/DO0; EDNS present → payload512..4096.
FlowId/revision оба0 либо обаnonzero; parentClass1 требует flow, class2 flow0;
class3 допускает user-DNS либо service flow0. use1 только purpose1; use2 только
purpose2/3. Branch0/1, carrier6/17, scope/subject!=FFFF, original immutable.
Provider endpointFFFF; bootstrap endpoint!=FFFF. В Physical role endpoint/scope/
carrier — actual physical frontier (Direct DNS может иметь endpointFFFF);
issuer выводит его из parent bundle/graph, а не принимает индекс как proof.
Canonical base ниже. Для query существует не больше одного Exchange role;
Physical reservations и waiter-only reservations ссылаются на собственную
live authority, не создают новый logical exchange под тем же query.

Reserved64: reservationId8,queryId16,bundleId24,contextId32,
sourceEpoch40,remainingNs48 u64; physicalCredits u16@56,pendingCredits u16@58,
role u8@60 (echo Reserve.role),reserved3@61. Allow pendingCredits1;
Exchange: bundle/context nonzero, contextId=issuer-issued ExchangeId,
physicalCredits0. Physical: bundle/context nonzero, contextId=exact retained
parentExchangeReservationId, physicalCredits1..64 (все оплаченные FD credits,
включая necessary scratch/namespace; capacity не обещает64 resources).
Waiter network: bundle nonzero/context0/physicalCredits0; Waiter Hosts:
bundle0/context=SourceObservationId nonzero/physicalCredits0.
Observation выдаётся issuer только после retained-source revalidation и хранит
полный binding; Reserve не принимает child observation ID.

PhysicalBind192 — точный R31 DNSPHY02 record. Numeric first-hop Destination
ниже, zero padding до24. PhysicalAck64: physicalReservationId8,
PhysicalResourceId16,queryId24,bundleId32,sourceEpoch40,remainingNs48 u64,
reserved8@56. ACK не разрешает DNS send без LogicalBind ACK. Header.reply
PhysicalAck совпадает с pending Physical Reserve35.sequence: после Reserved36
этот pending переходит в waiting-SCM/PhysicalAck, не освобождается и не создаёт
второй pending slot. PhysicalBind.physicalReservation связывает его с этим
runtime request без добавления sequence/Header в raw192. Parent exchange
reservation/query/bundle/epoch/path сверяются независимо. Duplicate Reserved,
late SCM/ACK и lost/ambiguous ACK не создают новую reservation/retry authority.

LogicalBind64+8N: version u16@0=2,kind u8@2(Direct1/Proxy2),flags0@3,
count u16@4=1..64,zero u16@6; reservation/query/bundle/exchange/stubBind/
producerSequence/remainingNs u64@8/16/24/32/40/48/56; ordered distinct
PhysicalResourceIds@64. Direct count1; Proxy count1..64. stubBind0 только
nonloopback (проверяет issuer по retained resolver). LogicalAck64:
exchangeId8,TransportProofId16,queryId24,bundleId32,revision40=1,
remainingNs48 u64; count u16@56=1..64,kind u8@58=1/2,zero5@59.

Append — точный R31 fixed48+8N. AppendAck56: exchangeId8,TransportProofId16,
appendSequence24,newRevision32,remainingNs40 u64; totalCount u16@48=1..64,
reserved6@50. Allow newRevision>=2. Sequence/revision match и union uniqueness
между revisions проверяет issuer; codec проверяет distinct текущего vector.

Retire24: version u16@0=2,target u8@2(Resource3/Proof4),flags0@3,zero4@4;
id u64@8,revision u64@16 (Resource0,Proof nonzero). Retired40: version u16=2,
status u8@2,target u8@3,zero4@4,id8,revision16 u64,pending u16@24,
duplicates u16@26,joined u8@28,zero3@29,watermark u64@32. Allow требует
pending=duplicates=0/joined1; Unknown3 допускает counts0..64/joined0/1,
удерживает custody, не KnownClosed. Deny2 bytes3..39=0. watermark не является
compaction proof или разрешением reuse IDs; history256 остаётся ограничением.

Cancel24: version u16=2,target u8@2,flags0@3,zero4@4,id u64@8,
reason u16@16,zero6@18. Targets1RequestSequence/2Exchange/3Resource/4Proof/
5ProducerRRset/6WaiterReceipt/7Reservation. Cancel reservation отзывает её
pending observation; отдельного child-issued observation ACK/cancel namespace
нет. Canceled32: common ACK,id u64@8,watermark u64@16,zero8@24.
Allow id/watermark nonzero; Deny/Unknown bytes3..31=0. Ownership, cleanup,
sibling isolation и bounded tombstones проверяются issuer, не codec.

## Canonical base и numeric Destination

NumericAuthorize42 — exact root prefix16, WaiterReceiptId u64@4.
Reply — existing GRANT19/56 с existing Frame decoder, exact pending42 и
сохранением parent class/required/fresh owner rules. Новый DNS ACK не добавляется;
private use/binding остаются в issuer/grant context, не в выдуманном tail GRANT.
Canonical base по parentClass1:
existing AUTHORIZE class1; parentClass2: exact PROBE8 purpose1; parentClass3:
existing AUTHORIZE class3 либо exact PROBE8 purpose2 (service/bootstrap flow0).
Base type определяется parentClass и length8 для PROBE; arbitrary raw config
не является base. Codec проверяет syntax, issuer — immutable source/path/class.
Reserve использует те же canonical base формы.

DNS_V2 numeric Destination — собственная compact encoding (не изменение
legacy Destination8): family u8@0=4/6,carrier u8@1=6/17,port u16@2 nonzero,
addressLen u8@4=4/16,reserved u16@5=0,raw address@7. Total11/23 bytes.
Domains, mapped/unspecified/multicast/broadcast forbidden. Loopback/private
numeric data не доказывают mandatory route/stub eligibility. PhysicalBind
дополняет encoding нулями до24. NumericAuthorize total≤1063, no trailing bytes.
use1 LogicalDestination не принимает Bootstrap; use2 PhysicalFirstHop требует
полного BootstrapBinding/epoch/member/actual carrier, issuer проверяет их до
durable install/GRANT. Codec не создаёт grant на основании member/index/hash.

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

Canonical DATA API находится в `profile_channel::dns_v2`: borrowed
`Record`/`View<K>`, `DnsFrame`, отдельный raw192 `PhysicalPacket`,
`Negotiated`, `HostsView`, `SnapshotRoleView`; typed IDs не являются grants.
Encode копирует immutable validated view, не reparses JSON и не аллоцирует.
`Record::decode` — body syntax; `DnsFrame::decode` дополнительно проверяет
launch binding, direction, ancillary shape, source epoch и exact pending reply.
Caller использует existing global direction Sequence и single-owner pending
operation: проверяет expected ACK kind/duplicated refs, потребляет pending один
раз и применяет original absolute deadlines/RTT. Статeless DATA decode сам
не выдаёт cache/waiter/Run authority и не заявляет replay-safe issuer lifecycle.
Legacy Frame продолжает отвергать все DNS_V2 kinds; actual negotiation/issuer
plumbing и protected producer checks — следующий milestone, gates false.

Независимый corpus — `tests/fixtures/xray-profile-channel-v3/dns-v2-canonical.json`,
reproducer `dns-v2-pack.py --check` (Python stdlib field tables, не Rust dump).
Для больших bounds vectors bytes собираются из offset/type/value tables,
включая fill(byte,count), и сравниваются с body/frame SHA256. Нормальные vectors
дополнительно имеют exact hex. u64 в JSON читаются без float64 round-trip
(например Go Decoder.UseNumber/RawMessage), включая MAX rejection vectors.
DNS maximum payload проверяет только codec bounds, не валидность RRset/TTL.
Numeric body1063 — budget bound; largest current existing canonical base815
даёт854 bytes с compact IPv6. Padding base до1024 не является допустимой base.

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
