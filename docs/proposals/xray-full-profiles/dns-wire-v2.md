# DNS_V2: согласованный HostsSnapshot wire tail

Статус: root принял layout с коррекцией полного retained path вместо chainRows[4].
Это specification для codec/goldens, не production authority или runtime PASS.
Нормативные PhysicalBind192, Append48+8N, Publish144 и
NumericAuthorize16 из dns-completion-scope.md сохранены. Runtime gates false.
Этот документ не разрешает V1 fallback или synthetic DNS response.

## HostsSnapshot tail: единственный layout

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

Root подтвердил этот исправленный tail. Один canonical codec commit закрепляет message kinds, descriptor/ACK/cancel,
все positive/negative goldens и no-downgrade. Go не должен независимо выбирать
другой HostsSnapshot layout. До завершения codec/parity/review production
decoder/admission остаётся закрытым; существующий ABI260 не меняется.

Основание: dns-completion-scope.md разделы «Обязательный bootstrap binding
(R31)» и «Resource revisions и append-before-use (R31)». Отдельная observation
не подменяет DNS transport, StubBind или user Known<=20ms.
