# DNS_V2: дополнение wire для root interop review

Статус: конкретный вариант недостающего HostsSnapshot tail, ещё не codec
authority. Нормативные PhysicalBind192, Append48+8N, Publish144 и
NumericAuthorize16 из dns-completion-scope.md сохранены. Runtime gates false.
Этот документ не разрешает V1 fallback или synthetic DNS response.

## HostsSnapshot tail: предлагаемый единственный layout

Publish purpose=3/sourceKind=2 использует этот tail после fixed144; request,
response lengths и transportProofId/proofRevision строго0. Никакого TTL,
DNS ID, qtype, resolver peer или DNSBundle вместо snapshot observation.
Все integers BE. Reserved bytes строго0. Строки без NUL/padding.

| Offset | Поле |
| --- | --- |
| 0 | magic[8]=DNHOST02 |
| 8 | version u16=2 |
| 10 | total tail bytes u16=136+keyLen+originalLen+2*memberCount |
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
| 124 | chainCount u16=0..4 |
| 126 | reserved u16=0 |
| 128 | chainRows[4] u16, ordered checked path, unused slots=FFFF |
| 136 | pinned-netgo canonical lookup key[keyLen] |
| next | immutable original hostname[originalLen], case/bytes preserved |
| next | ordered distinct member indices[memberCount] u16 |

Maximum tail674, Publish body818. Indices относятся к exact retained asset,
не к producer-supplied address vector. Source/asset hashes только matching:
без retained source FDs, identity revalidation и issuer observation отказ.
Canonical key обязан совпасть с pinned lookup original hostname; hostsRow alias
сравнивается с этим key. Member indices должны быть внутри addresses данной
строки и сохранять исходный порядок. Table11 mapping4 обязан иметь bit2;
Application-only bit1 не разрешает bootstrap. Bootstrap endpoint/subject/
scope/branch/carrier/chain независимо выводятся issuer из closed graph.

SourceObservationId выпускает issuer только после retained-source revalidation;
producer его не выбирает. remainingNs — переносимый остаток, не чужой monotonic
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

## Точечная синхронизация перед codec

Root: подтвердить этот tail либо вернуть конкретное поле/offset. После этого
один canonical codec commit закрепит message kinds, descriptor/ACK/cancel,
все positive/negative goldens и no-downgrade. Go не должен независимо выбирать
другой HostsSnapshot layout. До подтверждения этого варианта production decoder
не принимает DNHOST02; существующие records/ABI260 не меняются.

Основание: dns-completion-scope.md разделы «Обязательный bootstrap binding
(R31)» и «Resource revisions и append-before-use (R31)». Отдельная observation
не подменяет DNS transport, StubBind или user Known<=20ms.
