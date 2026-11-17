# CODEC5: explicit USER datagram parent для hostname physical permission

SOURCE/PURE contract. Runtime admission/protected producer pins не открывает.
SchemaHash=SHA256(ASCII `YONIK-DNS-V2-CODEC-5` + ONE NUL). Descriptor272/ACK40,
Header128, все прежние body layouts/rights/ABI260/mapping4/table11 неизменны.
CODEC4 остаётся отдельным exact pin; он отвергает Kind57/58 и Cancel target9.
При UDP requirement запрещён fallback4/3/2/1. Descriptor/ACK DATA не scope proof.

## Почему acquisition binding необходима

CODEC4 Numeric42 use2/class3 уже синтаксически допускает Destination protocol17.
Но его base Probe8 не содержит USER source/grant. Hosts55 rootId=0, NETWORK55
rootId=service grant, не USER grant. Query/selector/path сами не доказывают связь
с одним из нескольких live UDP originals. Нельзя выбирать «последний»/единственный
flow, алиасить QueryId и SourceFlowId либо использовать TCP control proof.

Добавляются два rights-free сообщения на том же serialized runtime endpoint.
Они требуют отдельно protected reviewed UDP-bootstrap consuming scope5. Прежний
Source4/UDP-ingress eligibility/descriptor5 не даёт этот scope; production pin None
до независимого review нового producer. USER grants/SourceFlow/parent bindings/
contexts/waiters/datagram permissions — разные retained namespaces.

Новый independent protected slot — `native_profile_producer.bootstrap_datagram`:
contract `udp-bootstrap-consumed-parent-member-send-v1`, version1,
contract_sha256 `41fc597be0d881f4d6dbd2843321d9e1a492b19f93a13c5351f632fdf68d4b1c`,
schema_sha256 `c05c312d47ed27ef93db80158cb7bc78f10c6b319d5d4407929885cb192ead03`.
Оба digest — SHA256 exact name+NUL. Scope связывает actual protected record/image/
final config/capsule/exact launch, consuming USER datagram parent и member/send/
close ownership; hash/JSON/ACK сами по себе его не создают. Reviewed patch pin None.
Прежние Source4/Wire4/Release4/UDP ingress records не подменяют этот slot и не
получают автоматически schema5/UDP-bootstrap authority. Candidate не install authority.

## Kind57 DatagramParentBind, exact64, producer→issuer, SCM0/credentials0

Все integers BE. Version u16@0=2; zero@2..7.

| Offset | Type | Поле |
|---|---|---|
|8|u64|QueryId, nonzero/non-MAX, новый invocation query |
|16|u64|существующий USER class1 GrantId, НЕ service/root/permission |
|24|u64|exact SourceFlowId parent grant |
|32|u64|exact USER policy revision |
|40|u64|source epoch, equals Header.binding.epoch |
|48|u16|parent scope <512 |
|50|u8|actual branch 0/1 |
|51|u8|zero |
|52|u32|requested remaining milliseconds1..1000 |
|56|8 bytes|zero |

Header objectId/replyTo=0, sequence новый. Ссылка — locator, не credential.
Issuer проверяет live USER grant/source/revision/subject/scope/branch/checked path,
immutable original UDP tuple/destination и retained R9/R23/R25 provenance3:
association/packet/permit/fingerprint/netns/epoch и ConsumedMatch, live control,
SourceFlow ownership. Fresh independent System UDP Known≤20ms/original expiry+RTT,
Local required=false без attribution. TCP proof/USER DNS/class3/child cookie не годятся.
Из grant issuer выводит full physical frontier с actual carrier17; original
USER destination НЕ подменяется hostname physical endpoint. Peerless UDP закрыт.
Credits pending/history/memory/refs до lookup/materialization/effects; shared caps
64FD/64pending/8MiB/history256 прежние. Пока только single raw SS physical frontier.

## Kind58 DatagramParentBound, exact64, issuer→producer, SCM0/credentials0

Version u16@0=2; status u8@2=Allow1/Deny2/Unknown3. Deny/Unknown bytes3..63=0.
Allow zero@3..7 и поля:

| Offset | Type | Поле |
|---|---|---|
|8|u64|DatagramParentBindingId, новый/nonreuse, отдельный от context/grant |
|16|u64|exact USER parent GrantId |
|24|u64|exact SourceFlowId |
|32|u64|exact QueryId |
|40|u64|exact source epoch |
|48|u32|remaining milliseconds1..1000, ≤requested/original deadlines |
|52|u16|exact parent scope |
|54|u8|exact branch |
|55|9 bytes|zero |

Header objectId=0, replyTo=exact pending57.sequence. ACK не выдаёт Source/DNS/route/
physical authority. На обеих сторонах binding usable только после actual ACK send/
receive. Parent/source/packet deadline не продлевается, exact binding immutable.
Повтор57/query/replay/смена parent/revision запрещены, renewal отсутствует.

## Context и Numeric без изменения прежних bodies

Для context55 с carrier17 обязателен exact ACKed ParentBinding того же query.
Issuer независимо восстанавливает path и проверяет его к parent grant frontier.
Hosts55 сохраняет root0; NETWORK55 имеет свой independent service grant. Одна
binding→один initial context; context renewal сохраняет original parent/deadline,
не позволяет rebind/Source mutation. Waiter использует СВОЙ query/binding/context,
не authority соседнего waiter. Cancel источника/parent/context отзывает derivatives.

Source5 повторно валидирует retained snapshot, chosen row/question/member и UDP
parent. Resolver transport (TCP/UDP peer) независимо разрешается существующим
resolver-only permit ДО Reserved36/Connect. SS ciphertext не DNS transcript.

Numeric42 use2/class3 Probe8 остаётся прежним. WaiterReceiptId связывает exact
binding/context/member/path/source. После проверок immutable fields и capacity
preflight, но до irreversible history/consume, issuer проверяет trusted datagram
lineage; после durable route — ещё раз перед GRANT/send publication. Возвращается
прежний Grant19 class3/flow0/required0/owner0, но хранится только как private
BootstrapDatagramPermission. Это НЕ TCP BootstrapPhysicalPermission/USER/service grant.
Одно effectful physical datagram attempt на Consumed original; cached DATA/другой
waiter не позволяют повторно отправить тот же packet. Packet bytes/metadata
retained до credited transfer/destruction; второй permit до release запрещён.
Actual consuming open/send требует одновременно exact live USER parent и exact
datagram permission + checked carrier/member/association/netns/epoch. Не generic
class3 tag. Revoke linearized, cancel одного flow не закрывает соседнюю association.

## Cleanup

Cancel47 target9 — DatagramParentBindingId (остальной body24 прежний), Canceled48
обычный exact pending reply. Existing source/USER/context/request cancel сначала
отзывает use, затем durable per-permission tickets/ref retirement. ACK KnownClosed
только после всех собственных refs/operations; Unknown sticky, custody/credits
сохраняются до actual worker+rules KnownClosed. Повтор terminal ACK не повторяет
close/release и не возрождает binding. Старые TCP/R61/R65/ownership fences не меняются.

Canonical vectors: `tests/fixtures/xray-profile-channel-v3/dns-v2-codec5.json`;
stdlib field-table reproducer `dns-v2-codec5-pack.py --check`. Это wire DATA,
не runtime proof и не разрешение расширить старые reviewed scope pins.
