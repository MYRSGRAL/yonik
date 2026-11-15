# P4: незавершённый native full-profile follow-up

Статус: частичный DNS prerequisite; full-profile authority и transport ownership
не реализованы. Builder намеренно не подключает этот patch и не объявляет feature.
Замороженные descriptors, ABI260 и upstream pin не изменяются.

## Реализованная часть

`app/dns/nameserver_local.go: LocalNameServer.QueryIP` передаёт query context в
`localdns.Client.LookupIPWithContext`. Обе resolver-ветки сохраняют этот context;
старый `LookupIP` остаётся совместимым entrypoint. Отменённый query завершается
до resolver. Provider `localhost` не заменяется другим сервером.

Это сохраняет context values, но не проверяет resolver snapshot или allowed peer.
Legacy `LookupIP` по-прежнему не получает flow context. Использовать изменение
как доказательство DNS authorization запрещено.

## Продуктовый blocker: закрытый issuer отсутствует

Проверенный retained archive SHA256:
`e5184047fd1380472f69114fb8173a0adfd8c50970560eceb9c87fcba0bb35e9`.

- `common/yonikbroker/bootstrap_linux.go: Bootstrap/DecodeBootstrap` декодирует
  session/generation/invocation и Binding, но не admitted manifest.
- `common/yonikbroker/wire.go: Kind/DecodeFrame/EncodeLookup` допускает только
  frozen Hello/Features/Attach/Lookup/Reply/Revoke. Lookup содержит IP tuple;
  Reply доказывает owner, но не policy decision, destination/subject/chain,
  sourceFlowId или provenance. Отдельного service/probe admission нет.
- `common/yonikbroker/closed_tun_linux.go: closedAttach` — private constructor;
  комментарий и codec descriptor явно отмечают отсутствие production issuer.
  `CarryClosedSession` копирует уже имеющийся consumer, не создаёт его.
- `common/yonikbroker/routing.go:65–99 guardEntry` отвергает missing consumer.
  Вызов `NewSession` с известным digest не заменяет trusted ingress admission.

## Минимальный следующий контракт для root/P5/P6

Нужен отдельный versioned authenticated carrier, не изменение ABI260: trusted
host issuer передаёт bounded admitted manifest, exact emitted digest, generation,
session identity, expiry/caps, resolver snapshot и allowed peers. Original ingress
и policy issuer должны отдельно выдавать FlowGrant с sourceFlowId, attribution,
provenance/required, исходным и разрешённым destination, subject/chain, expiry и
cancel. Только manifest service issuer выдаёт ProbeGrant. Decoder обязан иметь
конкретный production callsite; произвольные JSON/env/context setters исключены.

Точные wire layout, transport/custody, issuer callsite, authentication и replay
rules этого extension пока отсутствуют в contracts.md. Root должен назначить
их реализацию владельцу host/ingress boundary; Rust helper intent codec сам по
себе такого issuer не создаёт. После согласования можно подключить closed APIs
в yonikbroker и observatory, затем session-owned physical factories и logical
guards в Hysteria/gRPC/XHTTP. DNS hooks должны использовать тот же checked grant
и resolver snapshot. До этого full-profile запуск должен оставаться закрытым.

## Проверки этой частичной поставки

Go `go1.27.1-X:nodwarf5 linux/amd64`, `GOPROXY=off GOSUMDB=off
GOTOOLCHAIN=local`, `-p=1 -mod=readonly`. Скомпилированы localdns test ELF и
Xray main; main не запускался. Выполнен только
`TestYonikCancelledQueryDoesNotResolve`: PASS. RED не зафиксирован; полное
TDD/authority regression acceptance не достигнуто. Builder tests не менялись.
Reverse `git apply --check` на final source прошёл.

Evidence вне TTL:
`/home/myrs/projects/yonik/local/orchestration/evidence/p4-dns-966ee520/`.
До test execution сохранены base/final source archives, compiler ELF и test ELF,
их hashes в before-execution.json; команда и вывод — test-result.json.
Full runtime PASS, strict fresh-base patch-chain verification, transport guards,
grant/race/caps tests и builder apply/pins этой поставкой не заявляются.

## SOURCE proposal revision 1: YNKCAP01 (для согласования root)

Это конкретное предложение отдельного extension, ещё не утверждённый wire/API.
Ни Go implementation, ни новая сборка для этого proposal не выполнялись.
Source anchors ниже относятся к `src/` внутри retained archive, а не к строкам
патча. Полный список 22 прочитанных Go sources и SHA256 сохранён в
`/home/myrs/projects/yonik/local/orchestration/evidence/p4-dns-966ee520/issuer-source-hashes.json`.
Archive SHA256 остаётся указанным выше. Frozen ABI260 и descriptors не меняются.

### Где действительно есть исходные данные

| Source anchor | Реальный факт | Предлагаемая точка проверки |
| --- | --- | --- |
| `proxy/tun/handler.go:214–262 HandleConnection` | Есть stack connection, `RemoteAddr`, исходный destination; context унаследован от TUN. `session.NewID` — только logging ID | До sniff/DispatchLink создать private ingress receipt из owned TUN session + canonical tuple. Новый receipt на flow, не общий consumer из Init |
| `app/proxyman/inbound/worker.go:61–127 tcpWorker.callback` | Accepted connection даёт реальные RemoteAddr/LocalAddr, но destination SOCKS ещё не разобран | Зафиксировать immutable local ingress tuple и lifetime accepted connection. Для broker owner lookup tuple разворачивается в ориентацию client local → listener remote |
| `proxy/socks/server.go:122–164 processTCP` | Успешен SOCKS handshake, разобран destination; User.Email — protocol account, не executable identity | После handshake дополнить receipt request destination; выдать sourceFlowId и запросить ingress authorization до DispatchLink |
| `proxy/http/server.go:116–161,191,246` | HTTP auth опциональна; CONNECT или отдельный plain request знает destination | Отдельный receipt на каждый request, включая keep-alive (`goto Start`); HTTP account не заменяет OS attribution |
| `proxy/socks/server.go:238–283 handleUDPPayload` | Источник UDP уточняется после первого read; destination может меняться на каждом packet | Проверять UDP association и реальный tuple отдельно от TCP control owner, создавать destination-bound child receipt |
| `app/dispatcher/default.go:268–281,328–342` | Existing guard стоит ДО записи OriginalTarget; incoming context может быть служебным | Принять только private ingress/probe receipt, не mint по Inbound.Tag или caller destination |
| `app/dispatcher/default.go:303–319,361–377,439–517` | Sniff меняет Target/RouteTarget; forced tag, PickRoute или default выбирают handler | После `ob.Tag = handler.Tag()` и до `handler.Dispatch`: запросить checked decision для exact original/effective destination + subject/chain; здесь материализовать opaque FlowGrant |
| `transport/internet/udp/dispatcher.go:71–104,108–120` | `v.conn` возвращается без повторного Dispatch, destination не входит в reuse check | До любого WriteMultiBuffer проверять current child grant; grant первого packet не разрешает следующие destinations |
| `common/mux/server.go:165–264` | New mux/XUDP request несёт новое Target, но наследует parent context | Не наследовать grant родителя как разрешение child; для owned SOCKS/HTTP reject inbound mux sentinel до создания ServerWorker |
| `features/policy/policy.go:13–76` | Policy — timeouts/stats/buffer, не executable ACL | Не считать `ForLevel` trusted policy decision |
| `common/session/session.go:16–24,36–46` | ID не криптографический; Inbound — mutable metadata | sourceFlowId — новый session-local monotonic ID + invocation binding, не session.NewID |

В этих Go ingress НЕТ одновременно authenticated attribution и checked app ACL.
Authenticated owner появляется только после `routing.go:103–133
lookupAuthenticated` через frozen broker; grant разрешения ещё не появляется.
`closed_tun_linux.go:71` создаёт session consumer без per-flow tuple; поиск по
production sources yonikbroker не нашёл отдельного flow consumer constructor
или присваивания `c.flow`. Нельзя считать inherited consumer готовым ingress proof.

### Чего extension не должен дублировать

ABI260 уже проверяет nonce/digest/epoch, peer credentials/pidfd, tuple, owner status
и ограниченный OwnerTTL=20ms (`wire.go:15–23,63–83`; `bootstrap_linux.go:
ReceiveAuthenticated`; `routing.go:103–133`). Не передавать через новый protocol
копию executable path, PID/inode или произвольный `Known=true`. Frozen Reply.Cookie
информационный, не authority token. Сохранять свежую owner revalidation на
BeforeRouting/AfterDNS/BeforeDial и logical reuse; новый grant TTL не продлевает её.

Новые security данные: admitted run/manifest; immutable sourceFlowId и original
tuple/destination; provenance class; attribution-required; checked decision
revision и scope destination/subject/chain; cancellation/revoke generations;
resolver snapshot/peers; resource caps. Они связывают существующий owner proof
с конкретным разрешённым действием, которого ABI260 не описывает.
Rule names, display tags, account email, access logs, route reasons и counters —
диагностика; на wire не нужны. Provider subject string заменяется bounded index
в manifest; индекс задаёт scope, сам по себе не credential.

### Один carrier и его authentication/custody

Предлагается отдельный inherited `AF_UNIX/SOCK_SEQPACKET` control FD YNKCAP01,
отличный от ABI260 channel. Не открывать pathname socket, не читать credential
из JSON/env. Protected launcher передаёт fixed FD slot и sealed launch record;
env/argv могут лишь обозначить slot, не создавать authority. Worker endpoint
проверяет socket type, peer credentials каждого frame и trusted host pidfd/starttime,
связанные с проверенным launch record. Host endpoint проверяет exact launched
worker pidfd/starttime/uid и approved executable/config seal. Самостоятельно
запущенный core с похожими FD не допускается host; знание digest не admission.

Оба режима требуют один и тот же protected launch rendezvous. На LocalSocks
достаточно владения каналом от обычного процесса того же UID только для удобства,
но недостаточно для требуемой trust boundary. В этом proposal LocalSocks также
получает канал от protected issuer; TUN/route authority ему не выдаётся.
Если root решит сохранить unprivileged standalone LocalSession без protected
handoff, production issuer для него остаётся отсутствующим: это unresolved
deployment choice, а не повод принять loopback/tag/password как OS attribution.

Launch metadata: `mode`, session[16], invocation[16], nonce[32], digest[32],
epoch u64, generation u64, expected peer pid/starttime, expected role. Его exact
FD layout/OS seal и Rust custody должны быть определены root вместе с worker
boundary. FD ownership: launcher закрывает child endpoints после spawn; worker
принимает свой endpoint один раз, CLOEXEC; receiver закрывает все unexpected
SCM_RIGHTS даже при decode failure. Runtime extension frames несут ноль FD.
ABI260 TUN FD по-прежнему передаётся только прежним Attach; extension не копирует
его и не принимает raw sockets. Один control owner serializes receive/write;
никаких конкурирующих monitor readers на том же FD.

### Wire layout и лимиты proposal

Все integer big endian; reserved=0; неизвестный kind/version/flag — отказ.
Fixed header 128 bytes: magic[8]=YNKCAP01 @0; version u16=1 @8; kind u16 @10;
total u32 @12; sender sequence u64 @16; replyTo u64 @24; session[16] @32;
invocation[16] @48; runtimeDigest[32] @64; generation u64 @96; epoch u64 @104;
objectId u64 @112; reserved[8] @120. Nonce проверяется один раз в HELLO body
против launch record; channel не переносится между invocation. Max frame=65536,
max outstanding requests=64; проверка размера/FD count до payload allocation.
Sequence строго +1 отдельно в каждом направлении, начинается с 1, wrap запрещён.
ReplyTo=0 только unsolicited HELLO/REVOKE/CANCEL; ответы обязаны совпасть с
единственным ожидающим request и objectId; late/duplicate reply отзывает channel.

Destination: family u8 (4/6/domain), protocol u8 (TCP/UDP), port u16, length u16,
reserved u16, bytes[4/16/1..253]. Нет zone, mapped IPv4, NUL/control; domain
canonical ASCII/punycode из trusted compiler, не произвольная нормализация Go.
Tuple: protocol u8, family u8, reserved u16, localPort u16, remotePort u16,
localIP[16], remoteIP[16] (IPv4 zero-tail), всего 40 bytes. Wildcard tuple не proof.
Все variable vectors имеют count u16 и byteLength u32, проверяются оба ограничения.

| Kind | Body и смысл |
| --- | --- |
| HELLO=1 / ADMIT=2 / ACK=3 | HELLO: nonce[32], mode u8, reserved[7]. ADMIT: manifestHash[32], resolverSnapshotHash[32], policyRevision u64, lifetimeMs u32, counts/caps и bounded typed tables. ACK: эти два hashes; session переходит Admitted только после проверки обеих сторон |
| OPEN_INGRESS=16 / INGRESS_REPLY=17 | objectId=sourceFlowId. Request: ingressIndex u16, provenance u8, reserved u8, tuple[40], original Destination. Reply: status u8, required u8, reserved u16, decisionRevision u64, leaseMs u32, allowed manifest scope index u16, reserved u16. Ответ — только ingress receipt, ещё не full egress grant |
| AUTHORIZE=18 / GRANT=19 | Request: receipt objectId, original/effective Destination, subjectIndex u16, chainIndex u16, transportIndex u16, reserved u16. Reply: status u8, grantKind u8 (flow/probe/DNS), reserved u16, grantId u64, leaseMs u32, decisionRevision u64, exact scope indices. Grant создаётся private decoder только после проверки request/binding/live receipt |
| PROBE=20 | Запрос содержит только manifest probeIndex/subjectIndex u16; host service issuer возвращает GRANT с distinct probe kind, без пользовательского tuple/owner |
| CANCEL=32 / REVOKE=33 / CLOSE_ACK=34 | objectId=flow/grant или 0=session; reason u16 + reserved u16. CANCEL идемпотентен и не расширяет scope; ACK сообщает KnownClosed/Unknown, не молчаливый успех |

ADMIT typed tables ограничены: subjects/endpoints/chains ≤256 каждого; ingress≤4;
probe≤1; resolver peers≤16; DAT refs≤16; общий body≤65408. Индексы и references
проверяются до materialization, цепи acyclic. Строки subject≤160 bytes,
probe URL≤2048, redirect=deny; URL scheme/host/port/path проверяются как целое.
Manifest содержит graph physical leaves/chain membership, transport/security
fingerprints, resolver UDP/TCP peers и snapshot hash, DAT manifest hash. Не raw
provider JSON. Caps: logical≤4096, physical≤256, pools≤256, pending≤64,
session buffered bytes≤16MiB, idle≤30s; значения host может только уменьшать.
Manifest больше лимита отвергается, chunking/fallback в revision1 отсутствуют.

Статусы: Allow=1, Deny=2, Unknown=3; неизвестное значение — protocol error.
Provenance: SystemTun=1, LocalAcceptedTCP=2, LocalAssociatedUDP=3; ServiceProbe
не разрешён в OPEN_INGRESS. `required` выставляет host policy, caller не выбирает.
Host не верит присланному provenance без admitted ingressIndex и режима.

### Owner proof и два этапа выдачи

Go ingress receipt фиксирует original tuple/destination и cancel до sniff.
Host проверяет ingressIndex принадлежит admitted run, fresh owner/association,
app ACL и выделяет sourceFlowId в bounded ledger (предложенный Go ID — лишь
request correlation, host отвергает reuse). Для System это original TUN tuple;
для Local TCP — client socket tuple к owned listener, не outbound remote tuple.
Для Local UDP owner TCP association нельзя подставить за UDP owner: association
подтверждает только протокольную связь, required owner проверяется на UDP tuple.
Нет данных/неоднозначный owner → Unknown→deny, без наследования первого клиента.

Не изобретать второй owner service: host issuer и ABI260 broker должны разделять
один trusted owner/policy ledger. На новом канале не передаётся owner assertion;
host запрашивает тот же existing owner backend для immutable tuple. Existing
Go ABI260 rechecks остаются дополнительными проверками свежести, не заменяются
GRANT. Чтобы убрать двойной lookup, root может связать host ledger с реально
отправленным frozen Reply по (invocation, binding, requestId, tuple); нельзя
считать произвольный requestId от Go доказательством. Оптимизация необязательна
и требует sender-side storage в Rust, frozen wire при этом остаётся прежним.

Важное исключение LocalSocks: frozen `wire.go:SelectedFeatures` требует OwnedTUN
даже при appRequired=false; `closedAttach` требует Attach и проверенный TUN FD.
Использовать этот bootstrap для Local без TUN нельзя. Поэтому описанные выше
существующие Go ABI260 rechecks применимы к System. Для Local extension endpoint
сам использует тот же trusted owner backend и выдаёт fresh operation GRANT:
при required=true его leaseMs ограничен 20ms минус RTT, а не общей 1s lease.
Каждый BeforeRouting/AfterDNS/BeforeDial/logical reuse запрашивает fresh GRANT,
включая owner status; Unknown не превращается в Allow. Go private decoder хранит
эту operation freshness с immutable source tuple. Executable path/PID/inode всё
равно не передаются: owner и app decision проверяет один host issuer. Это новая
доставка результата существующего owner backend для Local, где frozen consumer
не существует, а не возможность выдать proof из session credential. Без такого
Local endpoint и его tests LocalSocks остаётся blocked.

В dispatcher после sniff/PickRoute/default host AUTHORIZE проверяет scope против
admitted graph и текущего app decision. Только полученный GRANT создаёт opaque
FlowGrant. Original receipt разрешает bounded routing/DNS evaluation, но не
произвольный dial. DNS для вычисления route получает отдельный DNS-kind grant,
derived от ingress receipt и admitted resolver table; это не пользовательский
full egress grant и не service ProbeGrant. Нет cyclic требования полного route
grant для DNS, необходимого самому route selection. Новый sniff destination,
DNS answer или subject вне scope требует нового AUTHORIZE, не мутации grant.

### Порядок boot и service admission

`main/run.go:217–235 startXray` сейчас вызывает `core.New(c)`; он создаёт
Background (`core/xray.go:169–177`). `core.NewWithContext:180–188` уже существует.
До него launch decoder должен аутентифицировать run, exact sealed config bytes
и ADMIT manifest. Только затем вызвать NewWithContext с private admitted session.
`core/xray.go:198–211` создаёт observatory feature; `Observer.New:236–251`
сохраняет этот ctx. `executeRun:95` вызывает Start; `Observer.Start:49–53`
немедленно запускает background. Следовательно admission после Start слишком
поздний. System frozen Attach/TUN custody завершается до inbound Start;
observatory получает только admitted session/service issuer, не TUN flow consumer.

`Observer.probe:143–183` должен запрашивать distinct ProbeGrant для manifest URL
и exact subject, создать request с context, переносить deadline/cancel в dial;
текущий dial берёт `o.ctx`, теряя HTTP callback context. Redirect уже запрещён
(168–170), это сохранить. Tagged dialer (impl.go:22–25) может оставить forced tag:
dispatcher обязан сравнивать его с ProbeGrant scope. Tag не mint-ит grant.

### Expiry, cancellation, pools и DNS

Session lease≤60s с renewal через тот же ADMIT binding; flow/grant lease≤1s,
но owner-required operation дополнительно требует fresh ABI260 proof≤20ms.
TTL считается от monotonic send time запроса, вычитается полный RTT; ноль/late
даёт Unknown→deny. Lease expiry закрывает resources, не только запрещает opens.
Никаких wall-clock timestamps как основания authority. Pending caps резервируются
до goroutine/buffer/dial; отказ до allocation. Shutdown: сначала под общим lock
перевести session/grant в revoked и увеличить revoke generation, затем cancel
pending, закрыть streams/physical и освободить reservations. Publication/reuse
повторно сверяет generation под тем же lock; победивший revoke запрещает publish.

Cancel original flow отзывает все его logical streams и derived DNS grants,
не session physical transport. Session revoke/EOF/peer death/parse error отзывает
всё, включая idle sockets и reconnect callbacks. Close/release idempotent;
ошибка cleanup фиксирует Unknown и блокирует повторное admission этой invocation
до подтверждённого cleanup. Оставшийся socket не считается успешным cleanup.

Pool key: session+invocation+digest+generation, transport/security identity,
physical endpoint, chain/subject isolation. Physical factory использует только
manifest transport lease и session context; FlowGrant не продлевает physical
authority. Каждый HTTP/2 stream/XHTTP request/UDP send заново проверяет свой grant
и исходный proof; callback получает private immutable grant reference. Reconnect
требует session manifest check и новую physical reservation. Все DNS cache hits,
singleflight waiters и callback reuse проверяют собственный derived grant,
snapshot hash, actual peer и deadline; общий socket не переносит attribution.
Local resolver читает только admitted snapshot, не live OS fallback; hostname
localhost provider остаётся тем же DNS backend с checked resolver factory.

### Точный дополнительный upstream scope для этого варианта

Ни один из перечисленных файлов в этом SOURCE задании не изменён.

| Дополнительный файл вне исходного P4 scope | Необходимый diff |
| --- | --- |
| `main/run.go` | В startXray принять closed launch/admission до core.New, заменить на NewWithContext; на любом отказе не вызывать Start. Это production caller нового private decoder, которого сейчас нет |
| `proxy/tun/handler.go` | HandleConnection создаёт отдельный immutable ingress receipt с original tuple/destination/cancel до DispatchLink. Init сохраняет только admitted session; shared consumer не становится flow |
| `app/proxyman/inbound/worker.go` | TCP callback привязывает receipt к accepted conn tuple/lifetime; UDP callback фиксирует реальный bound local endpoint и datagram source, не wildcard assertion. Это первичный источник LocalSocks attribution tuple |
| `proxy/socks/server.go` | После handshake и для каждого UDP destination связать request с accepted receipt/UDP association; reject mux sentinel для owned ingress; account не owner |
| `proxy/http/server.go` | После parse/auth создавать request receipt для CONNECT и каждого plain keep-alive request, закрывать logical lifetime отдельно от accepted connection |
| `app/dispatcher/default.go` | Входной receipt guard до allocation; после выбранного handler и sniff — AUTHORIZE/GRANT, включая forced/default paths, затем handler.Dispatch. В существующем scope нельзя привязать grant к реальному routing result |
| `transport/internet/udp/dispatcher.go` | Guard перед reuse/каждым payload write, destination-bound grant; закрывать/rekey link при смене scope. Иначе обход dispatcher на `return v.conn` |

Для минимального owned LocalSocks ingress inbound mux запрещается в SOCKS/HTTP
до `common/mux.Server.Dispatch`: тогда `common/mux/server.go` менять не нужно.
Если root требует inbound mux/XUDP, дополнительно нужен именно
`common/mux/server.go:165–264` (child receipts и per-payload reuse guard), иначе
такую поддержку нельзя объявлять. Это не запрет outbound transport multiplexing.
`core/xray.go`, `core/context.go`, `always.go`, taggedimpl и `tun_linux.go` для
предложенного boot/receipt варианта менять не требуется: NewWithContext и
контекстная передача уже есть, TUN custody сохраняется через existing OpenTUN.
Нужны соответствующие новые pure tests рядом с семью изменяемыми файлами.
Новые decoder/ledger files внутри `common/yonikbroker/` входят в исходный scope;
frozen `wire.go`, frozen vectors и старые descriptors остаются byte-exact.

### Решения, которые должен закрыть root до implementation

1. Подтвердить protected launch path для LocalSocks и exact sealed launch-record
   FD custody; без него local run authentication этим proposal не доказана.
2. Назначить Rust authority endpoint: общий owner backend и app-policy evaluator,
   canonical tuple ориентацию TUN/accepted TCP/UDP и decision revision semantics.
   Go Xray policy.Manager этим endpoint не является.
3. Согласовать proposed limits/layout и typed manifest mapping с P5, включая
   memory budget и exact resolver snapshot/NSS semantics; если требуется libc/NSS
   plugin execution, текущая pinned peer resolver модель его не покрывает.
4. Утвердить семь дополнительных production файлов и tests; выбрать reject
   inbound mux либо явно расширить scope на common/mux/server.go.
5. Определить renewal/expiry cleanup и observable Unknown в host lifecycle;
   никакой readiness до воспроизводимых fake race/caps/revoke/DNS regressions.
