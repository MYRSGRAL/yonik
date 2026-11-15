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
и trusted issuer должны отдельно выдавать FlowGrant с sourceFlowId,
provenance/required, исходным и разрешённым destination, subject/chain, expiry и
cancel. Только manifest service issuer выдаёт ProbeGrant. Decoder обязан иметь
конкретный production callsite; произвольные JSON/env/context setters исключены.

Конкретный revision2 proposal ниже задаёт wire layout, transport/custody,
issuer callsites, authentication и replay rules для согласования root/P5.
Rust helper intent codec сам по себе issuer не создаёт. После согласования можно подключить closed APIs
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

## SOURCE proposal revision 2.1: YNKCAP01 (для согласования root)

Revision2 заменяет revision1 целиком. Это reviewable proposal, НЕ final contract
и НЕ разрешение implementation дополнительных файлов. Общая P4 не завершена;
runtime закрыт. В этом задании не выполнялись Go implementation/build, runtime,
OS queries или новые tests. Значения layout/caps ниже — конкретный выбор proposal,
не отдельное одобрение пользователя.

### Решения root и граница полномочий

Local использует существующий normal LocalHost: host/session.rs:57–108
CheckedConfig удерживает BinarySnapshot, final runtime bytes и их digest;
LocalSession::start:205–263 проверяет current digest и владеет exact child.
host/binary.rs:49–69,206 BinarySnapshot исполняет sealed inode. host/process.rs:82
spawn и write_config:111 передают конфигурацию owned child. После последней
with_local_runtime_logging преобразования digest считается над теми же bytes,
которые идут в stdin. Не повторять compilation между admission и launch.

Новый Local module выдаёт admission только из потреблённого CheckedConfig +
owned Child/pidfd + session/invocation/generation/lifetime; private inherited
socketpair соединяет normal Host с этим child. Новая привилегия не нужна.
Это существующая Local threat model: не защита от полного same-UID Host compromise.
Local required=false выводится issuer из trusted Local mode, не UI флага.
OS attribution, executable/process-selector global policy в Local недоступны.
Protocol authentication и source tuple фиксируют происхождение request, но НЕ
превращаются в executable identity. Нет искусственного Local owner TTL=20ms.
Local lease ограничивает session/grant lifetime, а не свежесть OS owner.

System сохраняет native_session.rs::Session::from_verified:96–128
app_required:true (в этой базе строка 113; review anchor 104 зависит от ref).
Единственный existing owner backend — RemoteLookup и его protected lookup leaf.
Новый issuer НЕ выбирает provider route и НЕ дублирует Xray policy evaluator.
Xray выбирает original/effective destination и subject через native routing.
Issuer проверяет admitted run, trusted provenance, manifest subject/chain/
transport/resolver scope и mandatory constraints. App ACL проверяется только
существующей trusted active policy. Xray policy.Manager — timeout/stats/buffer,
не executable ACL. Provider rule tags, UI required, account email не authority.
Для пользовательского System flow app_required=true означает свежий Known
owner proof. Отсутствие отключённой optional App ACL само по себе не Allow
и не Deny: issuer ещё обязан проверить manifest/mandatory constraints.
Обязательная trusted active App ACL продолжает enforced-проверку; Unknown
owner всегда deny. UI не может превратить required в false.

System owner freshness остаётся ≤20ms исходного observation, RTT/очередь его
не продлевают. Общий сериализованный owner backend возвращает один result для
одной операции: frozen-derived receipt создаётся только после actual sent Reply,
а sideband lookup получает отдельный private operation receipt. Между этими
namespace нет неявного преобразования или обязательных двух lookup. Ни новый
wire PID/path, ни Known assertion не нужны. Для операции без свежего receipt
backend выполняет один lookup; старый receipt не продлевает freshness.

### Go source facts и точки mint

Anchors относятся к retained src/ archive SHA256
e5184047fd1380472f69114fb8173a0adfd8c50970560eceb9c87fcba0bb35e9.
Точный список 22 Go sources/hash:
 /home/myrs/projects/yonik/local/orchestration/evidence/p4-dns-966ee520/issuer-source-hashes.json.
Дополнительно 10 Rust source hashes на exact base HEAD 57f929683feb959ad87fd5e503acf3ee1932df0a
и полный ref/hash P5 API из git object 13f8919 сохранены в
/home/myrs/projects/yonik/local/orchestration/evidence/p4-dns-966ee520/issuer-revision2-source-hashes.json.

| Source anchor | Проверенный факт и необходимое действие |
| --- | --- |
| proxy/tun/handler.go:100,214–262 | Init переносит shared consumer; HandleConnection знает conn.RemoteAddr и исходный destination, но не выдаёт per-flow receipt. До sniff/DispatchLink зафиксировать immutable original tuple/destination и flow cancel |
| app/proxyman/inbound/worker.go:61–127,314–361 | Accepted TCP даёт actual RemoteAddr/LocalAddr; UDP local может быть wildcard. Создать private ingress receipt с actual bound listener и source, от owned accepted connection; wildcard не owner proof |
| proxy/socks/server.go:122–164,238–283 | После handshake известен request destination; UDP destination меняется на каждом packet. Handshake account не OS identity. Bind request receipt; UDP association не переносит TCP owner на UDP |
| proxy/http/server.go:116–161,191,246 | Auth опциональна, plain HTTP keep-alive возвращается к Start. Отдельный request receipt на CONNECT/plain request, не один grant на accepted TCP |
| app/dispatcher/default.go:268–281,328–342,303–319,361–377,439–517 | Existing RoutingEntry до OriginalTarget, sniff меняет Target/RouteTarget; выбор handler завершается на ob.Tag=handler.Tag(). Проверить private ingress receipt на входе, mint final FlowGrant после выбора handler до handler.Dispatch |
| transport/internet/udp/dispatcher.go:71–104,108–120 | Cached v.conn обходит Dispatch. Каждый payload проверять по actual payload.UDP, не cached dest/connEntry destination, включая cone-mode |
| app/observatory/observer.go:49–53,143–183,236–251 | New сохраняет feature ctx, Start запускает background; dial берёт o.ctx вместо HTTP callback ctx. Admit manifest до NewWithContext/Start, затем mint ProbeGrant для exact URL/subject, request ctx+deadline сохранить |
| transport/internet/tagged/taggedimpl/impl.go:22–25 | Forced tag лишь routing input; dispatcher сверяет его с grant scope, tag не создаёт grant |
| common/yonikbroker/routing.go:65–99,103–133 | Missing consumer denied; authenticated lookup доказывает owner tuple, но не отдельный policy/egress grant |
| common/yonikbroker/closed_tun_linux.go:19,71,228–233 | closedAttach private; shared session consumer не original per-flow attribution. CarryClosedSession только переносит consumer |
| common/session/session.go:16–24; features/policy/policy.go:13–76 | Logging ID не secure/sourceFlowId; ForLevel не app-policy issuer |

Original provenance появляется в owned ingress, owner proof для System приходит
из существующего broker, а approved scope — из manifest + mandatory/app policy.
Именно private decoder их объединяет; произвольного exported setter из config,
tag, context values, credential или bool быть не должно. Request domain из
SOCKS/HTTP/sniff динамический: wire decoder проверяет ASCII canonical hostname
(1–253 bytes, label 1–63, LDH, без пустых labels/leading/trailing hyphen),
IP literals отдельно через canonical IP, без zone/mapped-v4/NUL/control.
Trusted Go ingress переводит IDNA только уже существующим pinned implementation,
если его нет — non-ASCII reject, без новых dependencies. Host повторяет checks.
Sniff не переписывает original; effective/route target отдельно. DNS answers
проверяются как конкретные IP и не расширяют разрешённую цепь.

### Production System producer и отдельный handoff

В текущем HEAD anchors:
helper/systemd_worker.rs::start_native:796;
coverage.revalidate:874 → verify_pending:875 →
Session::from_verified:906 → handoff_verified_run:934.
После verify_pending и проверки P5 manifest против retained coverage/digest
создаётся отдельный CLOEXEC AF_UNIX/SOCK_SEQPACKET socketpair.
Supervisor сохраняет host endpoint, ledger и RuntimeScopeStamp до confirmed
cleanup; worker endpoint передаётся отдельным extension handoff. Общий
revocation owner связывает scope.revoke, native Session.close, sideband EOF,
worker death и helper stop. Один канал не переживает другой как авторизованный run.

Конкретный handoff: новый handoff_verified_profile_run в worker/role_handoff.rs
потребляет RunRole, проверяет binding, сначала retain(run.into_guard()) у supervisor,
затем посылает YNKEXT01 record с ОДНИМ SCM_RIGHTS extension worker endpoint на
уже authenticated role-handoff socket coverage.take_handoff(). После отдельного
ACK вызывает прежний transport_send БЕЗ изменения его bytes/FD count.
YNKROLE1 по-прежнему передаёт ровно channel+server_pidfd; DATA4 не меняется.
Legacy producer не посылает extension record и работает прежней веткой.

receive_verified_transport в role_handoff.rs перед existing YNKROLE1 peek узнаёт
YNKEXT01, принимает его отдельной функцией, проверяет expected helper credentials
и challenge binding; принимает максимум один record, затем обычные roles.
Extension binding должен совпасть с полученным frozen binding, иначе закрыть всё.
RunHandoff/VerifiedTransport удерживает optional OwnedExtension. Full-profile
production exec требует Some и проверенный P5 manifest hash; legacy None не
становится full-profile fallback. ProductionPermit::exec_run:323–361 сохраняет
extension FD отдельно через exec; Go main/run.go принимает его до core.NewWithContext.
Не нужны изменения marker/transport в anchor_exchange или run_authorization:
extension распознаёт уже existing role receiver. Реализовать opt-in внутри
role receiver, а не вставлять frame в frozen DATA4 parser.

YNKEXT01 record=192 bytes, big endian:
magic[8]@0, version u16=1@8, length u16=192@10, rights u16=1@12,
reserved u16=0@14, nonce[32]@16, finalDigest[32]@48, session[16]@80,
invocation[16]@96, generation u64@112, epoch u64@120, supervisorPid u32@128,
workerPid u32@132, supervisorStart u64@136, workerStart u64@144,
manifestHash[32]@152, reserved[8]@184.
ACK=40 bytes: magic YNKEXAK1[8] + SHA256(exact record)[32], rights=0.
Deadline=min(existing handoff deadline, now+1s), без неограниченного ожидания.

Record/ACK: ровно один SCM_CREDENTIALS, exact expected PID/UID; starttime/pidfd
проверяются retained identities. Record: ровно один SCM_RIGHTS с одним FD;
ACK: ни одного права. Unknown ancillary, duplicate credentials, TRUNC/CTRUNC,
неверные длины/count — reject; receiver закрывает ВСЕ полученные rights,
включая лишние, до возврата ошибки. FD проверяется как SEQPACKET; нет pathname
socket и нет третьего FD внутри старого transport_send. Runtime child уже
получает supervisor pidfd из frozen roles; extension использует тот же binding.
После exec Go сразу возвращает extension FD в CLOEXEC и принимает владение один
раз. Передача locator через env сама authority не создаёт: ответы принимает
только Host/supervisor с private retained ledger exact child/run.
Runtime frames не передают rights; SO_PASSCRED проверяет каждого sender.
На failure sender/receiver закрывают свои endpoints, supervisor отзывает scope,
не запускает payload/observatory; cleanup error остаётся Unknown.

Local: host/session.rs из checked bytes создаёт тот же protocol socketpair и
private LocalAdmission; host/process.rs наследует child endpoint и host pidfd
отдельными owned descriptors только этому BinarySnapshot command. Parent
закрывает child copies сразу после spawn, получает child pidfd и проверяет
первый HELLO по exact child PID/UID/starttime. Child проверяет host PID/UID,
inherited host pidfd и binding. Peer UID здесь normal UID, не root. Нет YNKROLE1,
DATA4, TUN или System owner proof. Session/invocation nonce создаёт Host; required
жёстко false. Host ledger существует до reap+resource cleanup. BinarySnapshot
не менять: существующий sealed command уже подходит.

### Typed manifest revision2 и P5 mapping

Новый typed codec не сериализует arbitrary JSON. P5 partial 13f8919:
RetainedSystemProfile::seal удерживает ОДИН CompiledProfileSystem/final digest;
PhysicalRequirements::new ограничивает physical≤128; resource/resolver custody
bridge ещё не реализован. Нельзя принять trait digest от IPC как custody proof.
Ниже точная предлагаемая capsule, P5 wire enum representation ещё должен быть
согласован root; capsule строится только из повторно checked typed intent.

Все таблицы по canonical compiler order, индексы u16, 0xffff=None; без map.
Header тела ADMIT 128 bytes:
manifestHash[32]@0, previousHash[32]@32 (zero при initial),
admissionId u64@64, leaseMs u32@72, mode u8@76 (Local=1/System=2),
required u8@77, reserved u16@78, policyRevision u64@80,
caps[8*u32]@88, tableCount u16=8@120, reserved[6]@122.
Caps в порядке logical=4096, physical=128, pools=128, pending=64,
sessionBufferedBytes=8388608, idleMs=30000, ingressReceipts=4096,
tombstones=256; host может только уменьшить.
За header ровно восемь tables: prefix type u16,count u16,byteLength u32;
каждая row имеет rowLength u16, reserved u16, затем поля ниже.
Все counts/row lengths/общая сумма проверяются checked arithmetic до allocation.

| Table/type | Caps и exact row payload (без row prefix) | P3/P5 mapping |
| --- | --- | --- |
| Subjects/1 | ≤256: UTF8 name string(u16 bytes+≤160), endpointIndex u16, chainIndex u16, transportIndex u16, flags u16=0 | graph.subjects + subject_endpoints; subject с TCP/UDP использует разные endpoint rows и scope rows, name допускает повторение только при разных protocol |
| Endpoints/2 | ≤256: Destination, role u8 (physical=1/chained=2/direct-dynamic=3), reserved u8 | EgressPlan physical/subject_endpoints/direct_subjects; physical rows≤128 P5 PhysicalRequirements; chained remote не firewall exception |
| Chains/3 | ≤256: subjectIndex u16,nextSubjectIndex u16 | EgressPlan.chains; unique source, acyclic; terminal physical/direct проверен отдельно |
| Transports/4 | ≤256: kind u8 (tcp/grpc/xhttp/hysteria), security u8 (none/tls/reality), reserved u16, fingerprint[32] | из validated stream settings для каждого subject |
| Resolvers/5 | ≤16: backend u8 (provider/system), protocol u8 (TCP/UDP), subjectIndex u16, snapshotHash[32], Destination | provider_resolvers отдельно от system_resolvers; checked peer routes и pinned snapshot custody, без promotion в physical exceptions |
| Resources/6 | ≤16: kind u8 (geoip/geosite), reserved u8, category string≤160, contentDigest[32], size u64 | graph.resources + verified DAT binding; dedup content files, category rows отдельно; ≤512MiB суммарно уникальные content digests |
| Ingresses/7 | ≤4: kind u8 (TUN/SOCKS/HTTP/probe), protocol u8, ownedPort u16, ownedAlias string≤160 | explicit OwnedRuntimePlan mapping; alias не credential; Local loopback ports checked Host |
| Probes/8 | ≤1: scheme u8 (http/https), redirect u8=0, port u16, host string≤253, path string≤2048, nSubjects u16, subjectIndices[n*u16] | graph.probe exact URL/expanded subjects; нет fallback URL из Go |

Destination encoding: family u8 (4/6/domain), protocol u8 (TCP=6/UDP=17),
port u16, length u16, reserved u16, bytes[4/16/1..253]. Domains проходят dynamic
validation выше; reserved zero, port nonzero. Tuple=40 bytes: protocol u8,
family u8, reserved u16, localPort u16, remotePort u16, localIP[16],remoteIP[16];
IPv4 zero-tail; wildcard/zone/mapped addresses запрещены для proof.

Scalar mandatory constraints не скрываются в flags:
revision2 System required=true, Local=false; direct_subject не превращается в
любой физический dial: для direct host AUTHORIZE связывает конкретный resolved
destination с проверенными System mandatory constraints/P5 route policy.
Дополнительный direct scope кодируется endpoint role=3 (direct-dynamic):
Destination в такой row отсутствует, вместо неё family=0,protocol TCP/UDP,
port=0,length=0,reserved=0; это ТОЛЬКО subject classification, не разрешение.
AUTHORIZE всегда несёт конкретный Destination и проходит mandatory constraints.
Endpoint role=1/2 обязан иметь полный Destination; role=3 разрешён только для
P3 direct_subjects. Никакого allow-all worker UID. Root/P5 должны проверить
совместимость этого динамического direct пути с текущим firewall enforcement.

Manifest hash: SHA256("YNKCAP-MANIFEST-v1\0" || final runtime digest[32] ||
mode u8 || required u8 || policyRevision u64 || caps[32] ||
восемь table prefix+rows в wire order). Не включать manifestHash/previousHash,
admissionId, lease в собственный hash; они binding/lifetime, не graph semantics.
Resource content digests, resolver snapshot hashes, scopes и transport fingerprints
входят через rows. Transport fingerprint: SHA256("YNKCAP-TRANSPORT-v1\0" ||
canonical typed P5 stream-settings bytes), включая network/security, serverName,
ALPN, REALITY fields, gRPC service/mode, XHTTP mode/xmux и Hysteria params,
header-custom bytes. Не raw JSON, не hash только имени; sensitive input не логировать.
Если P5 codec не предоставляет canonical typed bytes, fingerprint contract ещё
не готов и admission запрещён. Crypto implementations только existing deps.
Total frame≤65536; table bytes≤65280 после headers; oversize reject без chunking.

### Runtime header, IDs, направления и state machine

Header 128 bytes: magic YNKCAP01[8]@0, version u16=1@8, kind u16@10,
total u32@12, sequence u64@16, replyTo u64@24, session[16]@32,
invocation[16]@48, runtimeDigest[32]@64, generation u64@96, epoch u64@104,
objectId u64@112, reserved[8]@120. Big endian, reserved=0.
Sequence строго +1 per direction, starts=1; wrap/duplicate/gap→channel revoke.
replyTo=sequence исходного request; objectId имеет namespace по kind, не authority.
sourceFlowId назначает Host ingress ledger (never reuse invocation, starts=1);
grantId — другой counter Host; request seq — третий namespace. Caller request
correlation не становится sourceFlowId. ZERO только session/initial ingress request.

| Kind/direction | Body после header |
| --- | --- |
| HELLO=1 G→H | nonce[32], mode u8, reserved[7]; objectId=0,replyTo=0 |
| ADMIT=2 H→G | capsule выше; replyTo=HELLO seq для initial |
| ADMIT_ACK=3 G→H | manifestHash[32],admissionId u64,status u8,reserved[7]; replyTo=ADMIT seq |
| OPEN_INGRESS=16 G→H | ingressIndex u16,provenance u8(TUN=1/acceptedTCP=2/associatedUDP=3),reserved u8, tuple[40], original Destination; objectId=0 |
| INGRESS_REPLY=17 H→G | status u8,required u8,reserved u16,sourceFlowId u64,lifetime u32=0 (owned-ingress, не TTL),decisionRevision u64; replyTo=request |
| AUTHORIZE=18 G→H | sourceFlowId u64,grantClass u8(flow=1/DNS=3),reserved u8,subjectIndex u16,chainIndex u16,transportIndex u16,original Destination,effective Destination,resolverIndex u16,queryName string(u16 length+0..253 bytes),ownerReceiptKind u8, reserved[7],ownerReceiptId u64; objectId=0 для нового grant, live grantId для refresh |
| GRANT=19 H→G | status u8,class u8,required u8,reserved u8,grantId u64,sourceFlowId u64,leaseMs u32,decisionRevision u64,ownerFreshNs u64,ownerReceiptKind u8,reserved[7],ownerReceiptId u64; exact scope берётся из outstanding request; objectId=grantId при Allow, иначе 0 |
| PROBE=20 G→H | purpose u16(probe=1/bootstrapDNS=2),index u16(probe/endpoint row),subjectIndex u16,resolverIndex u16(0xffff вне DNS); sourceFlowId=0,required=0; scope только из exact manifest |
| RENEW=21 G→H | admissionId u64,manifestHash[32]; objectId=0; host отвечает ADMIT или DENY=22 (status u8,reason u8,reserved[6]) |
| CANCEL=32 either→peer | targetKind u8(request=1/flow=2/grant=3/session=4),reason u8,reserved u16,targetId u64; objectId=0; request cancel ссылается на sequence отправителя request; session targetId=0 |
| REVOKE=33 H→G | reason u16,reserved[6]; objectId=0,replyTo=0 |
| CLOSE_ACK=34 reply | targetKind u8,closeStatus u8(KnownClosed=1/Unknown=3),reserved u16,targetId u64; replyTo=CANCEL/REVOKE seq |

Status Allow=1/Deny=2/Unknown=3; Unknown всегда deny, не fallback.
Owner receipt имеет отдельный tagged namespace: None=0, FrozenSent=1,
SidebandOperation=2; прочие значения отвергаются. Local/probe передают только
None/id=0/ownerFreshNs=0. System request с None/id=0 требует свежего lookup,
а не разрешает действие без owner. FrozenSent/id — request ID реально
отправленного ABI260 Reply; SidebandOperation/id — монотонный ID внутреннего
actor ledger, не request ID frozen wire. Ненулевой kind с id=0 или None с
ненулевым id — protocol error. Эти числа не authority без retained ledger.

Общий actor проверяет binding, immutable tuple и привязку receipt к операции
живого sourceFlowId. Только FrozenSent требует actual-sent Reply. При отсутствии,
вытеснении или истечении корректно оформленной ссылки actor делает один lookup
для этой операции и создаёт SidebandOperation receipt с исходным owner expiry;
искусственный frozen Lookup/Reply не создаётся. Unknown/ошибка остаётся deny.
GRANT сообщает фактически использованные kind/id. Два namespace не смешиваются,
caller не может перенести receipt на другой flow. Actor хранит оба вида в общем
bounded ring≤64; eviction приводит к свежему lookup, не к доверию присланному ID.
Existing Go check может передать private FrozenSent receipt в AUTHORIZE;
grant не отменяет следующие frozen guards. Общий actor может использовать свежий
результат одной операции без обязательного второго lookup и без сдвига expiry.
System ownerFreshNs=min(remaining snapshot lifetime,20ms) после send queue;
Go вычитает RTT, stale→Unknown. Не переносить receipt между source flows.

States: AwaitHello→Admitting→Admitted→Revoking→Closed/Unknown.
До ADMIT_ACK никакие ingresses/probes/physical opens не принимаются.
Initial deadline=1s, session lease=60s, RENEW при remaining≤20s; один outstanding
renewal. Renewal допускает только тот же manifest hash/digest/policy revision/
mode/caps, новый admissionId+lease; old grants не продлеваются. Active lease
не прерывается ожиданием ACK, но при expiry revoke. Изменение manifest/policy/
generation требует stop+cleanup+новая invocation; замены scope под old grants нет.
ADMIT.replyTo=RENEW seq; ACK.replyTo=новый ADMIT seq; успешный ACK атомарно обновляет
session deadline. При ошибке/stale ACK старый deadline не продлевается.
Ingress receipt не имеет секундной lease: он живёт до закрытия owning TCP
connection/request, UDP association, TUN flow либо session и занимает один из
4096 ingress slots. Go issuer фиксирует этот lifetime до OPEN_INGRESS; закрытие
отменяет pending запрос и посылает CANCEL(flow). Host не восстанавливает закрытый
sourceFlowId повторным AUTHORIZE. Потеря канала/session закрывает все receipts.
Renewal session не создаёт новый ingress и не продлевает owner freshness.

Grant lease≤1s, physical lease≤session deadline; Local не owner lease.
Долгоживущий logical stream обновляет grant через AUTHORIZE с objectId=его
live grantId при remaining≤250ms. Требуются тот же sourceFlowId, exact scope,
class, decision revision и binding плюс свежая обязательная owner-проверка.
Host возвращает тот же grantId с новым bounded expiry; новый ресурс/ingress
не создаётся. Закрытый, отменённый или expired grant не возрождается refresh.
Смена scope требует нового grant и отдельного проверенного перехода, не refresh.
До получения и проверки GRANT Go сохраняет прежний deadline; timeout/отказ
или expiry закрывает только этот logical stream. Refresh не продлевает исходную
System owner observation: actor применяет её оставшийся срок либо новый lookup.
Lease deadline на receiver считается от monotonic send time соответствующего
HELLO/RENEW/AUTHORIZE/PROBE, вычитая весь RTT; sender не может
заново начать lease при delayed reply. Для ADMIT_ACK host удерживает deadline
исходного ADMIT, ACK не добавляет времени. Нулевой remaining lifetime — отказ.
REVOKE CLOSE_ACK имеет targetKind=session,targetId=0. CANCEL любого namespace
может только уменьшить собственные права, не отменить чужую session.

### Cancel, late replies, replay и memory preflight

Каждая сторона имеет один bounded control reader/writer. Pending≤64; request
deadline≤1s (owner operations дополнительно freshness), request body≤1024 bytes.
Отмена pending AUTHORIZE сначала атомарно помечает pending cancelled, затем
посылает CANCEL(request,original seq). Уже вычисленный GRANT может прийти раньше
CLOSE_ACK: receiver потребляет sequence, по tombstone не публикует grant и посылает
CANCEL(grant,id). Это допустимый late reply, соседние flows не отзываются.
Host cancelled request никогда не создаёт live grant; если grant уже published
на host, request→grant ledger закрывает его при CANCEL без ожидания клиента.

Tombstone ring≤256 per direction: request seq,target flow/grant IDs,deadline,
completion status, последняя received seq. Для cancelled request хранить до
matching reply/CLOSE_ACK или исходный deadline+1s; новый pending не допускается,
если нет гарантированного tombstone slot. После expiry использовать monotonic
contiguous retired request watermark (только префикс ниже всех live pending и
неистёкших tombstones; через hole не перескакивать): replies для retired seq потребляются без allocation/
publication, не сбрасывают соседей; unknown future replyTo или conflicting
повторный ответ для live request — protocol error. Wire sequence replay всё
равно отвергается. Нельзя принять watermark как успешный CLOSE_ACK: неизвестный
результат остаётся Unknown, targeted resources закрыты локально. Request/grant
mapping хранится до completion/retirement, global historical ledger не растёт.
Отмена original flow отзывает его grants/DNS children; session cancel/revoke
закрывает pending, logical и physical, с linearized fence до publication/reuse.
Cleanup ошибки сохраняют Unknown/custody; повторный close идемпотентен.

Общий explicit budget=8MiB на session в каждой реализации, не сумма скрытых caps:
immutable capsule≤64KiB; decoder RX/TX 2*64KiB; control queues 64*1024=64KiB
каждая сторона RX/TX (128KiB total); pending 64*2048=128KiB; tombstones 256*64=16KiB;
ingress 4096*192=768KiB; grants 4096*256=1MiB; pools 128*1024=128KiB;
physical metadata 128*512=64KiB; logical metadata 4096*128=512KiB.
Owner receipt ring обоих kind суммарно≤64*128=8KiB включён в тот же бюджет; grants всех
трёх классов суммарно≤4096, не отдельные 4096 на класс.
Остаток (около 5MiB при этих caps) — data buffers; общий checked reservation включает
и их, и container capacity/allocator rounding. Ограничения rows и byte budget
независимы; preflight считает serialized+decoded capacity одновременно. Большие
transport buffers резервируют разницу до allocation. Будущий codec обязан
доказать sizeof/capacity bounds; Go maps/goroutines не считаются бесплатными.
Allocation failure/cap overflow → targeted deny до spawn/dial; control revoke
имеет отдельный зарезервированный fixed slot, backpressure не блокирует revoke.

### DNS и transport enforcement

DNS до выбора route — AUTHORIZE class=DNS от private ingress receipt:
subject/chain/transport=0xffff, resolverIndex обязателен, effective Destination
есть exact resolver peer, original — immutable исходное user destination;
queryName — отдельное проверенное имя текущего запроса (может отличаться после
sniff, но не меняет original). Для flow class queryName пустой,resolverIndex=0xffff;
для DNS class queryName обязателен и проходит dynamic hostname validator.
Запросы DNS для bootstrap manifest physical hostname используют
manifest service issuer с отдельным manifest endpoint reference, не FlowGrant
чужого пользователя. PROBE purpose=2 использует endpoint hostname из manifest,
GRANT class=DNS,sourceFlowId=0,resolverIndex exact admitted row.
PROBE purpose=1 выдаёт class=probe. Нельзя выдать arbitrary service
DNS на произвольный caller hostname. Provider DNS сохраняется, OS resolver не
подменяет provider; system resolver использует pinned snapshot, без public fallback.
Каждый waiter/cache hit проверяет свой grant, peer/snapshot/cancel/deadline;
query/domain/result не логируются. DNS answers не разрешают новый egress leaf.

Physical factory session-owned и проверяет manifest transport lease при reconnect;
logical FlowGrant/ProbeGrant/DNSGrant проверяется при каждом stream/request/send.
Pool key=session+invocation+digest+generation+subject/chain+transport fingerprint+
physical endpoint. Отмена одного logical flow не закрывает shared physical;
session revoke закрывает всё. gRPC/XHTTP callback удерживает opaque current grant,
не копирует attribution первого flow. Hysteria UDP wrapper остаётся guarded,
без raw socket escape. SOCKS cone-mode проверяет actual payload.UDP; nil payload.UDP
допускается только для явно connected immutable destination, никогда как cached
fallback для произвольного datagram. Inbound mux reject до child dispatch; outbound
xmux сохраняется с отдельными grants на каждый logical stream.

### Дополнительные файлы: минимальный diff и pure tests

Это список для ROOT scope approval; никакой implementation этих файлов сейчас
не разрешается из child. Исходные P4 Go transport/observatory/DNS/broker файлы
остаются нужны. Семь дополнительных Go файлов:

| Файл | Минимальный diff | Чистые regression tests |
| --- | --- | --- |
| main/run.go | Принять private admission до NewWithContext/Start; failure не запускает features | fake boot order, missing/wrong digest/expired admission, no Start |
| proxy/tun/handler.go | Per-flow immutable receipt до sniff, source tuple/cancel из owned TUN | two flows separate receipt/cancel, no shared attribution |
| app/proxyman/inbound/worker.go | Local accepted TCP/UDP provenance и actual tuple, lifetime binding | forged/wildcard tuple denied, UDP association isolation |
| proxy/socks/server.go | Request receipt после handshake, per-datagram actual destination, inbound mux reject | cone payload.UDP change denied, TCP owner не UDP owner, outbound xmux unaffected |
| proxy/http/server.go | Отдельный receipt/grant на CONNECT и plain keep-alive request | two requests different target, previous grant cannot authorize next |
| app/dispatcher/default.go | Receipt guard перед allocation; issuer scope check после выбранного native route перед handler.Dispatch | native forced/default/balancer preserved, wrong subject/chain/sniff reauthorization |
| transport/internet/udp/dispatcher.go | Guard каждого payload перед cached link write | reuse without Dispatch still guarded, actual UDP target mismatch |

common/mux/server.go не нужен при explicit owned inbound mux reject.
core/xray.go/context.go, always.go, taggedimpl и tun_linux.go для этого варианта
не требуют изменений; existing NewWithContext/context forwarding/OpenTUN пригодны.
Если будущие tests выявят отдельную потерю контекста — report, не расширять молча.

Минимальный дополнительный Rust scope:

| Файл | Минимальная ответственность |
| --- | --- |
| helper/systemd_worker.rs | После verify_pending связать P5 checked manifest со stamp; создать sideband, retain endpoint/ledger в NativeRuntime до cleanup; вызвать profile handoff wrapper |
| helper/native_bootstrap.rs | Закрытый ExtensionAdmission из verified scope+checked manifest, без arbitrary constructor; общий revocation fence |
| helper/native_profile_channel.rs (новый) | Typed codec/manifest validator/issuer ledger, System scope/owner operation integration, bounded queues |
| worker/role_handoff.rs | Отдельные YNKEXT01 send/receive/ACK и optional owned extension в verified transport/exec; frozen transport_send unchanged |
| attribution/native_session.rs | Один общий сериализованный owner actor вместо двух владельцев RemoteLookup; actual Reply receipt/freshness, required=true сохранить |
| attribution/native_session/transport.rs | Dispatch frozen requests через того же owner actor, receipt только actual sent reply; queue delay не продлевает freshness |
| host/session.rs | Retain LocalAdmission от CheckedConfig/exact final bytes, session generation, stop/revoke/cleanup |
| host/process.rs | Private socketpair/host pidfd inheritance для exact child и cleanup; legacy checking path не получает grant |
| host/local_profile_channel.rs (новый) | Local issuer required=false, manifest scope и request lifetime, без owner lookup/OS attribution |

broker/remote.rs НЕ входит в обязательный diff: существующий lookup_and_project
достаточен actor-владельцу. Менять только если реализация докажет конкретный
недостающий existing API. run_authorization.rs/anchor_exchange.rs не добавлять.
host/binary.rs остаётся без изменений. Модульные объявления в helper.rs/host.rs
могут потребоваться для двух новых модулей; это механический scope отдельно
указать root, не считать неявным разрешением менять другие files.
P5 graph/resource/DNS codec/custody остаётся ownership P5/root; не писать их из P4.

Rust pure tests: fake peer credentials/rights decoder (0/1/extra rights, CTRUNC,
wrong role), immutable frozen vectors/FDcount, exact seal→manifest mismatch,
Local no privilege/required=false/no selector support, System required=true,
shared owner one lookup per operation/remaining TTL, cancellation-before/after
GRANT publish, late replies preserve neighbours, bounded watermark/tombstones,
renewal old-grants expiry, per-table truncation/count/index/hash/fingerprint,
full budget preflight before fake allocation, Unknown cleanup retaining custody.
Дополнительно: CONNECT дольше секунды с живым ingress и grant refresh, закрытие
ingress во время refresh без resurrection, grant expiry без успешного refresh,
unknown/evicted FrozenSent → fresh SidebandOperation без synthetic Reply,
cross-kind ID collision и original owner expiry после очереди/повторного use.
Только in-memory/fake state machine и source-level frozen vectors; реальные
socketpair/exec/proc/systemd/runtime tests в этой фазе запрещены.

### Оставшиеся design integration вопросы

1. Root/P5 должны согласовать canonical typed stream-settings bytes и enum mapping
   capsule с новым intent codec; до этого fingerprint/manifest не final.
2. Подтвердить operational direct-dynamic mandatory/firewall enforcement и exact
   resolver snapshot/NSS custody. Numeric metadata/trait digest не proof.
3. Реализация owner actor должна сохранить existing ABI260 semantics и отсутствие
   mandatory double lookup; internal sent-reply receipt не экспортировать из UI.
4. Root должен одобрить перечисленный дополнительный source diff и tests перед
   implementation; normal LocalHost, required=false и provider routing ownership
   уже выбраны root и не требуют нового вопроса пользователю.
