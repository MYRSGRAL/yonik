# P5: System intent и physical egress

Статус: typed IPC codec и versioned parse/dispatch реализованы с явным
Unsupported до native admission. FD-backed DAT и строгий resolver source
capture реализованы, но store/staging/native-consumption ещё не подключены.
P5 не завершена; P6 не должна считать
полный профиль доступным для System/TUN. Legacy request/capabilities, installed
trust checks, ABI260 и исторические pins не изменены.

## Реализованный API

`yonik_linux::helper::profile_intent`:

- `PhysicalRequirements::new(&EgressPlan) -> Result<PhysicalRequirements, EgressError>`
  принимает только закрытый compiler manifest; лимит physical leaves — 128 до
  аллокаций/callbacks. Общий бюджет physical + bootstrap DNS + LAN/private
  по-прежнему проверяет `PublicBlockPolicy::new`, до dedup.
- `endpoints()` возвращает только `EgressPlan::physical()`: chains уже разрешены
  P3. Remote chained subjects и direct subjects не добавляются в исключения.
  TCP и UDP остаются отдельными requirements, даже при одинаковом host/port.
- `provider_resolvers()` и `system_resolvers()` возвращают отдельные закрытые
  требования DNS. Ни один из этих списков не добавляется в transport exceptions.
- `capture_numeric<T>(worker_uid, mark, &Cancellation, capture)` передаёт host
  callback точный `SocketAddr` и firewall protocol. Callback возвращает
  `Result<(ifindex, T), EgressError>`, где T удерживает host route observations.
  Numeric endpoints полностью проверяются до первого query; hostname требует
  отдельного bootstrap provenance bridge и получает `BootstrapRequired`.
  Loopback, unspecified, multicast, link-local, broadcast и IPv4-mapped IPv6
  не проходят. Нулевые UID/mark запрещены. Это алгоритм capture, не proof issuer.
- `CapturedPhysicalRoutes<T>::revalidate(&Cancellation, verify)` проверяет
  каждый сохранённый T. Любая ошибка или отмена необратимо инвалидирует весь
  набор. `transports()` после этого возвращает `Stale`; успешная повторная
  callback-проверка не оживляет набор. Частичный capture освобождает свои T.
  T здесь — observations, а не владелец активного worker/network resources.
- `RetainedSystemProfile::seal(CompiledProfileSystem, generation, selection_digest)`
  потребляет один compiler result и вычисляет SHA-256 exact config через bounded
  streaming writer, без второй копии credentials. Сохраняет результат целиком;
  `compiled()` только заимствует, `into_compiled()` перемещает его для launch.
  `matches(generation, selection_digest, runtime_digest)` проверяет DATA binding.
  Source selection и generation обязан подтвердить trusted caller; сам wrapper
  их не удостоверяет и capability не создаёт. Повторная compilation после seal
  запрещена в интеграционном callsite: случайный probe credential изменит digest.

У типов нет Serialize/Deserialize или arbitrary JSON/Value constructor.
Новый `yonik_engine::native_profile::ProfileIntent` предоставляет `decode`,
`from_profile`, `write_sensitive`, `validate`, `compile_system`. Wire envelope:
`version:1, graph:<закрытые typed structures>`. Это object schema, не строка
native JSON, DSL или opaque blob. Поля P3 представлены private typed structs:
settings, transport/security, DNS, routing, balancers, probes, ingress.
Metadata remarks/meta исключены уже P3. Нет публичного Value constructor.
Размер <=64 KiB; до typed materialization проверяются depth/duplicates/null,
bounded sequences проверяются до чтения следующего typed элемента. Unknown
fields отвергаются до materialization их значения. После decode неизменённый
P3 validator повторно проверяет полный graph/references/effects.

`FullProfileRequest::{new,decode,write_sensitive}` добавляет version=1,
generation, selection digest и kill_switch. Aggregate request <=64 KiB,
нулевые generation/selection запрещены; эти координаты не catalog proof.
До decode helper резервирует conservative credit 4 MiB в existing process-wide
config budget и удерживает его до Drop request; отказ до materialization при
исчерпании бюджета. OwnedRuntimePlan/listener/resource bindings выбирает helper,
а не IPC. До их admission новый dispatch не выдаёт prepared artifact.

## Точные точки интеграции helper

`helper/service.rs`: новая отдельная `PrepareFullProfileV1` принимает только
один string argument с typed request, без FDs. `parse` вызывает bounded decode,
`dispatch` повторяет graph preflight и возвращает Unsupported без handle.
Introspection дополнена методом, availability/capabilities не расширены.
`SystemClient::prepare_full_profile` использует этот exact метод. Legacy
`SystemProfileRequest`/`ProtectionHost::prepare_profile` сохраняют ServerIntent.

`helper/session_host.rs`: `SessionArtifact::{endpoint,port,protocol,route,route_capture}`
и `query()` пока single endpoint. Замена на полный набор затрагивает
`prepare_profile_inner`, `apply_profile`, `start_profile`, `verify_network_facts`;
проверка каждого элемента обязательна до prepare completion, перед Apply,
после TUN configure и в active sweep. Callback для numeric capture обязан
использовать существующие `lookup_route_captured`, `checked_route` и
`same_captured_kernel_route`, проверяя exact namespace/worker UID/mark/table.
Все ответы повторно связать с одним network stamp/context. Любой stale элемент
отменяет всю подготовку. Текущий компонент сам host queries не выполняет.

## Resource/DNS custody: отдельный незакрытый bridge

`OwnedRuntimePlan::bind_resources` и `bind_system_resolver` доверяют host traits.
Ни полученный по IPC digest, ни `ExternalRef`, ни resolver endpoint metadata
нельзя использовать как реализацию этих trusted traits без source proof.
Существующий `resource_fd_receiver::rebuild` обслуживает canonical policy
resources, а не проверку категорий native DAT.

Для production необходимы pinned read-only DAT descriptors с checked bytes/hash,
kind/category parser, controlled owned basename и lifetime до подтверждённого
worker stop. Отдельно нужны resolver/NSS snapshot custody, exact content identity,
checked UDP/TCP route captures и bootstrap provenance. Изменение snapshot
инвалидирует весь admitted result. Provider DNS не заменять OS DNS и не давать
ему blanket direct exceptions. Cleanup failure сохраняет custody и Unknown;
Drop route observations не является worker cleanup.

Реализован `PinnedNativeDat::verify(File, ExternalRef, &[OwnedResourceRequirement],
&Cancellation)`: проверяются actual read-only FD, root-owned regular inode,
mode/nlink/size, stamp before/after, SHA-256, bounded protobuf DAT grammar,
тип records, count и точные category codes. Code приводится к upper-case как
в pinned loader, attrs сохраняются в requirement; существование category
не означает непустой результат attribute filtering. Unknown protobuf fields,
duplicate categories и malformed/truncated/overflow records отвергаются.
Descriptor остаётся owned; `revalidate` заново проверяет stamp/content digest.
`VerifiedNativeResources` удовлетворяется этим FD-backed объектом, не IPC
metadata. Буфер и parser overhead резервируются через existing config budget.
Он ещё не открывает trusted catalog path и не stage-ит DAT под owned basename.

`PinnedResolverSnapshot::capture` открывает только `/etc/resolv.conf` и
`/etc/nsswitch.conf` с NOFOLLOW/CLOEXEC/NONBLOCK, удерживает root-checked FDs,
exact bytes/stamps/digest и memory reservation. Revalidate открывает fixed
paths заново, сверяет содержимое/identity и старые retained descriptors.
Symlink resolv.conf, NSS modules/actions/files/mDNS, search/options пока дают
явный отказ. Единственная поддержанная grammar — `hosts: dns` и ordered
nameserver lines, <=16 servers. Это проверенный source snapshot для compiler
trait, **не доказательство использования snapshot native resolver**. Production
native branch обязана применять admitted snapshot/server rows per-query,
не читать live NSS/resolv или environment fallback. `localhost` в provider
config не заменяется. Нужны отдельные TCP/UDP route bindings и snapshot receipt
в carrier. Эти capture функции не исполнялись на host в данной фазе.

## Недостающая native activation authority P4

Переданные root source facts P4 commit
`6acfecb459a9d60c59a6cb794c89ea0b578965ff`: partial DNS context change,
builder не подключён; main compile-only. Bootstrap/DecodeBootstrap содержит
session binding без admitted manifest; frozen EncodeLookup/ReplyBody доказывает
tuple/owner, но не policy decision/sourceFlowId/subject-chain/probe admission.
private closedAttach не имеет production issuer. P4 ready не предполагается.

Rust anchors: `helper/native_owner.rs::commit_native_owner` создаёт
`RunAuthority::from_bound(OwnerBinding)` из retained scope; это разрешение
владельца helper, не FlowGrant/ProbeGrant. `helper/run_authorization.rs`
и `worker/anchor_exchange.rs` сохраняют прежний authenticated owner protocol.
Новый manifest нельзя объявлять authenticated только по совпавшему session ID.

Минимальный отдельный versioned carrier contract для согласования root/P4:

1. Trusted helper, после повторной graph/resource/DNS/selection проверки,
   передаёт bounded manifest через отдельный authenticated channel, связанный
   с retained authenticated run и exact emitted digest/generation. Carrier
   связывает session identity, graph/subjects/chains/physical manifest identity,
   resource descriptors identity, resolver snapshot identity, expiry и caps.
   Frozen ABI260/EncodeLookup/ReplyBody остаются неизменными. Конкретный transport,
   endpoint authentication и receipt format ещё не утверждены/не реализованы.
2. Native adapter возвращает authenticated receipt принятия **этого** manifest.
   Ни DTO от UI, ни session credential, ни hash без custody такого receipt
   не создают. Helper связывает receipt с одной retained compilation.
3. `IssueFlowGrant(authenticated_original_flow, checked_policy_decision,
   admitted_session)` доступен только trusted original ingress/policy issuer.
   Закрытый результат содержит sourceFlowId, attribution/provenance/required,
   destination, subject/chain, session/digest/generation, expiry/cancellation.
   Owner/tuple lookup не подменяет этот вызов. Смена destination/subject/chain
   требует нового решения issuer. Общий transport не наследует grant первого flow.
4. `IssueProbeGrant(admitted_session, admitted_probe_requirement)` доступен
   отдельному trusted service issuer. Только subjects/destination из manifest;
   пользовательской attribution ему не приписывать. Grant types не взаимозаменяемы.
5. Receipt/grants/revoke проверяются перед каждым logical open/reuse и physical
   reconnect. Revoke linearized до dial/reuse; physical lifetime session-owned,
   logical cancellation flow-owned; cleanup idempotent, failure остаётся Unknown.

Это требования к API, а не существующие Rust/Go symbols. Нужны реальные issuer
callsites и authenticated carrier от root/P4. До них новый helper path обязан
возвращать Unsupported, а availability оставаться false. Не создавать готовую
activation из compile result или придуманного тестового issuer.

## Проверки и предел результата

Новые unit tests работают с synthetic импортом, compiler и memory callbacks.
Проверяются physical budget, chain/direct separation, TCP/UDP, отсутствие DNS
promotion, numeric safety, cancellation, каждый route capture/revalidation,
sticky stale и сохранение exact sealed bytes/digest/generation/selection.
Ни system profiles, user DB, NSS, proc, routes, services, sockets, native worker
или config-test не исполняются. Source/PURE результат не является runtime PASS.

## Canonical transport bytes для capsule P4

Сверены proposals `dccd92659ebca1818678ab1e734d39a0cf45767c` и root
`434b49b`, revision2.1. Последний остаётся design, не native readiness.
Ingress receipt живёт до owning ingress/session close. Grant refresh использует
AUTHORIZE objectId=live grantId с тем же scope/class/sourceFlow/binding;
expired/cancelled grant не воскрешается, owner expiry не сдвигается. Owner
receipt namespaces: None=0, FrozenSent=1, SidebandOperation=2. Только FrozenSent
требует actual-sent ABI260 Reply; correctly-shaped unknown/evicted reference
даёт один actor lookup и SidebandOperation без synthetic frozen request/reply.

Реальный API `ProfileIntent::transport_kind(subject)` возвращает закрытые
`WireTransportKind::{Tcp=1,Grpc=2,Xhttp=3,Hysteria=4}` и
`WireSecurity::{None=0,Tls=1,Reality=2}`. Defaults отсутствующих network/security
— Tcp/None, как в P3. Это предлагаемые точные enum bytes table4 revision2.1;
P4 должен закрепить их явно, поскольку draft перечисляет названия без чисел.
Destination protocol остаётся другим namespace: TCP=6, UDP=17. Для family
domain требуется явное число в draft; предлагается 3 (IPv4=4, IPv6=6).
Остальные draft namespace enum числа не изменяются этим codec.

`write_transport_sensitive(subject, writer)` даёт **не JSON**:
`P5STRM01[8] || kind u8 || security u8 || Option<Stream> || Option<Mux>`.
Все integers big endian. Option = byte 0 (absent) или 1 + value; null запрещён.
String = byteLength u32 + exact UTF-8 bytes; bool = 0/1; u64/i64 = 8 bytes;
List = count u32 + ordered values; object = ordered fields ниже, каждый Option.
Нет map, field-name strings, padding, trailing fields или implicit enum casts.
Сумма canonical bytes <=64 KiB. Наличие explicit default/empty object сохраняется
и может менять fingerprint; это безопасное более строгое разделение pools.

| Object | Порядок полей (в каждом сохранён Option) |
| --- | --- |
| Stream | network, security, tcpSettings, grpcSettings, xhttpSettings, hysteriaSettings, tlsSettings, realitySettings, finalmask |
| Empty/tcpSettings | нет payload fields |
| Grpc | serviceName, authority, multiMode, mode |
| Xhttp | mode, host, path, extra |
| Extra / Xmux | xmux / maxConnections |
| Hysteria | version, auth |
| Tls | serverName, enableSessionResumption, fingerprint, alpn, allowInsecure |
| Reality | serverName, publicKey, shortId, fingerprint |
| Mask | tcp, quicParams |
| MaskEntry | type, settings |
| MaskSettings | clients, servers (каждый List<List<Packet>>) |
| Packet | type, packet, rand |
| Quic | congestion, bbrProfile, disablePathMTUDiscovery |
| Mux | enabled, concurrency (i64), xudpConcurrency, xudpProxyUDP443 |

Каждое строковое поле сохраняет exact validated UTF-8, включая header-custom
packet в его str/hex/base64 spelling. Packet type и rand также входят; это
точное encoding **typed settings**, а не decoded/random generated wire packet.
P4 minfix: если draft «header-custom bytes» означал только decoded packet,
заменить это на exact P5STRM01 Packet encoding выше; raw/native JSON не хешировать.
Probe/destination/chain/subject не входят в stream bytes: они отдельные scope
поля и обязательные pool-key компоненты. Outbound credentials/settings связаны
exact runtime digest + subject index, не объявляются исключёнными из authority.
Fingerprint на стороне P4/helper = SHA256(`YNKCAP-TRANSPORT-v1\0` || exact bytes).
Engine не добавляет crypto dependency, только выдаёт bounded canonical bytes.
Golden для direct subject без stream/mux: ASCII P5STRM01 + `01 00 00 00`.

Несовпадения capsule draft с полным P3 grammar, которые нельзя исправить
молчаливым flattening/выбором одного protocol:

- Subjects/1 caps256 с повторными именами для TCP/UDP не покрывает все <=256
  outbounds (SS даёт две scopes). Endpoints/2 caps256 также может не покрыть
  до512 subject endpoints после chains при physical<=128. Minfix: явно разделить
  unique subject identity и protocol scopes либо поднять **новые draft** caps
  scopes/endpoints до512 с прежним total-frame64KiB reject. Это не изменение
  существующих IPC/firewall limits; wire draft требует отдельного review.
- Chains/3 «unique source» неоднозначен при duplicated subject rows. Нужны
  точные source-scope/next-scope indices и правило native TCP/UDP transition.
  `EgressPlan::chains` — tag edges, не доказательство такого transition.
  P5 не выбирает произвольный TCP row вместо UDP и не разрешает chained remote
  напрямую. P4 должен сверить transition с actual outbound transport factory.
- Resolvers/5 caps16 — дополнительный capsule admission bound, а не P3 grammar
  bound; codec не обрезает provider list. Ingresses/7 caps4 корректен только для
  фактических owned listeners, не для <=16 provider aliases. Если rows означают
  provider aliases, нужны отдельные alias→owned-index rows или cap16.

## Реальный direct-dynamic firewall контракт для scope review

Role3 classification не открывает egress. Сейчас firewall пропускает только
exact BoundTransport (IP, protocol, destination port, ifindex, UID, mark);
worker broad UID exception запрещён. Минимальный рабочий путь:

1. Один сериализованный Backend принимает authenticated AUTHORIZE с live
   sourceFlowId/grant binding, resolved numeric destination, protocol/port,
   generation/digest/policy revision и mandatory/app decision. Проверяет scope,
   private/LAN/namespace constraints, отмену и owner freshness. Provider route
   уже выбрал Xray; второй routing evaluator не нужен.
2. До allocation/query резервирует slot в общем bounded ledger. Static + DNS +
   dynamic exceptions вместе с остальными policy entries остаются в existing
   MAX_EXCEPTIONS=128 (и бюджете link-control); дубликаты не обходят input cap.
   Ledger key включает session/generation/digest, namespace, worker UID/mark,
   exact destination/protocol/port/ifindex; grant refs/lifetime ограничены.
3. `lookup_route_captured` с тем же UID/mark/protocol/port, `checked_route` и
   полный route/context/stamp capture подтверждают escape route. TUN/own table,
   stale, неизвестный путь или один непроверенный DNS answer — deny.
4. Compose полного PublicBlockPolicy с одним новым exact BoundTransport.
   Existing `NftExecutor::apply_durable_public_policy` + journal intent/revision
   устанавливают replacement; `recover_public_policy` подтверждает DesiredRules.
   Затем ещё раз route/context/revocation check. **Только после этого** publish
   GRANT/dial. `check_public_policy` (-c) не считается установкой rules.
5. Shared exact exception имеет refcount live grants, не authority первого flow.
   Native guard каждого logical open/reuse/send обязателен: kernel rule не умеет
   различать sourceFlowId при одном worker UID/mark. Refresh не расширяет scope,
   revalidates route/policy/owner, не сдвигает исходный owner expiry.
6. Expiry/cancel сначала линеаризует native revoke fence и закрывает logical
   resources. Последний ref retiring key удаляется durable policy replacement;
   повторный close idempotent. Slot не переиспользуется до KnownClosed/проверенного
   retirement. Route mutation инвалидирует связанные grants и весь admitted
   session context; не перенаправлять старое исключение на новый ifindex.
7. Неизвестный результат nft/remove/cleanup сохраняет journal, resource custody
   и Unknown. GRANT не публикуется, дальнейшие opens блокируются; при утрате
   enforcement требуется session revoke + confirmed worker stop до освобождения.
   Recovery не превращает прежние rules в live grants и не делает blind unlock.

Existing executor/journal API достаточно для correctness-first full-policy
replacement; новый kernel set/ABI не нужен. Latency/rate limits на updates
обязательны; превышение bounded capacity даёт deny, не broad exception.

## Минимальный дополнительный scope для production custody/multi-route

Ни один из перечисленных далее файлов этим commit не меняется.

- `helper/protection_host.rs::Operation`, `Backend::run`,
  `impl ProtectionHost for SystemProtectionHost` (PrepareProfile anchors
  111/418/618 на base13f8919): новая FullProfile операция и передача trusted
  resource/resolver factory в существующий serialized blocking job. Сейчас
  approved service dispatcher может только closed preflight + Unsupported;
  нельзя подменить ServerIntent для обхода этой отсутствующей ветки.
- `helper/native_owner.rs:423,551`: два SessionArtifact literals. Для реальной
  замены single-route на vector нужны только адаптация этих fixtures к новому
  полю и сохранение Arc identity; authority/RunAuthority там не расширять.
  Без этого изменения добавление production поля ломает all-targets tests.
- `worker.rs::WorkerPayload` (288), `new_bundle` (342): resources сейчас только
  `Arc<RebuiltBatch>`, который происходит от canonical rules, не exact native DAT.
  Нужен отдельный trusted native-DAT retained batch/payload branch; нельзя выдать
  raw DAT за canonical input. `worker/native_resources.rs::{validate,copy_owned}`
  и `worker/native_assets.rs::Assets` могут переиспользовать sealing/owned basename
  staging после отдельного narrow review. Не менять frozen ABI260/records.
- Trusted catalog locator/source policy отсутствует в P5 API. Root должен
  утвердить источник root-owned DAT descriptors, exact category parser/index
  и staging lifetime. PinnedNativeDat уже проверяет actual contents, но не
  выдумывает catalog path и не объявляет file доступным worker.
- R4 channel/issuer scope остаётся отдельно у root: systemd_worker,
  native_bootstrap, role_handoff, native_session/transport и новые channels.
  Его добавление должно удерживать P5 pins, resolver snapshot и весь route set
  до confirmed worker stop. Дополнительные nft/storage files не требуются для
  direct replacement с текущим journal API; новые kernel queries здесь не запускались.

Для обычного NSS `files dns`, symlinked resolved stub, search/options нужны
additional typed snapshot data (hosts entries, ordered search/options и backend
selection), все actual source FDs, path-identity revalidation и native consumer,
который использует snapshot без live libc/environment fallback. Capsule
Resolvers/5 с одним hash+Destination этого не доказывает. Minfix proposal:
либо отдельный bounded typed resolver-snapshot section + authenticated acceptance
receipt, либо строго ограничить support `hosts:dns`/nameserver-only и явно deny
остальное. Provider localhost сохранить в обоих случаях. Это незакрытая часть
full-profile integration, не причина заменять provider DNS другим сервером.
