# P5: System intent и physical egress

Статус: частичный DATA/PURE компонент. Нового IPC codec, helper dispatch и
production custody bridge пока нет. P5 не завершена; P6 не должна считать
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
Этот API не является typed graph IPC: существующий graph хранит private Value,
а wire codec всей принятой схемы ещё предстоит реализовать в engine/helper.
Подмена codec сериализацией JSON, DSL или sensitive byte blob не допускается.

## Точные точки интеграции helper

`helper/service.rs`: `SystemProfileRequest`, `Request`, `parse`, `dispatch` и
`ProtectionHost::prepare_profile` сейчас принимают `ServerIntent`. Отдельная
versioned ветка полного intent должна повторно проверять закрытый graph и
ownership, сохраняя MAX_REQUEST/MAX_WIRE_BYTES (64 KiB). Не использовать
`system_profile` как raw full-profile fallback. Legacy introspection не менять
до появления настоящего нового dispatch.

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
Drop route observations не является worker cleanup. Эти bridges не реализованы.

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
