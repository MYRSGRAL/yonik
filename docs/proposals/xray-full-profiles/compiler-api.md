# Native compiler: API кандидата P3

Статус: SOURCE/COMPILE/PURE. Это не runtime acceptance и не разрешение запуска.
P3 остаётся открытой до проверки перечисленных ниже ограничений полного scope.

## Публичные интерфейсы

Модуль `yonik_engine::native_profile`:

```rust
validate_profile(&NativeProfile) -> Result<ValidatedGraph, ProfileCompileError>
compile_profile_local(&NativeProfile, &OwnedRuntimePlan)
    -> Result<CompiledConfig, ProfileCompileError>
compile_profile_system(&NativeProfile, &OwnedRuntimePlan)
    -> Result<CompiledProfileSystem, ProfileCompileError>
```

`OwnedRuntimePlan::new(NonZeroU16, NonZeroU16)` требует разные Local/probe порты.
`with_system(SystemTun)` задаёт System-вариант. Local API отвергает System plan,
System API требует TUN. `map_ingress(&str, OwnedIngress)` явно сопоставляет
provider inbound с Local или System. Два provider listeners нельзя неявно
свести в один вход; такой конфликт возвращает `Ownership`. Неиспользованное
сопоставление также отвергается. Sniffing переносится только после проверки
закрытой схемы; FlowGrant issuer P4/P5 должен проверять итоговое назначение.

`CompiledProfileSystem::{config, graph, egress}` возвращают заимствованные
закрытые результаты. `into_config` перемещает конфигурацию. Для Local manifest
получается через `validate_profile` того же NativeProfile. Произвольных JSON/Value
конструкторов нет. Все ошибки — конечный enum без provider values/credentials.
Debug графа, endpoint и CompiledConfig скрывает содержимое; getters чувствительны.

`ValidatedGraph`:

- `subjects() -> &[String]` — provider outbounds в исходном порядке;
- `selector_sets() -> &[(String, Vec<String>)]` — проверенные prefix sets balancers;
- `egress() -> &EgressPlan`;
- `resources() -> &[OwnedResourceRequirement]`;
- `probe() -> Option<&ProbeRequirement>` — URL и раскрытое множество subjects.

`EgressPlan::{physical, chains, direct_subjects, resolvers, subject_endpoints}` отделяет TCP/UDP
физические endpoints от chain edges, direct subjects и resolver requirements.
`PhysicalEndpoint::{host, port, protocol, requires_bootstrap}` не делает DNS lookup.
`ResolverRequirement::{endpoint, subject}` требует отдельного route/DNS admission;
resolver endpoint нельзя автоматически добавлять в direct firewall exceptions.
`subject_endpoints()` связывает каждый dial subject с исходным remote endpoint;
P5 следует `chains()` до physical leaf и не разрешает remote через прямой маршрут.
Observatory URL также требует проверки destination/redirect policy P4.

## Ресурсы и digest

`OwnedResourceRequirement::{kind, category}` создаётся только validator из
`geoip:`/`geosite:` matcher. Provider `ext:` paths отвергаются. Trusted store
реализует `VerifiedNativeResources::lookup(&OwnedResourceRequirement)
-> Option<resource_bundle::ExternalRef>`: он обязан проверить DAT digest,
тип и наличие точной категории. Это trusted interface, а не доказательство,
которое разрешено принимать из IPC или provider metadata.

`OwnedRuntimePlan::bind_resources(&ValidatedGraph, &impl VerifiedNativeResources)`
проверяет Xray engine/format/count/size/kind и общий лимит 512 MiB.
`resource_bindings()` отдаёт пары requirement/reference. Эмиттер заменяет только
matcher strings на `ext:r-<digest>.dat:<category>`. Credentials и прочие strings
не переписываются. Без binding возвращается `ResourceRequired`.

P5/P8 должны stage/pin эти DAT под exact owned basename в контролируемом runtime
каталоге, проверить bytes/digest/category и удерживать custody до cleanup.
Compiler не читает DAT, не скачивает geodata и не подтверждает наличие файлов.
Существующий `resource_bundle` не изменён; production bridge native DAT catalog
в этой фазе отсутствует. Resource references в DNS hosts keys пока отвергаются.

Digest вычисляет существующий host seal над **точными bytes**
`CompiledConfig::write_sensitive`, включая listeners, mark, routing и случайный
probe password. Source identity/semantic identity не заменяют emitted digest.
Новая компиляция создаёт новые credentials: нельзя повторно компилировать между
admission и запуском, сохраняя старый digest. Отдельного SHA API в engine нет;
вводить собственную криптографию или зависимость ради этого не стали.

## Native schema и ограничения

Pinned archive SHA256:
`e5184047fd1380472f69114fb8173a0adfd8c50970560eceb9c87fcba0bb35e9`.
Source commit `a4a3dff5b20c2faae567b742c172c7b95e75c083`, Xray 26.10.31.
Сверены conf xray/dns/router/transport_internet/transport_method/
transport_security/transport_finalmask/hysteria/vless/shadowsocks;
member hashes сохраняются в P3 evidence `provenance.json`.

Положительные схемы проверяют поддержанные native объекты; graph удерживает
закрытый validated Value и типизированный manifest. Это ещё не полный типизированный
IPC graph codec P5. P1 гарантирует duplicate/depth bounds; compiler дополнительно
проверяет root 64 KiB до Value, outbounds 256, rules 2048, resources 16.
Metadata remarks/meta удаляется до runtime. Paths/API/scripts/listeners provider
не передаются как произвольные runtime effects.

Поддержаны VLESS TCP/gRPC REALITY, XHTTP TLS/xmux maxConnections, SS TCP,
Hysteria2 TLS/UDP, header-custom str/hex/base64/rand, QUIC bbr/reno и
bbrProfile conservative/standard/aggressive. Остальные варианты дают typed отказ.
`grpcSettings.mode=false` распознаётся как no-op pinned Go schema (там нет этого
поля); `true` отвергается, в `multiMode` не преобразуется.

Новая синтетическая fixture содержит семь native-schema форм. Это не полная
копия shape-only отчёта: все реальные формы/входные mappings/resources ещё не
покрыты, поэтому полный scope семи provider profiles **не объявлен закрытым**.
Ограниченный validator проверяет fingerprints, целые s/m/h duration,
port expressions/mux bounds; остальные native варианты требуют расширения схем.
Typed IPC representation и повторное helper admission остаются работой P5.
Pure tests сравнивают
runtime bytes/значения при смене портов и семантики, не криптографический digest.

P4 остаются Go blockers observatory consumer, Hysteria UDP type-switch, gRPC
handoff и lifetime shared pools. Ни наличие config, ни новый manifest их не чинят.
FlowGrant/ProbeGrant и session/digest/generation binding из reviewed contracts
остаются обязательными. Ни core/config-check, ни network, services или Linux
acceptance в этой фазе не выполнялись.
