---
title: Полные Xray-профили — план реализации
design_ref: 2026-11-15-happ-full-profiles-design.md
created: 2026-11-15
status: approved
session_id: 2026-11-15-happ-full-profiles
total_phases: 8
task_complexity: complex
source_base: e14aeae6c0cd89e9a49bd4ee03b4c6412e0e2e32
execution_mode: parallel
---

# План реализации

## Цель и ограничения

Семь конфигураций проверенной подписки импортируются и выбираются как семь
полных Xray-профилей с исходной семантикой; Auto/balancers, DNS, TCP/gRPC,
XHTTP и Hysteria поддерживаются в LocalSocks и System/TUN. Число профилей
не зашивается в код. Sing-box пока недоступен для запуска, его данные сохраняются.

Начальная база — принятый remote main e14aeae6, повторно проверенный через
GitHub перед созданием плана. Незавершённый P07-кандидат 700bd6f не включается
неявно. Local main 36b0b11 защищён, история не переписывается.

Разрешены локальные атомарные task-коммиты. План предусматривает обычное
локальное объединение task-веток в отдельную интеграционную ветку, без
коммитов в protected main и без force/rebase/reset. Изолированные checkout
создаёт T3; не shell-команды. Публикация PR не является шагом этого плана.

Обычно работают два исполнителя одновременно. Все они получают непересекающиеся
owned files в текущем batch, запрет отмены чужих изменений и вложенного
делегирования. Root не пишет implementation-код по протоколу Maestro.

## Зависимости и выполнение

```text
P1: контракты и базовые типы
 ├─ P2: импорт и каталог ──────────────────────┐
 └─ P3: Xray validator/emitter ─┬─ P4: native ─┤
                              └─ P5: System ─┤
                                             P6: Desktop/QML
                                               → P7: review
                                               → P8: build/install и actual campaign
```

| Этап | Фазы | Режим при parallel | Исполнители |
| --- | --- | --- | --- |
| A | P1 | Последовательно | coder |
| B | P2, P3 | Параллельно | два coder |
| C | P4, P5 | Параллельно | два coder |
| D | P6 | Последовательно | coder |
| E | P7 | Независимое ревью | code-reviewer/security-engineer |
| F | P8 | Последовательно | coder |

При sequential порядке P1→P2→P3→P4→P5→P6→P7→P8. P4 использует именно
runtime fixtures/разрешённые graph subjects и digest результата P3, поэтому
P4/P5 запускаются после P3, на одной глубине зависимостей. Это уточнение порядка
не расширяет утверждённую область изменений.

## P1. Контракты, fixtures и фундамент модели

Agent: coder. Parallel: нет. Blocked by: нет. Blocks: P2, P3.

Создать:

- `crates/yonik-import/src/native_profile.rs` — закрытый NativeProfile,
  ProfileEntry и безопасный summary без credentials.
- `crates/yonik-import/tests/native_profiles.rs` — bounded parsing и opaque
  original preservation, семь независимых root entries.
- `tests/fixtures/xray-full-profile-seven.json` — синтетические версии всех
  используемых shapes, без реальных endpoint/credentials/URL.
- `docs/proposals/xray-full-profiles/contracts.md` — окончательные public API,
  identity/ownership и native session/stream contracts.

Изменить `crates/yonik-import/src/lib.rs`: экспорт новой модели и нового
профильного entrypoint без необоснованного удаления старого server API.

Начальные интерфейсы, уточняемые внутри P1 до делегирования потребителей:

```rust
pub enum ProfileEntry { Server(ParsedServer), Xray(NativeProfile) }
pub fn import_profiles(bytes: Vec<u8>) -> Result<ProfileImportReport, ImportFailure>;
impl NativeProfile {
    pub fn name(&self) -> &str;
    pub fn write_sensitive(&self, writer: impl std::io::Write)
        -> Result<(), std::io::Error>;
}
```

NativeProfile здесь DATA с закрытым bounded construction, не authority и не
CompiledConfig. Пересечение IPC повторно валидируется на стороне helper.
Полный graph, исходный snapshot, summary и runtime bytes не копируются без
общего бюджета. Источник, semantic intent и runtime config имеют разные digest.

До implementation P4/P5 зафиксировать закрытые native contracts: кто выдаёт
служебный observatory capability из authenticated run, какие destinations и
subjects разрешены, кому принадлежат shared physical transports и отдельные
logical streams. Provider tag/JSON не создаёт authority. Между incompatible
sessions/digests/generations pooling запрещён; logical flow проверяется при
каждом открытии/reuse, отмена одного не закрывает соседний, revoke закрывает все.
До завершения P1 эти native contracts независимо проверяет code-reviewer;
без закрытых замечаний по authority P4/P5 не начинают implementation.

Проверки: `cargo test -p yonik-import --test native_profiles`; прежние import
tests; JSON size/depth/duplicate/reference tests; fmt и targeted clippy.
Если контракт потребует frozen ABI/dependency/неразрешённых Go-изменений,
выдать конкретный blocker до кода соответствующей области, без обхода guards.

## P2. Импорт, зашифрованное хранение и версия каталога

Agent: coder. Parallel: да, с P3. Blocked by: P1. Blocks: P6.

Owned files:

- `crates/yonik-linux/src/repository.rs`;
- `crates/yonik-linux/src/subscriptions.rs`;
- `crates/yonik-subscription/src/lib.rs`;
- `crates/yonik-linux/tests/profile_selection.rs`;
- новый `crates/yonik-linux/tests/full_profile_catalog.rs`;
- профильные subscription import/refresh tests при необходимости их адаптации.

Ввести versioned catalog projection Server/Native, profile-aware selection и
сводку review по самостоятельным конфигурациям. Catalog lookup/resolve сверяет
source generation/revision, fingerprint и тип профиля. Полный конфиг не
дедуплицируется как набор single endpoints. Новый каталог строится из encrypted
snapshot, без запроса пользователя повторить ссылку и без сетевой загрузки.

До P6 сохранить совместимые server-only API либо явный отказ для native вместо
fake host/port. Нельзя возвратить вымышленный ParsedServer от полного профиля.
Reorder/rename не должны терять стабильные ID; неоднозначные legacy favourites
сохраняются с требованием повторного выбора. CAS и защита рабочего snapshot
при массовой ошибке остаются прежними; refresh не переключает active session.

Проверки: profile_selection, full_profile_catalog, subscription_refresh_contract,
subscription_import_failure; temporary encrypted repository с test keys,
без настоящего user data/keyring. fmt и all-targets clippy затронутых packages.

## P3. Xray-specific graph validator и trusted emitter

Agent: coder. Parallel: да, с P2. Blocked by: P1. Blocks: P4, P5.

Создать `crates/yonik-engine/src/native_profile/{mod,graph,validate,emit}.rs`
и `crates/yonik-engine/tests/xray_full_profiles.rs`.
Изменить `crates/yonik-engine/src/lib.rs`, `routing.rs`, `dns.rs`, `system_tun.rs`
только для отделения owned runtime surfaces и экспорта новых compiler API.

Контракт:

```rust
pub fn compile_profile_local(profile: &NativeProfile, runtime: &OwnedRuntimePlan)
    -> Result<CompiledConfig, ProfileCompileError>;
pub fn compile_profile_system(profile: &NativeProfile, runtime: &OwnedRuntimePlan)
    -> Result<CompiledProfileSystem, ProfileCompileError>;
```

Типы OwnedRuntimePlan, CompiledProfileSystem и EgressPlan закрыты и определяются
P1/P3; System result отдаёт существующий CompiledConfig и typed egress requirements,
но не выдаёт route/FD authority. Нельзя открыть public arbitrary-Value constructor
CompiledConfig. Прежний single-server compiler сохраняет свой контракт.

Сохранить ordered routing, tag references и prefix-selector множества, balancers,
observatory, DNS detours, chains, REALITY/TLS, gRPC/XHTTP, Hysteria quicParams и
выбранный finalmask `header-custom`. Lua/noise/realm/другие неиспользуемые mask
families не становятся разрешёнными по сходству namespace. Unknown congestion
отвергается до возможного panic внутри native core.

Compiler генерирует owned listener/probe/TUN/logging/marks; provider file paths,
API, downloads и лишние listeners не исполняются. Resources требуют owned
manifest. Probe следует graph default/разрешённой entry, а не fixed `proxy`.
System physical egress вычисляется с учётом цепочек; неизвестный physical leaf
не превращается в широкое firewall исключение.

Проверки: xray_full_profiles и прежние routing/dns/system_tun tests; semantic
graph assertions всех семи fixtures, malicious paths/unknown fields, bounds
до крупных аллокаций, reference cycles/reserved tags, exact digest changes.
fmt и clippy `--all-targets -- -D warnings`.

## P4. Native Xray: observatory и transport ownership

Agent: coder. Parallel: да, с P5. Blocked by: P3. Blocks: P6.

В repository создать versioned follow-up patch
`adapters/xray/v26.10.31/native-full-profile.patch`, descriptor
`native-full-profile.json` и технический `native-full-profile.md`.
Изменить `tools/build_native_adapter.py` и его соответствующие tests только
для Xray apply/pins нового patch. Прежние frozen records и upstream version/commit
не переписываются. Сначала строго проверить применение к закреплённому дереву.

Upstream файлы, которые patch вправе менять после явного одобрения расширения:

- `app/observatory/observer.go` — уже разрешённый служебный probe context;
- закрытые `common/yonikbroker/` API и соответствующие tests;
- `transport/internet/system_dialer.go`;
- `transport/internet/memory_settings.go`;
- `transport/internet/hysteria/dialer.go`;
- `transport/internet/grpc/dial.go`;
- `transport/internet/splithttp/{dialer,client,mux}.go`;
- `app/dns/nameserver_local.go` и `features/dns/localdns/client.go` — отдельное
  DNS-дополнение явно утверждено пользователем после SOURCE trace context loss;
- относящиеся к ним regression tests.

Observatory-only разрешение не покрывает последующие transport файлы: их
дополнительный scope запрашивается вместе с утверждением этого плана.

Нужны совместимый guarded UDP PacketConn adapter без потери release/revoke,
trusted context handoff в gRPC callbacks и session-owned physical pools с
flow-owned logical requests/streams для Hysteria/gRPC/XHTTP. Нельзя unwrap
socket и потерять ownership, убрать guard, отключить xmux или разрешить missing
consumer ради совместимости. Контракт P1 должен обеспечивать isolation по
session/config/generation и авторизацию каждого logical open/reuse.

SOURCE evidence: Hysteria dialer ждёт PacketConnWrapper/cnc.Connection, тогда
как guardedSystemDial возвращает ownedFlowConn; memory_settings factory имеет
тот же type-switch риск. gRPC callback не переносит private consumer. Physical
socket сейчас привязан к cancellation первого flow, а pools допускают reuse.

Проверки: локальная компиляция затронутых packages и test binaries, только
in-memory tests с fake connections, без реального listen/dial. Проверить
UDP adapter без panic, независимую отмену двух logical streams, denial при
неверном binding/destination/subject, reconnect, полный session revoke и
ресурсные caps. Исполнение core/worker, network и services не разрешено.
Frozen ABI260, новые зависимости, другие transports и script masks не менять.

## P5. System helper: typed graph admission и EgressPlan

Agent: coder. Parallel: да, с P4. Blocked by: P3. Blocks: P6.

Owned files: `crates/yonik-linux/src/system_client.rs`,
`helper/service.rs`, `helper/session_host.rs`, `helper/session_host_tests.rs`,
`managed_network/firewall.rs`; новые `helper/profile_intent.rs` и
`helper/profile_intent_tests.rs`. Реальные пути тестовых modules сверить с
existing `#[path]` declarations перед изменением, не создавать параллельный
неиспользуемый test module.

Ввести versioned bounded typed profile request; это не raw native JSON/DSL.
Helper повторно валидирует graph/ownership и compiler output. Старый request
формат, legacy capability и frozen native wire остаются совместимыми. Размеры
и existing IPC limits не повышаются без доказанного общего бюджета.

SessionArtifact удерживает весь проверенный набор physical egress routes,
DNS bootstrap provenance и acquired resources. Использовать existing
BoundTransport vectors вместо allow-all worker UID. Каждая прежняя single-route
prepare/apply/active revalidation точка проверяет все элементы; любой stale
элемент инвалидирует подготовку. Direct provider flows получают явно проверенный
контракт native flow authorization и firewall, без неограниченного исключения.

Сохранить installed-profile/trusted executable/source checks, owner lifetime,
generation/digest binding, cancellation, custody и sticky Unknown cleanup.
Missing profile/proof не становится capability=true. Config validation не
объявляется actual traffic PASS.

Проверки: pure helper/profile/firewall tests, multiple endpoints TCP/UDP,
hostname bootstrap provenance, chain physical leaf, route change, stale
generation, caller cancellation, failed cleanup. Все host/backend queries —
mocked; services/proc/kernel/network и настоящие installed profiles не трогать.

## P6. Desktop/QML, actual Connect и Xray-only

Agent: coder. Parallel: нет. Blocked by: P2, P4, P5. Blocks: P7.

Owned files: `crates/yonik-desktop/src/{backend,system_session,preferences}.rs`,
`crates/yonik-desktop/qml/Main.qml`, relevant desktop backend tests и новый
`crates/yonik-desktop/tests/full_profile_connect.rs`.

UI показывает исходные profiles/remarks, а не искусственные host/port. Auto
виден как полноценный профиль. Native engine fixed to Xray. Sing-box убрать
из доступного выбора/Connect, но сохранить его persisted data и без потери
показать недоступность старых engine-specific profiles. Старую реализацию и
артефакты массово не удалять. Core-agnostic URI профили допускаются через Xray.

Оба Connect callsites передают profile-aware compiled config; generic compile
fallback и молчаливое игнорирование provider graph запрещены. Перед await и
после него сверяются source/profile/revision/command generation. Конфликтующие
Yonikrouting/DNS controls показывают конкретную причину недоступности.
Typed SourceFailure и Error/Connection contexts должны сохраняться.

Обязательны callsite regressions для полного Auto и остальных shapes, stale
selection/draft, engine mismatch и settings conflict. Отдельно проверить
source freshness требований P11; исторические execution/source bindings не
переписывать. Если потребуется reviewed_source_update в
`docs/validation/p11-integrated-candidate.json`, делать его только после
соответствующего узкого review, с `new_runtime_pass=false`.

Проверки: desktop pure tests, serde/snapshot contract, QML-related static/tests,
GUI compile-only и all-targets clippy. Настоящий Host/Qt/keyring не запускать.

## P7. Независимое интеграционное ревью

Agent: code-reviewer и security-engineer с read-only ownership.
Blocked by: P6. Blocks: P8.

Проверить exact source SHA/union, actual Connect paths, семь profile semantics,
encrypted storage/migration, bounds и отсутствие секретов, egress authority,
pool/per-stream isolation, native revoke и unchanged frozen contracts.
Критические findings возвращаются соответствующему writer; повторное ревью
ограничено findings/delta и затронутыми связями. Root не исправляет код вместо
Maestro исполнителя. Одобрение ревью не заменяет actual traffic evidence.

## P8. Сборка, evidence, установленное приложение и actual campaign

Agent: coder. Parallel: нет. Blocked by: P7.

Обычным локальным merge собрать отдельную интеграционную task-ветку; зафиксировать
parents/tree и сохранение проверенных blobs. Frozen source/команды/toolchain,
hashes и ELF сохранить до выполнения тестов. Rust 1.85.1 locked/offline/j1;
CARGO_TARGET_DIR только внутри собственного transient root с BSD directory
flock, сборки через существующий global Rust slot. Go — existing toolchain и
локальные зависимости, без downloads/upgrade. Полная compile-only сборка нового
Xray/GUI должна входить в утверждение плана; бинарники при этом не запускаются.

Сохранить текущий installed desktop binary и launcher для rollback. После
успешных разрешённых проверок обновить user desktop launcher/артефакты;
не активировать system helper/service/profile и не перезапускать пользовательскую
сессию автоматически. Новые authority/profile tuples не выдаются на основании
одной compilation. Сохранить exact install readback и hashes.

Затем подготовить reviewable actual campaign: source/ELF/profile pins,
отдельные cases всех семи profiles в LocalSocks/System, Auto health/rebalance,
DNS/direct/proxy routes, cancellation/stop/revoke и cleanup; точные endpoints,
ресурсы и rollback. Пользовательский отдельный grant требуется до core/worker,
network probes и services. Пока он отсутствует, evidence явно SOURCE/COMPILE/
MOCK_ONLY; задача не объявляется полной runtime acceptance.

Перед завершением этапа проверить отсутствие активных сборок и ссылок на
собственный transient, выполнить cargo clean, удалить только собственные
восстановимые roots. Единственные копии source/evidence/ELF оставить без TTL.

## Риски и запреты расширения

| Риск | Уровень | Контроль |
| --- | --- | --- |
| Потеря provider semantics при нормализации | Высокий | Полный graph, semantic fixtures и actual Connect assertions |
| Authority на shared transports и background flows | Высокий | Закрытый session contract, per-stream validation и revoke tests |
| Слишком широкие System egress exceptions | Высокий | Typed physical-leaf plan, routes/provenance/revalidation |
| Избранное и старая проекция каталога | Средний | Versioned rebuild и явное ambiguous mapping |
| Неучтённый file/network effect | Высокий | Closed validators и owned resource manifest |
| Дополнительные Go/ABI/dependency изменения | Высокий | Конкретный blocker до изменения, не расширять scope молча |
| Недостаток actual evidence | Высокий | Отдельный campaign grant, без подмены compile success на PASS |

## Самопроверка плана

Maestro MCP validate_plan недоступен; выполнена self-check по fallback протоколу.
Восемь фаз допустимы для complex scope. Dependencies ацикличны и содержат только
прямые blockers. У P2/P3 и P4/P5 нет shared writable files. Shared contracts
принадлежат P1 до запуска downstream writers. Read-only P7 не получает задачи
создавать код. Конкретные task briefs фиксируют дополнительные test files до
запуска, чтобы не было неявного shared ownership.

Execution Profile: восемь фаз; четыре parallel-eligible фазы в двух batches;
обычно не больше двух исполнителей одновременно. Риск повторной работы выше
в P1/P4/P5 из-за native authority; сначала contracts и source proof, затем код.
Предсказание часов без экспериментальных данных не даётся.

## Ожидающие решения

1. Пользователь утвердил план, дополнительный Go transport scope P4 и
   compile-only сборку Xray. Прежние запреты runtime/dependencies/ABI сохранены.
2. Пользователь выбрал parallel: до двух исполнителей в отдельных worktree.
