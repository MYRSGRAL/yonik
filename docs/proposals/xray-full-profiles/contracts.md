# Контракт полных профилей P1

Статус: DATA API реализован; runtime/native API ниже предложен для независимого
review перед P4/P5. Compile-only и pure tests не являются Linux/runtime acceptance.

## Публичный importer API

`yonik_import::import_profiles(Vec<u8>) -> Result<ProfileImportReport, ImportFailure>`.
`ProfileEntry::Server(ParsedServer) | Xray(NativeProfile)`.
Report: `entries: Vec<ProfileEntry>`, `issues: Vec<Issue>`,
`base64_envelope: bool`, `original(&self) -> &SecretText`.
NativeProfile имеет закрытые поля и конструктор:
`ordinal(&self) -> usize` (с нуля), `name(&self) -> &str`,
`engine(&self) -> ProfileEngine` (единственный вариант Xray),
`source(&self) -> &SecretText`,
`write_sensitive(&self, impl std::io::Write) -> Result<(), std::io::Error>`.
Нет Serialize/Deserialize, произвольного Value constructor и runtime capability.

Один top-level объект или каждый непосредственный элемент массива даёт ровно
один Xray DATA profile. Не рекурсивный поиск. Признак Xray: непустой outbounds
массив объектов с непустым строковым protocol без sing-box type. Это распознавание
семейства, не валидация protocol/settings: неизвестные расширения сохраняются.
Пустой массив и нераспознанный root — fatal, частичный native report не публикуется.
Duplicate keys (включая escaped aliases) запрещены на любой глубине.
URI и один Base64 envelope используют прежнюю серверную модель; старые
`import_bytes`, `import_reader`, cancellable API не меняются.

Лимиты: input 8 MiB, decoded 32 MiB, roots 20 000, каждый root 64 KiB,
JSON depth 64. Сначала depth/unique/raw syntax, затем bounded root references,
проверка размера до materialization. Сумма копируемых roots <=32 MiB; поскольку
roots не пересекаются, она также <= content.len(). Original <=8 MiB; decoded
временно <=32 MiB; raw roots в сумме <=32 MiB; метаданные O(input), references
<=20 000. Полное дерево Value не строится. Для native report нет второй копии
целого native_json. Name до 160 символов без control, хранится с redacted Debug;
подпись недоверенная и может содержать секрет. UI должен экранировать её.
Ошибки сохраняют исходные bytes и сообщают только FatalError без source snippets.

## P2: каталог и reconciliation

Новая версия проекции каталога — 2. Это контракт будущей реализации repository,
не изменение существующей БД в P1. Rebuild из encrypted original snapshot,
без network и без удаления старой проекции до успешного CAS. Selection связывает
source ID, catalog version, source revision/generation, profile kind и identity.
Проверки делаются до и после await; refresh не переключает активную сессию.

Identity native: source-scoped, kind-separated keyed SecretIdentity от полного
root без top-level remarks/tag; остальные bytes/поля входят в identity. P2 должен
реализовать ограниченную канонизацию объектов (порядок ключей несущественен,
порядок массивов существенен), сохраняя raw root отдельно. Имя и ordinal не ID.
Идентичные roots требуют multiset reconciliation: старые IDs сохраняются при
однозначном соответствии; неоднозначность требует выбора, не присваивает чужой ID.
Изменение семантики создаёт новую identity. Нельзя сопоставлять старый outbound
favourite с полным balancer автоматически. Старые записи сохраняются для явного
повторного выбора. Root digest, semantic identity и emitted runtime digest различны.

## P3: graph и compiler ownership

P3 читает `source().expose()` только в trusted validator и не логирует его.
Summary P1 ограничен ordinal/name/engine; endpoint summaries получаются лишь из
проверенного graph. Типизированный закрытый graph принадлежит yonik-engine,
не importer. Все поля должны быть consumed валидатором или вызывать typed отказ;
unknown effects не превращаются в authority. Ссылки, циклы, selectors, ordered
rules, DNS detours и physical chain leaves проверяются до emitter.

Предложенные API P3:
`compile_profile_local(&NativeProfile, &OwnedRuntimePlan) -> Result<CompiledConfig, ProfileCompileError>`;
`compile_profile_system(&NativeProfile, &OwnedRuntimePlan) -> Result<CompiledProfileSystem, ProfileCompileError>`.
OwnedRuntimePlan, CompiledProfileSystem и EgressPlan — закрытые новые типы P3.
System result содержит CompiledConfig и bounded typed egress requirements,
но не FD/route permission. Compiler владеет listeners, probes, TUN, API и logging;
provider routing/DNS сохраняются без тихого merge с global settings. Конфликт
явно недоступен. Provider files/scripts/downloads/listeners не выполняются.
Helper заново валидирует bounded typed graph и ownership, затем связывает exact
emitted digest/generation с prepare/apply/active revalidation всех egress leaves.
Сырой JSON через IPC не authority. Generic server fallback запрещён.

## P4/P5: предлагаемый закрытый native контракт

Следующие имена — проектируемый Go internal API, не существующая гарантия.
Точка проверки — common/yonikbroker и trusted adapter admission после
аутентификации runtime run, до запуска observatory/transport callbacks.
`AdmitSession(authenticatedRun, runtimeDigest, generation, boundedManifest)`
выдаёт непрозрачный SessionHandle только trusted adapter. Нет конструктора из
tag/context/provider JSON. Manifest выведен из проверенного graph и содержит
probe destination (scheme/host/port/path и политику redirects), allowed subjects,
physical leaves, transport policy, expiry и caps. Binding проверяется на каждом
open/reuse; DNS resolution/rebinding и redirect не расширяют destinations.

`SessionHandle.OpenProbe(destination, subject)` выдаёт закрытый flow consumer
только при точном binding; `OpenLogical(subject, destination, transport)`
проверяет каждый logical stream даже при готовом pooled physical connection.
Неверный digest/generation, unknown/expired/revoked session и missing consumer
дают denial до dial. Provider tag — только проверяемое имя, никогда credential.
Никакого fallback на root context. Выдача capability и revoke линеаризованы:
revoke запрещает новые открытия, включая незавершённый dial/reconnect.

Physical transport принадлежит session, logical request/stream — отдельному
consumer. Отмена первого или любого logical flow закрывает только его stream;
не закрывает соседний и не продлевает authority отменённого. Global revoke/stop
закрывает все streams, idle/dialing physical sockets и callbacks, освобождает
ресурсы ровно один раз; cleanup failure остаётся видимым Unknown.
Pool key включает session identity, runtime digest, generation, transport/security
parameters, destination и chain/subject isolation. Межсессионный reuse запрещён.
Caps обязательны на session/pool/physical/logical counts, pending opens, bytes,
idle lifetime; checked counters резервируются до allocation/dial, возвращаются
на error/cancel. Reconnect заново проверяет binding и egress authorization.

gRPC callback получает trusted sealed session handoff от admitted transport
factory, а не из произвольного callback context. Callback заново открывает
проверенный logical consumer; missing handoff — denial. UDP PacketConn wrapper
сохраняет необходимые Hysteria type-switch интерфейсы, но не отдаёт наружу
незащищённый socket. Read/Write/ReadFrom/WriteTo/Close/deadlines проходят ownership
и revoke guards; destination ограничен manifest. Close idempotent; release ровно
один раз, ошибки и частичные открытия не теряют custody. Проверить обе factory
ветки system_dialer и memory_settings, включая typed mismatch без panic.

Обязательные P4 тесты — in-memory fake connections: denial без capability,
wrong digest/generation/subject/destination, callback handoff, два logical streams
с отменой одного, reconnect, caps и конкурентный revoke/dial/close. P5 отдельно
проверяет все routes/provenance и stale prepare без allow-all worker UID.

## Существующие SOURCE invariants и недостающие доказательства

По source facts принятой задачи xray::extract flatten-ит outbounds в ParsedServer;
repository prepare_profiles_checked использует report.servers; original encrypted,
native_json — весь документ. HelperSessionArtifact пока single endpoint;
closed worker payload bounded JSON+digest не разрешает raw JSON effects.

Pinned archive: patched-source-xray.tar, SHA256
e5184047fd1380472f69114fb8173a0adfd8c50970560eceb9c87fcba0bb35e9.
Это переданные root SOURCE findings, не повторный native audit P1:
observatory не имеет closed consumer; guarded UDP wrapper несовместим с
Hysteria type-switch; gRPC callback теряет consumer; pooled physical ownership
связан с первым flow. P1 их не исправляет и не заявляет готовый native API.
До P4/P5 нужен независимый review этого контракта; до acceptance нужны source
proof реализации и отдельно разрешённые actual проверки. Frozen ABI260,
зависимости и Go в P1 не меняются. Fixture синтетическая, не actual evidence;
её extension shapes требуют сверки P3 с pinned native schema.
