---
status: proposed_for_source_review
implementation_approved: false
session_id: 2026-11-15-happ-full-profiles
---

# Дополнение scope для завершения P4/P5

Это проект дополнительных изменений к принятому восьмифазному плану.
Перечисленные здесь новые области implementation ещё не разрешены. Запуски
ядра, helper/worker, Host/GUI, служб и сетевых probes по-прежнему закрыты.
Принятый DATA/compiler результат не выдаёт runtime authority.

## Сохраняемый результат и ограничения

Полный Xray-профиль сохраняет provider routing/DNS, Auto, chains и transport
settings в обоих режимах. Конфликтующая глобальная executable/routing/DNS policy
не смешивается с профилем. Sing-box данные сохраняются, запуск пока недоступен.
Новых dependencies, изменения ABI260, frozen записей, старых FD counts и
переписывания исторических execution evidence нет.

Local использует normal Host, его checked final config bytes и sealed executable
snapshot. Private child-bound канал не даёт TUN/firewall/OS-attribution прав.
`required=false` определяется доверенным Local mode. Для System сохраняется
existing `app_required=true`, verified RuntimeScopeStamp и один owner backend.
Xray выбирает provider route; issuer проверяет разрешённый scope и обязательные
ограничения, не реализуя второй provider routing evaluator.

## Дополнительные Go callsites

Это дополнение к уже разрешённым broker/observatory/transport/DNS файлам.

| Файл в pinned Xray | Минимальная задача |
| --- | --- |
| `main/run.go` | Принять authenticated admission до создания features/Start |
| `proxy/tun/handler.go` | Выдать per-flow immutable System ingress receipt |
| `app/proxyman/inbound/worker.go` | Удержать accepted TCP/UDP tuple и lifetime |
| `proxy/socks/server.go` | Связать handshake/каждый actual UDP destination с receipt |
| `proxy/http/server.go` | Разделить CONNECT и каждый plain keep-alive request |
| `app/dispatcher/default.go` | Проверить receipt и выбранный subject/chain после routing |
| `transport/internet/udp/dispatcher.go` | Проверять actual payload destination перед cached-link reuse |
| `app/proxyman/outbound/handler.go` | Проверить actual protocol scope и outbound mux decision перед proxy dispatch |
| `transport/internet/dialer.go` | Проверить source-scope→next-scope chain redirect, который обходит default dispatcher |
| `common/mux/client.go` | Session-bound physical factory вместо Background и отдельные logical grants |

Owned inbound mux отвергается явно; outbound xmux сохраняется. Изменение
`common/mux/server.go` в этот вариант не входит. Для каждого callsite нужны
точные in-memory regressions без настоящих listen/dial.
Всего десять дополнительных Go callsites. Source-derived exact mapping,
protocol transitions и P5STRM01 binding закреплены в capsule-mapping.md.
Глобальный browser dialer не наследуется в owned full-profile launch env.

## Дополнительные Rust области

| Файл относительно `crates/yonik-linux/src/` | Минимальная задача |
| --- | --- |
| `helper/systemd_worker.rs` | Создать и удержать отдельный sideband после verified coverage |
| `helper/native_bootstrap.rs` | Связать checked manifest с существующим stamp/revocation |
| новый `helper/native_profile_channel.rs` | Bounded codec, issuer ledger и общий owner actor |
| `worker/role_handoff.rs` | Отдельный YNKEXT01/ACK и extension exec custody |
| `attribution/native_session.rs` | Единственный actor-владелец owner backend |
| `attribution/native_session/transport.rs` | Сохранить frozen semantics и actual-sent receipt |
| `host/session.rs`, `host/process.rs` | Normal Local child/channel/exact-byte lifecycle |
| новый `host/local_profile_channel.rs` | Local scope issuer без OS attribution |
| `helper/protection_host.rs` | FullProfile operation в существующем serialized backend |
| `helper/native_owner.rs` | Адаптировать два SessionArtifact test literals, без расширения authority |
| `worker.rs` | Отдельная native-DAT ветка WorkerPayload вместо canonical RebuiltBatch |
| `worker/native_resources.rs`, `worker/native_assets.rs` | Проверить и stage exact owned DAT, сохранить custody до cleanup |

Уже разрешённый P5 scope `native_profile/intent.rs` и его module exports
дополняется только закрытой typed scope projection из того же validated intent.
Общий bounded channel codec следует вынести в новый `profile_channel.rs` корня
yonik-linux; helper/Local модули разделяют codec, не копируют wire реализации.
Его declaration в `lib.rs` механическое; новый public arbitrary authority
constructor не допускается. Соответствующие pure tests располагаются рядом
с owned modules; non-scoped legacy файл не получает нового полномочия по имени.

Module declarations в существующих `helper/mod.rs` и `host/mod.rs` входят только
как механическое подключение новых модулей. `run_authorization.rs`,
`anchor_exchange.rs`, `broker/remote.rs`, `host/binary.rs` не требуют изменений
по текущему source trace. Не расширять этот список без конкретного нового факта.

## Firewall и ресурсы

Direct-dynamic classification не разрешает dial. До GRANT serialized backend
проверяет numeric destination, mandatory constraints и полный route capture,
устанавливает durable policy с exact BoundTransport и повторно проверяет fence.
Static, bootstrap DNS, dynamic, private/LAN/link-control вместе остаются внутри
existing MAX_EXCEPTIONS=128. Blanket worker UID исключения запрещены.

Shared exact exception имеет bounded refcount. Последний grant отзывается до
durable retirement правила. Неопределённый исход сохраняет journal/custody и
Unknown, блокируя новые opens; recovery не восстанавливает старые grants.
Используется existing nft executor/journal API, без нового kernel ABI.

Pinned DAT должен иметь проверенные actual bytes/hash/kind/category и отдельную
trusted delivery ветку. IPC descriptor сам по себе не proof. Fixed root-owned
catalog, точная source policy, staging и provisioning определены в
resolver-snapshot-contract.md. Existing worker asset/tmpfs limits не повышаются
по compiler cap512MiB; DAT и resolver asset вместе должны помещаться в прежний
worker budget64MiB и его file count. Oversize отвергается до staging.
Provider localhost не подменяется публичным DNS. Snapshot сохраняет pinned
CGO-disabled netgo semantics, включая files/order/search/options и stub peers;
он доставляется отдельным проверенным asset, без live libc/OS fallback.

## Проверки и граница утверждения

Source/code review, compile-only Xray и Rust/GUI, pure fake race/caps/revoke tests
и frozen-vector regressions остаются разрешёнными проверками принятого плана.
Actual traffic и активация System потребуют отдельного конкретного grant.

Порядок реализации после отдельного утверждения этого дополнения:

1. Общий codec/layout + closed typed projection и fake parity tests Rust/Go.
2. Local/System issuer/custody и ресурсы; параллельно Go grants/transport guards
   в двух непересекающихся worktrees с зафиксированным общим контрактом.
3. Actual dispatch/native hooks, direct durable policy и lifetime/cleanup tests;
   затем исходные P6 Desktop/Connect, P7 review, P8 build/install/campaign.

Текущий строгий P5 NSS subset не повышается до полной поддержки одним изменением
документа. Новый snapshot consumer обязан пройти malformed/FD mutation/peer/
cache/cancel/family regressions. Catalog/data provisioning ещё не выполнен.
Source rechecks закрыли текущие NSS и pinned-native findings; runtime остаётся
неподтверждённым. Pure tests не читают resolver/user state и не запускают sockets.

Эти три документа представляют proposed source scope, не user approval и не
обещание готовности. Доработка новых файлов начнётся только после явного
согласования: Go вне прежнего перечня раньше не разрешался. После утверждения
кодек уточняется только внутри описанных closed schemas/caps, без изменения
старых ABI или расширения destinations/authority. Любое такое расширение
требует нового конкретного решения, а не неявного fallback.
