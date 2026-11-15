---
status: draft
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

Owned inbound mux отвергается явно; outbound xmux сохраняется. Изменение
`common/mux/server.go` в этот вариант не входит. Для каждого callsite нужны
точные in-memory regressions без настоящих listen/dial.

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
trusted delivery ветку. IPC descriptor сам по себе не proof. Existing worker
asset/tmpfs limits не повышаются по compiler cap 512 MiB; oversize отвергается.
Provider localhost не подменяется публичным DNS. Snapshot должен учитывать
actual source identity и поддержанные resolver semantics без live fallback.

## Проверки и ещё открытые пункты дизайна

Source/code review, compile-only Xray и Rust/GUI, pure fake race/caps/revoke tests
и frozen-vector regressions остаются разрешёнными проверками принятого плана.
Actual traffic и активация System потребуют отдельного конкретного grant.

До передачи этого дополнения на утверждение должны быть закрыты:

- Точное разделение unique subjects/protocol scopes, chain transitions и alias
  mapping в capsule; P5STRM01 и enum bytes связать с принятым P5 codec.
- Конкретный trusted DAT catalog/source locator и lifecycle provisioning.
- Полный resolver snapshot contract для требуемого NSS/backend поведения;
  текущий P5 поддерживает только `hosts: dns`/nameserver-only и честно отказывает
  остальным вариантам. Это ещё не достаточное доказательство работы подписки.
- Результат независимого P5 custody review и соответствующие исправления.

До этих уточнений документ остаётся draft; перечень файлов не является
заявлением готовности или разрешением их менять.
