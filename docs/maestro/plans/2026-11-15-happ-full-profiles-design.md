---
title: Полные Xray-профили подписки как в Happ
created: 2026-11-15
status: approved
type: design
design_depth: standard
task_complexity: complex
session_id: 2026-11-15-happ-full-profiles
source_base: e14aeae6c0cd89e9a49bd4ee03b4c6412e0e2e32
---

# Полные Xray-профили подписки

## Проблема

Текущий importer обходит outbounds каждого JSON-конфига и создаёт отдельные
ParsedServer. Каталог repository сохраняет эти серверы, а не самостоятельные
корневые конфигурации. Поэтому UI показывает узлы «Авто выбора», теряет
группировку и не предоставляет запуск исходного алгоритма балансировки.
Полный зашифрованный snapshot уже сохраняет исходник; потеря семантики возникает
в проекции профилей и компиляторе запуска, а не в самом хранении response.

## Уже согласовано пользователем

1. Standard Maestro: дизайн, план, реализация и независимое ревью.
2. Полные профили сразу для LocalSocks и System/TUN.
3. Provider routing/DNS сохраняются. Конфликтующие общие настройки Yonik явно
   недоступны для полного профиля; молчаливого объединения нет.
4. Отдельный тип полного профиля рядом с обычным сервером. Сохраняются корневые
   конфигурации, порядок и названия, без автоматической смены ядра.
5. Sing-box пока исключён: доступным ядром этапа остаётся Xray. Существующие
   данные sing-box не удаляются и не преобразуются в Xray без явного действия.
6. Архитектура полного профиля подтверждена. Узкий Go scope observatory явно
   разрешён: реализация, локальная компиляция и чистые in-memory unit tests;
   runtime/network/services и изменения frozen ABI260 не разрешены.

## Требования и критерии

- REQ-1: один корневой JSON-конфиг даёт один полный профиль; для проверенного
  response это семь профилей, включая «Авто выбор». Число семь не зашивается.
- REQ-2: сохраняются ordered routing, outbound chains, balancers, observatory,
  DNS и используемые transport extensions; неизвестные поля не исчезают молча.
- REQ-3: выбранный полный профиль действительно поступает в runtime compiler;
  generic single-server fallback запрещён в обоих режимах.
- REQ-4: LocalSocks и System/TUN используют один проверенный Xray graph, но
  разные планы принадлежащих приложению ресурсов и сетевой авторизации.
- REQ-5: refresh, offline reopen, revision/generation CAS и активная сессия
  сохраняют существующие гарантии. Новая версия каталога перестраивает старую
  проекцию из encrypted snapshot без повторного сетевого скачивания.
- REQ-6: IDs и избранное не зависят от display name. Старые избранные узлы нельзя
  автоматически объявлять эквивалентными всему balancer profile; неоднозначное
  сопоставление сохраняет запись и явно требует повторного выбора.
- REQ-7: публичные DTO, ошибки и логи не раскрывают credentials, JSON или URL.
  Структурная проверка и общий бюджет памяти предшествуют materialization.
- REQ-8: после проверенной интеграции обновляется установленное приложение с
  сохранением прежнего бинарника для rollback. GUI и actual traffic results
  фиксируются отдельно от compile-only и pure-test результатов.

## Архитектура — согласована

```text
subscription response
  → bounded import и encrypted original snapshot
  → ServerProfile | XrayFullProfile
  → revision-bound selection
  → closed validated Xray graph + explicit ownership plan
  → trusted runtime compiler
      → LocalSocks CompiledConfig → CheckedConfig → LocalSession
      → System CompiledConfig + EgressPlan → helper prepare/apply → worker
```

Полный профиль привязан к Xray; универсальная cross-engine IR не требуется.
Типизированные validators сохраняют поддержанные native extensions и все
ссылки между узлами. Простой blacklist опасных ключей не является validator.
Исходный документ, принятые semantics и итоговые runtime bytes имеют разные
идентичности. Итоговый sealed runtime digest остаётся основанием запуска.

Compiler создаёт собственные loopback/probe listeners, TUN, logging и API
поверхности. Provider paths, listeners, загрузки файлов и script effects не
исполняются произвольно. Конфликтующие inbound references требуют явного
согласования, а не удаления. Probe проверяет ProfileDefault/заданный graph
entry, а не фиксированный outbound с именем proxy.

System helper должен удерживать bounded EgressPlan: физические transport
endpoints, protocol, captured routes, DNS provenance и generation. Проверяются
все элементы перед prepare/apply и во время активности. Исключение для узла,
доступного через chain, не превращается в разрешение прямого обхода chain.
Mandatory native authorization/revocation остаются обязательными независимо
от provider routing. Существующий firewall уже принимает bounded vectors.

### Рассмотренные подходы

| Подход | Сохранение поведения | Проверяемость | Решение |
| --- | --- | --- | --- |
| Xray-specific typed graph и trusted emitter | Сохраняет native algorithms и ссылки | Явные validators и ownership | Рекомендуется |
| Полная общая IR двух ядер | Требует доказывать перевод алгоритмов | Большая дополнительная область | Не нужна при Xray-only |
| Прямая передача provider JSON | Сохраняет bytes, но не контролирует effects | Не удовлетворяет trust boundary | Не допускается |
| Извлечение одного outbound | Теряет Auto и собственные правила | Текущая проблема остаётся | Не удовлетворяет REQ-1/2 |

## Конкретный native blocker и предлагаемый Go scope

Retained patched Xray source:
`local/evidence/linux-controller-rehearsal-14229843-msrv85-2/patched-source-xray.tar`.
SHA256: `e5184047fd1380472f69114fb8173a0adfd8c50970560eceb9c87fcba0bb35e9`.
Hash совпадает с preserved-source.json принятой базы. Upstream commit
`a4a3dff5b20c2faae567b742c172c7b95e75c083`, версия 26.10.31.

Доказанная SOURCE-цепочка:

```text
app/observatory/observer.go:151–152
  → tagged.Dialer(root context, destination, outbound)
transport/internet/tagged/taggedimpl/impl.go:22–25
  → dispatcher.Dispatch без закрытого consumer
app/dispatcher/default.go:268–270
  → RoutingEntry
common/yonikbroker/routing.go:65–68
  → ErrDenied при отсутствии private routingKey
```

CarryClosedSession переносит только уже имеющийся consumer; на feature/root
контексте observatory такого источника нет. Rust/JSON не могут создать private
Go routingKey. Отключение guard или доверие произвольному tag запрещены.

Предлагаемый узкий native seam: служебный observatory probe получает capability
только от уже аутентифицированной runtime session, связанной с точным config
digest/generation. Ограничения включают разрешённые probe destinations и
outbound subjects, tracking ресурсов и global revoke/stop. Сам provider tag
или feature context не создаёт такую capability. Конкретный API и выдача
capability должны пройти отдельный design/security review перед реализацией.

Предполагаемые upstream места изменения:

- `app/observatory/observer.go` — выдача probe context через закрытый API;
- `common/yonikbroker/` — минимальный закрытый служебный session/flow API и
  тесты его binding, denial, expiry и revoke;
- adapter patch/manifest/source-lock plumbing для воспроизводимого применения.

Пользователь явно разрешил этот Go scope. Разрешение включает только эти
изменения и локальную compile-only проверку затронутых пакетов/тестов плюс
чистые in-memory unit tests существующим toolchain и локальными зависимостями.
Без загрузок, запуска worker/core, сетевых probes, сервисов и изменения ABI260.
Если выяснится необходимость других Go-файлов или wire fields, область должна
быть отдельно обоснована. Создание capability из недоверенного JSON запрещено.

## Оставшиеся проверки исходников

Первый audit остановился после observatory blocker; затем выполнено отдельное
ограниченное продолжение по выбранным transport shapes. Direct и chains
доходят до existing guarded physical leaf; TCP `header-custom` оборачивает
уже открытое соединение. System firewall semantics для direct всё ещё требует
Rust-контракта, а не allow-all worker UID.

Найдены дополнительные concrete SOURCE blockers:

- Hysteria `dialer.go:130–142` и `memory_settings.go:76–91` ожидают UDP
  PacketConnWrapper/cnc.Connection, но guardedSystemDial возвращает ownedFlowConn;
  успешный guarded dial попадает в panic/type mismatch.
- gRPC `dial.go:102,122–130` восстанавливает часть context, но не private consumer.
- Hysteria/gRPC/XHTTP переиспользуют physical transports для разных logical
  flows, тогда как existing OwnSocket связан с cancellation первого flow.
  Нужны session-owned physical lifetime и отдельный guard каждого logical flow.

Минимальный дополнительный Go scope перечислен в P4 implementation plan.
Пользователь отдельно разрешил его при утверждении плана.
Frozen ABI260/dependencies и новые mask families в расширение не входят.
Для выбранного `header-custom` отдельный Go networking change не требуется.
Другие finalmask variants имеют дополнительные script/network effects;
разрешение выбранного variant не распространяется на весь namespace.

Scope всех семи профилей остаётся целью. Временный Unsupported в ходе разработки
не считается поставкой полного результата. Config-check не доказывает, что
observatory, маршрутизация и отзыв разрешений работают на настоящем трафике.

## План проверок — согласован

1. Санитизированные fixtures всех семи форм, без реальных адресов/credentials:
   boundaries, названия, порядок и отсутствие flattened дубликатов.
2. Graph semantics: balancers/selectors, reference sets, prefix selectors,
   DNS detours, chains, probe target и transport settings.
3. Негативные проверки malformed/unknown fields, размеров до аллокаций,
   file/script/network effects, tag collisions и отсутствующей authority.
4. Каталог: refresh/reorder/rename, revision conflict, offline reopen, старая
   БД и избранное. Ошибка не заменяет рабочий snapshot.
5. Настоящий Connect callsite обоих режимов, exact digest binding, stale
   prepare, отмена и cleanup failure. Нет generic fallback.
6. Native служебные flows: отказ без capability, неверный digest/generation,
   запрещённый destination/subject, stop/revoke и закрытие ресурсов.
7. Релевантные pure tests, fmt, clippy all-targets -D warnings; затем отдельно
   разрешённые config-check/actual tests на pinned binaries. Успех не выводится
   только из compilation или наличия профилей в интерфейсе.

## Команда и границы будущего плана

После согласования shared contracts можно разделить import/catalog, Xray
validator/emitter, System helper EgressPlan и native observatory seam. Одновременно
обычно работают один–два исполнителя с непересекающимися owned files. Отдельный
reviewer проверяет native authority и реальные callsites после интеграции.
Точный план, worktrees и execution mode утверждаются до code delegation.

## Текущее состояние

Дизайн подтверждён пользователем, включая раздел проверок. Product-код и Go
не менялись, runtime не запускался. Утверждены scope, provider ownership,
модель профиля и архитектура, включая ограниченные Go scopes observatory и P4
transport changes. Конкретный native capability API требует технической
проверки. Implementation plan утверждён; ожидается выбор execution mode.
