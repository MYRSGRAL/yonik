# Типизированный профиль и сетевой план сессии

Продолжение [плана интеграции](https://github.com/MYRSGRAL/yonik/blob/c454a0d7398529aaf095dc70c6329aa4e3370052/docs/superpowers/plans/2026-11-10-system-session-integration.md).
Этот срез готовит вход и сетевую часть SystemSessionHost. Сам авторизованный
session host, его IPC и GUI пока не реализованы; `system_tun:false` сохраняется.

## ServerIntent

`yonik_import::ServerIntent` переносит только известные поля сервера. Закрытый
контракт содержит protocol/host/port/credentials/transport/security/options.
Нет путей, argv/env, unit, raw URI или готовой конфигурации ядра. Все шесть
протоколов импорта представлены явно; неизвестные/неподдержанные параметры
отклоняются, а не теряются при преобразовании. Проверка конкретным compiler
и config-check закреплённого ядра остаётся обязательной.

Единственная JSON-точка входа — `parse_json`: до выделения DTO проверяются
64 KiB входа и глубина до пяти контейнеров. Общего Deserialize у публичного
типа нет; compile-fail doc-test закрепляет запрет обхода этой границы.
Приватные DTO запрещают неизвестные, повторные и отсутствующие поля.
Строки ограничены, ALPN содержит не более 16 элементов. Ошибки категориальные,
Debug скрывает данные. Сериализация явно содержит credentials и разрешена
только для защищённого канала; это не диагностический export.

`from_server` не читает файлы и не делает DNS-запросы. `into_server` восстанавливает
core-поля для compiler, оставляя source пустым: исходный URI/JSON и пользовательские
названия продолжают храниться в существующем repository, а не в helper DTO.
Hostname допустим в DTO; его безопасное bootstrap-разрешение решает host.

## SessionNetworkPlan

`helper::SessionNetworkPlan` не десериализуется. Helper выбирает CSPRNG name ID,
table, socket mark, RPDB priority и адреса двух семей; проверяет пересечения с
представленной topology. План связывает `compiler_tun()` с теми же дескрипторами,
которые передаются production TunExecutor и durable Journal.

Journal IDs сессии — 16…22: TUN, IPv4/IPv6 адреса, два default route в собственной
таблице, два inverted-mark capture rule. ID 1 оставлен действующей public policy.
Чужой PublicBlock record внутри session-окна отклоняется до эффектов.

Порядок методов:

1. Host проверяет авторизацию, generation/context и свежую внешнюю topology.
2. `configure` создаёт TUN, настройки link, адреса и маршруты, без RPDB capture.
3. Host готовит nft-защиту и подтверждает transport escape с правильным worker UID.
4. `capture` устанавливает правила обеих семей. Подтверждены должны быть все
   семь точных записей; старый Confirmed с pending reconciliation не принимается.
5. Host запускает worker и отдельно проверяет cgroup, endpoint, readiness и DNS.
6. После подтверждённого завершения worker tree host вызывает
   `cleanup_after_worker`: RPDB → routes → addresses → TUN. Публичную блокировку
   этот метод не снимает; решение зависит от kill switch и авторизации Unlock.

Ошибки/отмена оставляют durable частичный journal. Повторный configure не
выдаётся за recovery; host обязан выполнить явную сверку/очистку. Существование
плана или успешный capture не означает Applied/Connected.

## Собственные изменения и внешняя topology

`session_external_topology` — чистая проекция actual RTNETLINK snapshot. Она
проверяет namespace/alias/имя/MTU/link shape, подтверждённые addresses/routes/RPDB,
исключает только их и узко проверенные kernel derivatives. Чужие адреса, маршруты,
правила, nexthops, multipath и child/master references не скрываются. Нет удаления
по одному имени или фильтрации всех маршрутов таблицы без проверки.

`verify_external` требует точный состав семи ресурсов и сравнивает проекцию с
исходным snapshot. Порядок внешних записей сохранён; даже безвредная перестановка
может потребовать повторной подготовки. Нельзя просто присвоить новый NetworkStamp
после эффектов и объявить все изменения своими.

Граница: собственные per-link AF_SPEC devconf/token и TXQLEN/GSO/GRO/TSO metadata
проверяются по ABI-форме, а не по первоначальным значениям. Для полного binding
host должен отдельно закрепить собственный link contract; проекция не заменяет
эту проверку, resolver/manager context, event-loss detection или live reconcile.

Приёмка среза: [evidence](../validation/2026-11-10-session-plan.md).
