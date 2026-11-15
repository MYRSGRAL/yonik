---
session_id: 2026-11-15-happ-full-profiles
status: in_progress
workflow_mode: standard
design_depth: standard
task_complexity: complex
design_approved: true
implementation_plan_approved: true
execution_mode: parallel
execution_backend: native
current_phase: 1
total_phases: 8
current_batch: foundation
design_document: docs/maestro/plans/2026-11-15-happ-full-profiles-design.md
implementation_plan: docs/maestro/plans/2026-11-15-happ-full-profiles-impl-plan.md
phases:
  - {id: 1, name: Контракты и базовые типы, agent: coder, status: in_progress, parallel: false, blocked_by: [], files_created: [], files_modified: [], files_deleted: [], retry_count: 0}
  - {id: 2, name: Импорт и каталог, agent: coder, status: pending, parallel: true, blocked_by: [1]}
  - {id: 3, name: Xray compiler, agent: coder, status: pending, parallel: true, blocked_by: [1]}
  - {id: 4, name: Native transport, agent: coder, status: pending, parallel: true, blocked_by: [3]}
  - {id: 5, name: System helper, agent: coder, status: pending, parallel: true, blocked_by: [3]}
  - {id: 6, name: Desktop и Connect, agent: coder, status: pending, parallel: false, blocked_by: [2, 4, 5]}
  - {id: 7, name: Независимое review, agent: code-reviewer, status: pending, parallel: false, blocked_by: [6]}
  - {id: 8, name: Сборка и установка, agent: coder, status: pending, parallel: false, blocked_by: [7]}
source_base: e14aeae6c0cd89e9a49bd4ee03b4c6412e0e2e32
---

# Полные профили подписки как в Happ

## Подтверждённая цель

Пользователь выбрал полные профили сразу для LocalSocks и System/TUN.
Самостоятельные JSON-конфигурации должны сохранять порядок, названия и
семантику, включая многосерверный «Авто выбор». Standard Maestro выбран явно.
Пользователь выбрал сохранение routing/DNS логики провайдера: несовместимые
общие настройки Yonik явно недоступны для такого профиля, без тихого merge.
Пользователь подтвердил отдельный тип полного профиля рядом с обычным сервером:
границы корневых JSON-конфигураций сохраняются, ядро закреплено, тихого
преобразования в другое ядро нет. Согласование owned-полей явное.
Последующее уточнение пользователя: sing-box пока исключён. На этом этапе
доступным ядром остаётся Xray. Существующие данные sing-box сохраняются,
не удаляются и не преобразуются молча. LocalSocks и System/TUN входят в цель.
Пользователь подтвердил архитектуру и явно разрешил узкий Go seam observatory,
описанный в draft дизайна: код, локальная компиляция и чистые in-memory tests.
Это не разрешение на запуск core/worker, служб, сетевых probes, загрузки
зависимостей, изменение других Go-областей или frozen ABI260.
Раздел проверок подтверждён: семь профилей, оба режима, security/review,
обновление приложения и отдельная actual-проверка. Дизайн и план приняты.
Во время детализации найден дополнительный
Hysteria SOURCE blocker: совместимость native socket wrapper и QUIC reuse.
Его scope и pooled transport changes отдельно разрешены в утверждённом P4.

## Подтверждённые факты

- Установлен и запущен бинарник принятой базы e14aeae6; старый процесс не
  объясняет наблюдаемое расхождение.
- Тестовая подписка с User-Agent приложения возвращает семь полных JSON
  конфигураций. Секретный URL и response не включаются в документы и Git.
- Три конфигурации содержат balancers/observatory; все семь имеют DNS.
  Отдельные transport shapes включают TCP, XHTTP, Hysteria и gRPC.
- ImportReport.servers и каталог repository сейчас проецируют отдельные
  нормализованные outbound/server records, а не корневые конфигурации.
- Зашифрованный snapshot сохраняет оригинал; отдельного типизированного
  полного профиля и его resolve/activation пути пока нет.
- Миграция должна учитывать версию проекции каталога, стабильные ID,
  избранное, refresh и generation/revision CAS.

## Текущая работа

- Анализ импорта и хранения завершён read-only агентом debugger.
- Отдельный architect исследует System/TUN и LocalSocks authority/activation
  границы. Найден Xray SOURCE blocker: служебный observatory probe не получает
  закрытый ConsumerGuard/routingKey и отказывается текущим RoutingEntry.
  Поддержка Auto в System/TUN требует узкого Go seam; отключение guard запрещено.
  Узкий Go scope observatory теперь разрешён; конкретный закрытый API и его
  binding/revoke должны пройти проверку в первом implementation этапе.
  Реализация и runtime не начинались.
- Дизайн и план одобрены. Следующий шаг — выбор execution mode и запуск P1.
- Продолжение source audit завершено: direct/chains/header-custom доходят до
  existing physical guards; Hysteria UDP wrapper, gRPC handoff и pooled transport
  lifecycle требуют дополнительного Go scope. Он описан в P4 и явно разрешён.
- Implementation plan подготовлен: восемь фаз, self-check dependencies и
  parallel ownership PASS. План, включая расширение P4, одобрен.
  Execution mode выбирается следующим шагом по Maestro.
- Пользователь явно утвердил восемь фаз и дополнительный Go scope P4:
  Hysteria UDP ownership и pooled gRPC/XHTTP/Hysteria context/lifecycle,
  regression tests и compile-only сборка Xray. ABI260/dependencies не менять;
  runtime/network/services по-прежнему требуют отдельного grant.
  Пользователь выбрал parallel, до двух исполнителей в отдельных worktree.
  P1 запускается отдельно из-за зависимости остальных фаз от shared contracts.

## Ограничения

Сохранить шифрование, границы размеров, проверку возможностей, lifecycle,
native broker и авторизацию. Произвольный JSON не становится System authority.
Go разрешён только в описанных observatory и P4 transport scopes. Изменение
зависимостей, других Go-областей и frozen ABI отдельно не разрешены. Реальные
службы, ядра и пользовательское хранилище в исследовании не запускались и
не читались. Эта задача не объявляет полную Linux acceptance.
