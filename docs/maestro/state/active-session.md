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
current_phase: 2
total_phases: 8
current_batch: import_and_compiler
p1_task_id: node:delegated-task:command%3Amcp%3A86c209a8-956f-4962-9793-d3caa9268944%3Adelegate-task%3A4b1e8175-889a-4852-b8c6-a82144dfde88
p1_thread_id: thread:delegated-task:command%3Amcp%3A86c209a8-956f-4962-9793-d3caa9268944%3Adelegate-task%3A4b1e8175-889a-4852-b8c6-a82144dfde88
p1_candidate: d6857b21e6992e3d4b7d448b4395a44f6f96d842
p1_review: scoped_clean
p1_recheck_thread: thread:delegated-task:command%3Amcp%3A86c209a8-956f-4962-9793-d3caa9268944%3Adelegate-task%3A98dc36ca-eb0f-439b-86eb-879a1a7c6a13
p1_review_thread: thread:delegated-task:command%3Amcp%3A86c209a8-956f-4962-9793-d3caa9268944%3Adelegate-task%3A2fdfb486-f16a-4156-b6f1-5b63eb67b2fc
design_document: docs/maestro/plans/2026-11-15-happ-full-profiles-design.md
implementation_plan: docs/maestro/plans/2026-11-15-happ-full-profiles-impl-plan.md
phases:
  - id: 1
    name: Контракты и базовые типы
    agent: coder
    status: completed
    parallel: false
    blocked_by: []
    files_created: [crates/yonik-import/src/native_profile.rs, crates/yonik-import/tests/native_profiles.rs, tests/fixtures/xray-full-profile-seven.json, docs/proposals/xray-full-profiles/contracts.md]
    files_modified: [crates/yonik-import/src/lib.rs]
    files_deleted: []
    retry_count: 1
    downstream_context:
      key_interfaces_introduced: ['import_profiles(Vec<u8>) -> Result<ProfileImportReport, ImportFailure>', 'ProfileEntry::Server | Xray', 'NativeProfile ordinal/name/engine/source/write_sensitive', 'Proposed FlowGrant and separate ProbeGrant native contracts']
      patterns_established: ['One root = one profile', 'Raw sensitive DATA is not runtime authority', 'Typed per-flow grants do not derive from session credential']
      integration_points: ['P2 report.entries and encrypted original', 'P3 trusted native profile validator', 'P4/P5 reviewed source/digest/generation/cancellation grant contract']
      assumptions: ['Fixture synthetic; native extension schemas must be checked against pinned source']
      warnings: ['Go/native implementation and actual acceptance not provided by P1']
  - {id: 2, name: Импорт и каталог, agent: coder, status: in_progress, parallel: true, blocked_by: [1]}
  - {id: 3, name: Xray compiler, agent: coder, status: in_progress, parallel: true, blocked_by: [1]}
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
- P1 делегирован coder/Sol medium в отдельном T3 worktree. Root docs commit
  412ede9 сохраняет согласованные дизайн, план и execution mode. Повторных
  подтверждений для уже утверждённых локальных implementation шагов не требуется.
- Автор P1 завершил кандидат 64dbfc7: пять owned files, пять новых тестов и
  прежний importer suite/clippy/fmt PASS. Кандидат ещё не интегрирован и P1
  не завершён до независимого review code/bounds и native contract.
  Scope deviation evidence: первая compilation до retention compiler ELF,
  затем suite повторён после retention; подтверждение полного exact source
  archive не подменяется частичным package snapshot.
- R1 нашёл escaped protocol, URI line preservation и отсутствие явного
  per-flow grant в native contract. Root исправил узкую delta в d6857b2,
  добавил два regression tests и разделил FlowGrant/ProbeGrant. RED подтвердил
  оба дефекта (5 pass/2 fail); GREEN full importer suite/clippy/fmt PASS.
  Полный source archive и test ELF сохранены до исполнения; каждый tracked
  файл/исполняемый bit сверяется с fix commit. Evidence:
  /home/myrs/projects/yonik/local/orchestration/evidence/happ-full-profiles-p1-root/
  Собственный target очищен cargo clean, transient удалён.
- Узкий re-check R1 98dc36ca — scoped CLEAN для трёх findings на d6857b2.
  P1 gate закрыт; реализация native grants всё ещё относится к P4/P5.
- P2/P3 подготовлены к parallel delegation из reviewed P1 + state-only commit.
- PR229 остаётся OPEN на 155af74: Python падает exact P11 source freshness.
  Предыдущий typed Connect correction 700bd6f и его review/evidence сохранены
  отдельно. Эта ветка не включается неявно в Xray full-profile source base.

## Ограничения

Сохранить шифрование, границы размеров, проверку возможностей, lifecycle,
native broker и авторизацию. Произвольный JSON не становится System authority.
Go разрешён только в описанных observatory и P4 transport scopes. Изменение
зависимостей, других Go-областей и frozen ABI отдельно не разрешены. Реальные
службы, ядра и пользовательское хранилище в исследовании не запускались и
не читались. Эта задача не объявляет полную Linux acceptance.
