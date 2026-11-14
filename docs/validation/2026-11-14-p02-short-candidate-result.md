# P02 SHORT: завершённый candidate workload

**CANDIDATE_NOT_ACCEPTED**. 12 окон по 900.001–900.029 s: три пары на core.
Measurement source `35408d531a86ec858e1d2fc3489e8e092fda5d27`; posthoc validator
и targeted control source `51fd15a3a94c1e5e2ca400e1dcd7ccf26438715e`.

372 sample прошли новый validate_group без ошибок; 6/6 пар имеют идентичные
config bytes. Сохранённые product identities больше не живы; campaign exit 0,
failure.json и cleanup-fallback отсутствуют. Нормальные Stop/reap/rebind завершены.
Это проверка фактов старых rows, не задним числом выполненные lifetime pidfd guards.

## Ресурсы

PSS/private dirty — конец окна, медиана [min; max], MiB. CPU — секунды за 900 s.

| Core / группа | PSS | Private dirty | CPU |
|---|---:|---:|---:|
| sing-box / engine | 39.20 [37.35; 40.04] | 15.79 [14.04; 16.01] | 0.03 [0.01; 0.04] |
| sing-box / full | 139.07 [130.36; 145.58] | 92.97 [86.91; 95.71] | 0.02 [0.02; 0.03] |
| xray / engine | 33.05 [32.96; 33.05] | 8.24 [8.21; 8.30] | 0.02 [0.02; 0.03] |
| xray / full | 119.73 [119.12; 121.53] | 66.75 [66.60; 68.73] | 0.04 [0.02; 0.04] |

CPU baseline близок к нулю и квантован clock ticks: относительные проценты
здесь не являются надёжным сигналом регрессии. Raw FD/threads, отдельные GUI/core
PSS/private dirty, CPU ticks, namespaces и descendants сохранены во всех samples.
Wakeups=null с причиной; main-thread context switches подписаны как proxy.

## Независимые targeted controls и ограничения

Actual GUI wrong-CA → Limited/kind=tls/noHTTP и trusted restored-positive
завершены на обоих core теми же ELF/observer/pins. Cleanup fault controls на actual
pinned engines: SIGSTOP + controlled pre-health abort → TERM→KILL, exit/reap/rebind.
Это root engine_only teardown, не production GUI cleanup_fault API. 6 tests PASS.

`sing-box-2-full` имеет документированный overlap/noise targeted controls.
Поэтому три чистых повторения для sing-box не установлены. Остальные условия:
dev/unoptimized GUI, offscreen/software Qt/private SNI, порядок full→engine;
влияние прочей host-нагрузки не исключено. Energy/physical Plasma/full-system TUN,
release budgets и остальная config-матрица не покрыты.

Root-review должен определить пригодность candidate и точный дальнейший scope.
Новые 900 s пары автоматически не запускались. Старые PASS/raw/manifest не менялись.

## Evidence

[Сводка validator и hash каждого окна](../evidence/p02-short-private-20261114/final-candidate.json).
Полные immutable measurement raw/ELF/source:
`/home/myrs/projects/yonik/local/evidence/p02-short-private-20261114/`.
Posthoc source/checks: `/home/myrs/projects/yonik/local/evidence/p02-short-final-20261114/`.
Targeted controls и overlap intervals:
`/home/myrs/projects/yonik/local/evidence/p02-r2-targeted-20261114/completion.json`.

Own transient Rust target ранее очищен cargo clean, 2.5 GiB; task root удалён.
P01/product CLI/common application/build не изменены.
