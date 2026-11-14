# Private X11 campaign supervisor

Новая отдельная tooling delta после frozen native commit
`0c184394de3a336048c065f74075e3555fc70068`. Файлы native/model/Probe/GTK,
прежние ELF и bindings не меняются. Этот wrapper требует отдельного review;
его short proof не подменяет независимый frozen review native inputs.

## Контракт

`--mode campaign` выполняет ровно 18 cells: rep=1..3 → rows=1000/10000 →
qt/gtk/slint, последовательно, один candidate process/session за раз. Общий
частный Xvfb живёт на протяжении серии; Xvfb и host/compositor не входят в
ресурсные суммы candidate. Никаких физических Plasma/Wayland/power выводов.

Каждая cell: process-cold startup (не cold filesystem cache), initial frame,
Probe A → scroll/frame → Probe B>A; page, первый exact-host search и тот же
warm repeat, select/favorite/filter/reset/sort/scroll. Далее Probe на границах
900 секунд visible и 900 hidden; Show, Quit, exit=0, cleanup/reap. Во время
900-секундной фазы stdin не используется: только stdout readiness и пассивные
/proc samples через 5 секунд. Нет дополнительных settling intervals, вычитания
settling или требования нулевого delta. Естественные GTK paint cycles остаются
в измерении; after-paint не объявляется presentation. Qt frameSwapped и Slint
AfterRendering сохраняют отдельные определения.

Sample содержит CPU ticks всех потоков процесса, SC_CLK_TCK, PSS/USS,
main-thread context-switch **proxy**, wakeups=null, gpu=null,
hardware_power=null, реальные timestamps чтения. Conditions на границах и с
каждой выборкой содержат UTC/monotonic, uname, loadavg, renderer environment,
наблюдаемые build processes того же UID. Другие workers/P02 не меняются.
Короткие build bursts между samples и процессы других UID могут быть пропущены.
Частота 5 секунд — целевой период; реальные timestamps сохраняют scheduler/read
jitter. Суммы CPU/memory и deltas вычислять по этим timestamps, не подменять
неизвестные wakeups нулём. Probe send/ack boundaries включают собственный
transport/observer overhead; он не вычитается произвольно.

Cell alarm — 2100 секунд, затем отдельный cleanup budget 10 секунд. SIGTERM →
SIGKILL адресуются только зарезервированной owned process group и pinned pidfds;
leader не reap до последних group signals. Namespace/start/PGID/SID/executable
identity проверяется при spawn и samples. Локальный subreaper позволяет reap
наблюдённых осиротевших descendants, включая сменивших session. Обнаруженный
candidate descendant делает cell FAILED: leader-only metric его не учитывает.
Census при sampling и cleanup не является непрерывным fork/exit tracer:
короткоживущий descendant и его peak resources между census могут быть пропущены,
а ненаблюдённый escaped descendant не имеет доказанной атрибуции. Поэтому это
не доказательство полного process-lifetime accounting. Cleanup failure и
unaccounted observed child никогда не дают COMPLETE. Kernel-stuck процесс
может не завершиться в budget: это FAILED с cleanup evidence, не успешный reap.

`--mode short` сохраняет все 18 cells/операции/identity/cleanup, но использует
150 мс на фазу, sampling 50 мс и cell budget 30 секунд. COMPLETE в таком terminal
означает только **mode=short**, не прохождение 900/900.

## Snapshot и запуск после разрешения root

`create_snapshot.py` создаёт новый каталог вне TTL/worktree, проверяя frozen
Python dependencies и все 17 native inputs против commit 0c184 и retained
manifest. Копируются runner, frozen Child/Oracle/resource_counters/Probe helper,
17 native source inputs, три ELF, Xvfb, provenance и сам snapshot builder.
Файлы read-only, каталоги 0555; manifest содержит SHA-256 каждого файла,
контракт, отдельные frame definitions и trusted host inputs (static ldd closure
Xvfb/ELF, Python executable, xkbcomp). Это SHA-pinned cooperative read-only
snapshot; владелец того же UID способен изменить permissions. Это не защита от
злонамеренного owner/root и не полностью герметичный OS image: Python stdlib,
динамические plugins/fonts и trusted host libraries остаются host runtime.
Static host inputs проверяются до/после серии; обновление делает серию FAILED.

Python запускается `-I -B`, cwd переводится в snapshot, imports идут из snapshot.
Native plugin/library path overrides удаляются только из окружения потомков;
PATH фиксируется /usr/bin. Worktree после запуска не читается. `ready.json`
содержит reference audit cwd/exe/fd/maps, modules/sys.path/code source names для
supervisor, Xvfb и первого candidate; каждая последующая cell повторяет audit.
Root может переназначить worktree только после проверки актуального ready и
живого PID/start/namespace/session из receipt (с собственным pidfd), отсутствия
ссылок на worktree у runtime/launcher и совпадения manifest SHA. Launcher также
следует запускать с cwd snapshot: команда ниже начинает с cd и exec.

Актуальный reviewed snapshot v6, manifest SHA, точная абсолютная команда и
terminal contract находятся в `launch-v6.json`. `preflight.json` сохраняет
исторический v5 short proof и не является новым runtime proof для v6.
v6 создан из reviewed cleanup-only source d5c99880cb14dbde2d870610d2cbbf509df472eb;
root сообщил narrow CLEAN, 8 controls PASS и post-reap OSError control.
Здесь выполнен только non-native validate/dry-run: 28 file hashes, 158 host inputs,
source/import/cwd/exe/fd/maps audit; owned validator завершён, native/campaign
процессы не создавались. У inspectable same-UID peers refs v6 не найдены;
permission-denied peers перечислены в binding, общесистемное отсутствие refs не заявлено.
Старый immutable v5 сохранён. GUI/18-cell/long запуск и повтор controls не выполнялись.
Команда **не выполнялась в campaign mode**. Её запуск требует отдельного явного
разрешения root после native frozen review и wrapper review.

Результаты: immutable `receipt.json` (PID/start/namespace/exe/session/boot ID),
`binding.json`, `ready.json`, 18 `cell.json` и fsync+rename `terminal.json`.
Только exit=0 + terminal event state=COMPLETE + mode=campaign + 18 valid cells
+ успешный cleanup являются campaign completion. Receipt/ready без terminal,
FAILED, отсутствующий terminal или mode=short не являются таким completion.
Output должен быть новым каталогом вне worktree/TTL; частичные результаты не
перезаписываются. Malformed metadata разбирается внутри supervisor finally.

## Проверки

```sh
python -m unittest discover -s bench/ui/campaign -p test_runner.py -v
ruff check bench/ui/campaign
ruff format --check bench/ui/campaign
```

Семь тестов запускают настоящие маленькие owned children: ignored TERM требует
KILL/reap; same/escaped-session descendant вызывает fail; malformed metadata
после spawn, невалидный stdout, cell alarm и CLI malformed manifest дают FAILED;
реальный 5-секундный sampler не пишет в stdin. Native short дополнительно
проверяет весь 18-cell цикл на retained ELF из immutable snapshot. Никаких
Rust rebuild, новых dependencies/downloads, Docker или изменений host session.
