# P02: read-only closure после selector review

Готов только source/bindings checkpoint. Measurement, GUI/engine/native product,
fixture, controls, waiter/autolaunch не запускались. Toolkit не опрашивался и не
приостанавливался. Gate для будущей единственной pair: root подтверждает toolkit
terminal **COMPLETE + owned cleanup**, затем отдельно разрешает команду execute.

## Snapshot

`/home/myrs/projects/yonik/local/evidence/p02-one-pair-closure-b1b9ce1/`

Manifest SHA256:
`21f90aa0776ba26870c0e691c7479d9a122efbd64e961ae4beac8d781b51033e`.
[Bindings и результаты проверки](../evidence/p02-short-private-20261114/closure-binding.json).

8 файлов, 219818 bytes source/assets плюс manifest; это не копия repo:

- `tools/p02/one_pair.py` byte-exact reviewed b1b9ce1;
- `tools/p02/connected_idle.py` byte-exact reviewed 51fd15a;
- `tools/engine_host.py`, `tools/engine_compile.py`, `tools/engine_smoke.py`,
  `tools/traffic_echo.py`: транзитивные Python imports, byte-exact b1b9ce1;
- `tools/p02/tray_fixture.py`: отдельный child script actual GUI path;
- `crates/yonik-desktop/qml/Main.qml`: expected qrc hash reference для gui().

Для Main.qml остальные QML/assets читаются из unchanged GUI ELF, поэтому весь
QML tree не нужен. `engine_smoke.FIXTURES` и `engine_host.ROOT` теперь указывают
в snapshot; TUN/echo/sandbox/compiler функции не вызываются one_pair. Engine-only
импортирует только wait_listener из engine_compile, не generated()/compiler.

`campaign()` не вызывается и linux-composition.json не читает. Этот metadata
оставлен только как pin provenance в verification evidence вне runtime closure;
необходимые core/GUI/observer hashes уже hard-pinned в selector. Ни одного байта
reviewed source не исправляли для переноса. Literal runtime worktree dependency
не обнаружена: REPO/__file__ imports, tray child path и qrc expected hash
разрешаются относительно snapshot. Старый controls path снаружи snapshot —
immutable evidence reference, не mutable worktree import.

Все snapshot directories 0555, files 0444, symlinks отсутствуют. Manifest/content
hashes проверены после установки permissions. Это read-only дисциплина и
content binding, **не** kernel immutable flag: владелец технически может chmod.
Snapshot после финальной проверки не изменяется; результаты проверки пишутся
только в отдельный каталог, приведённый ниже.

## Проверка isolated environment

Точный проверенный argv (cwd `/`):

```sh
env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -B \
  /home/myrs/projects/yonik/local/evidence/p02-one-pair-closure-b1b9ce1/tools/p02/one_pair.py
```

Этот argv — **dry-run**, --execute не добавлялся. Fixed output остаётся
`/home/myrs/projects/yonik/local/evidence/p02-replacement-sb2-reviewed` и отсутствует.
Dry-run bindings теперь содержат snapshot path corrected driver, не путь worktree.
Selector SHA256 остался `cf898d917d0c425f1e6583b175cc10d649254a3b4928da40790be3dc1c391fc6`;
corrected driver — `508f837200ffa07aaaca6e88cc296c41dd789bf6dfbd9aa054d6bd8c43536f23`.

Отдельный import-only audit загрузил всю локальную Python closure из snapshot.
Python audit запрещал процессы, fork/spawn/exec, sockets, чтения worktree и записи
вне verification evidence. Событий runtime нет; module origins/read paths не
содержат worktree. Exact argv dry-run и audited dry-run JSON совпали; snapshot
не получил __pycache__ или иных новых файлов. Все проверочные Python команды
завершились exit 0, owned background handles отсутствуют.

Verification evidence:
`/home/myrs/projects/yonik/local/evidence/p02-closure-verification-b1b9ce1/`:
`verification.json`, `manifest.sha256`, `exact-argv-dry-run.json`,
`dry-run-audit.json`, `imports-audit.json`, audit probe source.

28 объявленных host inputs (Python/openssl/curl/dbus-daemon/KSecretD/gdbus,
выбранные Qt libraries/plugins и GI/dbus package/typelib files) сверены по hashes;
3 existing GUI/observer/core ELF также совпали с прежними bindings. Native
binaries для этой проверки не запускались, только читались их файлы. Это не
hermetic OS image и не полный runtime file trace: stdlib/system libraries остаются
host inputs, их обновление требует повторной сверки перед запуском. Raw старой
кампании, controls и original ELF не изменены.

После root проверки snapshot и toolkit terminal gate будущая execute команда
использует тот же argv с единственным добавленным `--execute`. Никакого waiter,
расписания или автоматического продолжения здесь нет. Worktree больше не нужен
этому source closure и может использоваться для другой задачи. R-A по-прежнему
означает bounded observational reuse snapshots, не новые guards задним числом
и не final P02/release/physical/8h acceptance.
