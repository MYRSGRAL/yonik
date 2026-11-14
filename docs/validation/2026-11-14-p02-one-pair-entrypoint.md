# P02: one-pair entrypoint для root narrow review

Source+unit/dry-run checkpoint. `--execute` **не запускался**. Новый GUI/engine,
fixture, controls, measurement, rebuild/download/VM не выполнялись. Старые 12 raw
и control bindings не изменены. R-A означает только bounded observational reuse,
не выполнение новых guards в старой кампании и не полный P02.

Новый `tools/p02/one_pair.py` заменяет только отсутствовавший selector из minimum
plan: фиксированы sing-box, replacement pair №2, один повтор, full→engine,
900+900 s. Нет caller config/server/shell/artifact inputs. `--core`, `--pair`,
`--repeats`, `--seconds` принимают только эти значения. Output фиксирован:
`/home/myrs/projects/yonik/local/evidence/p02-replacement-sb2-reviewed`.
Любой существующий output, включая dangling symlink, даёт отказ; execute отдельно
резервирует его атомарным mkdir(exist_ok=False). Default dry-run ничего не создаёт.

## Проверено сейчас

6 selector unit tests: ровно два planned windows; dry-run без execute/Popen/mkdir;
execute routing только через mock; wrong core/pair/repeats/duration и arbitrary
config/shell args rejected; wrong output/collision/symlink/hash rejected; fake-driver
composition выполняет один full idle и один engine_only, передавая **тот же bytes
object** из capture, без parse/recompile baseline. Настоящие helpers при этих unit
не вызываются. Ruff check/format проходят; actual dry-run проверил SHA256 existing
ELF/observer/core/corrected driver и напечатал JSON. Это не runtime proof replacement.

## Exact argv/environment

Из assigned worktree:

```sh
cd /home/myrs/.t3/worktrees/yonik/t3-aef0f1a8-4b0e7a90d95fae43
env -u APPIMAGE -u APPDIR -u LD_LIBRARY_PATH -u LD_PRELOAD -u PYTHONPATH \
  PYTHONDONTWRITEBYTECODE=1 python3 tools/p02/one_pair.py
```

Явные fixed args, эквивалентный dry-run:

```sh
env -u APPIMAGE -u APPDIR -u LD_LIBRARY_PATH -u LD_PRELOAD -u PYTHONPATH \
  PYTHONDONTWRITEBYTECODE=1 python3 tools/p02/one_pair.py \
  --core sing-box --pair 2 --repeats 1 --seconds 900 \
  --output /home/myrs/projects/yonik/local/evidence/p02-replacement-sb2-reviewed
```

Только **после отдельного root narrow review и разрешения единственной pair**
к последней команде добавляется `--execute`. В этой задаче runtime permission
ещё не дано. Не использовать stock campaign(), --oracle-only или повтор всего P02.

При execute reused `gui()` создаёт закрытое private environment, same-UID bus и
real SecretService; external fixture генерируется теми же helpers. Loopback ports
выбираются заново существующим port allocator, key policy не меняется. Полный
GUI с actual QAction connect/hide выполняет capture и corrected held-pidfd/group
idle; Stop/reap/rebind/quit завершает GUI **до** engine half. Engine-only получает
captured bytes непосредственно, LANG=C, SSL_CERT_FILE=та же own CA, тот же peer,
health fixture и config keepalive. После обоих окон сверяются retained config
bytes. Whole-run deadline 2400 s; TERM/INT/ALRM переводятся в исключение и cleanup
existing helper contexts. Ошибка сохраняет failure.json, без retry/перезаписи raw.
Завершение означает REPLACEMENT_PAIR_RECORDED_REVIEW_REQUIRED, не P02 PASS.

## Bindings и границы review

Selector SHA256:
`cf898d917d0c425f1e6583b175cc10d649254a3b4928da40790be3dc1c391fc6`.
Corrected driver SHA256 не менялся:
`508f837200ffa07aaaca6e88cc296c41dd789bf6dfbd9aa054d6bd8c43536f23`
(source 51fd15a). Hard-pinned paths/digests GUI, observer и sing-box находятся в
[actual dry-run JSON](../evidence/p02-short-private-20261114/one-pair-dry-run.json).
Исходные production source/ELF остаются прежними, нового Rust build нет.

Narrow review: selector bounds/default no-runtime; no output overwrite/race;
ровно full→engine без additional oracle/campaign; exact captured object и file
bytes; reuse 51fd held-pidfd/cleanup contexts; source/artifact pins и evidence
status. Никакой новый product/common/P01 код не меняется.

Остаются известные границы: старые observations posthoc, dev/unoptimized GUI,
offscreen/private SNI, fixed-order bias, недоступные точные wakeups, physical/8h
и matrix вне scope. Неизменённые targeted TLS/cleanup controls не повторяются.
