# Сравнение Linux UI

Изолированный стенд Qt Quick/CXX-Qt, GTK4 и Slint на общем Rust actor. Он не
заменяет действующий GUI yonik и не использует реальные профили, SQLite, keyring
или proxy core. Состав окна и обмен JSONL описаны в [PROTOCOL.md](PROTOCOL.md).

Production MSRV остаётся прежним. Для стенда используется Rust 1.97.0: версии
GTK4 0.11.5 и Slint 1.18.1 требуют Rust 1.92. Зависимости стенда закреплены его
собственным Cargo.lock, основной workspace не меняется. Все кандидаты собираются
одним toolchain с одинаковым release profile. Noto Sans должен быть доступен
через fontconfig; системные библиотеки GTK4/Qt Quick требуются отдельно. Для
CXX-Qt нужен совместимый linker: lld/gold/mold вместо GNU ld.bfd.

Сборочный каталог должен находиться вне checkout, под общим lock корня задачи:

```sh
mkdir -p /var/tmp/codex-myrs/transient/yonik-ui-comparison
flock -s /var/tmp/codex-myrs/transient/yonik-ui-comparison \
  /home/myrs/projects/yonik/local/orchestration/with-rust-slot \
  env CARGO_TARGET_DIR=/var/tmp/codex-myrs/transient/yonik-ui-comparison/target \
  CARGO_BUILD_JOBS=1 cargo +1.97.0 build --manifest-path bench/ui/Cargo.toml \
  --release --bins --locked
```

Сравнивать следует реальные окна последовательно в одной незаблокированной
сессии, после завершения всех сборок. Offscreen не подтверждает энергопотребление.
Различия системных контролов и renderer необходимо отражать в результатах.
Счётчики созданных, живых и видимых строк различаются; Slint сообщает недоступные
live/visible как null. Прокрутка подтверждает запрос и кадр, но фактическая
геометрия требует отдельной визуальной проверки.

Полный план принятия решения находится в
[плане UI benchmark](../../docs/superpowers/plans/2026-11-09-linux-ui-benchmark.md).
Короткий smoke подтверждает протокол и работоспособность стенда. Он не выбирает
победителя и не закрывает G-UI/G-POWER, проверки других DE, accessibility,
fractional HiDPI, clipboard, tray и connected-idle с engine baseline.

Варианты внешнего вида независимо от toolkit находятся в
[design/ui-variants.html](../../design/ui-variants.html).

## Воспроизводимый запуск

`check-offscreen.py --artifacts /каталог --output /новый/каталог` проверяет хеши
бинарников из manifest.json и тот же JSONL-сценарий на 1000/10000 строках через
независимый oracle драйвера. Desktop display исключён из окружения дочерних
процессов. Qt использует software/offscreen; GTK — headless, если он поддержан
системной библиотекой. Slint сохраняет выбранный winit/OpenGL backend. Отказ
backend — сохранённый blocker, а не успешная проверка. Idle и ресурсные
сравнения эта команда не выполняет.

`bash bench/ui/run-comparison.sh /каталог/артефактов /новый/каталог/результатов`
проверяет ScreenSaver и SHA-256, затем запускает кандидатов последовательно:
три повтора × два размера × три toolkit. Каждый прогон ограничен GNU timeout
2100 секундами, после TERM даётся 10 секунд на cleanup. Общее верхнее время
18 × 2110 секунд (около 10 ч 33 мин), обычные idle-фазы занимают около 9 часов.
Ошибка останавливает серию; частичные результаты не перезаписываются.
Нужна активная разблокированная Wayland-сессия и корректный XDG_SESSION_ID;
команда не меняет блокировку, suspend или профиль питания. При автоблокировке
драйвер прервёт visible idle. Три повтора — повторные process startup, без
обещания холодного файлового кеша. Это только стоимость synthetic UI процесса,
без controller/tray/engine baseline и аппаратной энергии, не закрытие G-POWER.

Частный X11 preflight с passive Probe/native counters находится в
`private-x11-preflight.py`; его evidence и границы acceptance описаны в
[preflight](../../docs/validation/ui-private-preflight/README.md).
Этот отдельный runner не ослабляет Wayland/session guards основного драйвера.
