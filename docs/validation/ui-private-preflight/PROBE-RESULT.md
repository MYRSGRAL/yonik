# Продолжение PR191: пассивный native counter

Утверждённое root расширение из пунктов 1–4 реализуется только в bench/ui.
Старый run2.json — исторический результат до Probe; GTK Quit RED повторён
на неизменённых retained ELF в gtk-quit-red.json с тем же timeout=15 секунд.

Причина GTK: main() удерживает сильный window reference; Control::Quit вызывает
window.destroy(), но MainLoop завершается только сигналом destroy. RED получил
все 11 reports на обоих размерах, затем Quit timeout. Теперь Control::Quit
явно вызывает MainLoop.quit() перед destroy независимо от lifetime окна.

Legacy 14-field report/ack и оригинальный tools/ui_benchmark.py не меняются.
Probe — GUI-thread read-only snapshot с двумя дополнительными полями. Qt nonce
передаётся через QML строкой, чтобы не терять точность u64 в JavaScript.
Counter overflow насыщается в MAX и делает следующий Probe invalid; сброса и
wrap нет. Qt atomic counter считает frameSwapped, GTK постоянный observer
считает after-paint (paint cycle, **не presentation**), Slint считает каждый
AfterRendering перед pending guard. Observer не вызывает redraw/tick/timer.

Короткая матрица выполняет одинаковую последовательность на 1000/10000:
initial frame; Probe A; scroll 199/frame; Probe B>A; settling/no-mutation пары;
query page; exact-host cold search и немедленно тот же warm search; select;
favorite/filter/reset/sort/scroll; visible settling; hide/hidden settling;
show/shown settling; Quit с лимитом 15 секунд и reap. Cold здесь первый поиск
в процессе, не обещание холодного файлового кеша. Каждое действие имеет latency
и process sample (PSS/USS, CPU ticks, context-switch proxy), Probe сохраняет
исходное состояние/counter и sample. Counter разных toolkit не считается
одинаковым видом presentation. GPU и hardware_power записываются null.

Positive canary использует тот же PID до idle. Frozen/disconnected controls
подменяют **наблюдение** реального Probe B и проходят через тот же validator и
canary gate: native observer не отключается во время валидного прогона.
Stale nonce и overflow observation также внедряются в реальный Probe report.
Malformed nonce (-1/bool/string/u64 overflow) отдельно посылаются настоящему
stdin parser каждого toolkit; требуется invalid_input и нормальный Quit.
Model tests проверяют u64 boundary, неизменность всей модели, exact Probe shape,
отмену последующих actor команд на Quit и saturation->invalid. Это не
аппаратный frame oracle и не независимый code review.

## Контракт после независимого review

Root отдельно разрешает длинный launch после проверки коротких evidence и
source/binary binding. Порядок: rep=1..3, rows=1000/10000, toolkit=qt/gtk/slint;
всего 18 последовательных fresh процессов. Совпадающая функциональная
последовательность выше, затем ровно 900 секунд visible и 900 hidden на каждый
процесс, Show и Quit/reap; Probe на границах фаз, passive /proc samples не реже
60 секунд, без GUI polling в idle. Таймаут 2100 секунд + 10 cleanup на ячейку.
Между фазами допускаются settling frames с сохранением raw counter facts;
установка renderer фиксирована: Qt software/xcb, GTK cairo/x11, Slint
femtovg/winit/X11 с Mesa LIBGL_ALWAYS_SOFTWARE=1/GALLIUM_DRIVER=llvmpipe.

Короткий runner намеренно не содержит режима 9 часов: запуск долгой кампании
не авторизован этой задачей. P01/P02 long campaigns — возможный шум, их не
останавливали. Physical Plasma/Wayland/energy/GPU и выбор toolkit остаются
отложенными. Зависимости, pins, production MSRV/root Cargo не меняются.

## Проверенный результат

Финальный `probe-short-final.json`: 6/6 functional runs PASS (1000/10000,
Qt/GTK/Slint), matched_workload=true. 12/12 настоящих malformed-nonce inputs
отклонены с invalid_input; после каждого native loop нормально завершился.
3/3 дополнительных сценариев скрывают окно, посылают scroll без ожидания кадра,
затем Quit и Probe после Quit: ни frame, ни Probe после отмены не допускается,
finish(15) требует exit=0. Все 21 native child и Xvfb reap/proc-absence PASS.
Каждый functional run отвергает повреждённые page_hash/event, frozen/disconnected
observation, stale nonce и counter overflow. Во всех шести процессах прошёл
round-trip nonce=18446744073709551615, включая Qt/QML.

GTK permanent after-paint counter в видимом состоянии растёт примерно на 60
paint cycles/s даже **до** canary scroll. Отдельный gtk-idle-diagnostic.json:
initial 2→121 за 2 секунды без команд; scroll 124→244 за 2 секунды; hidden
244→244 за секунду; shown 245→366 за 2 секунды. Во всех шести немедленных
диагностических парах Probe счётчик совпал. Это не 60 presentations/s и не
доказанная энергия. Нулевой idle budget не является acceptance этой fixture.
Первый новый short отвергался ошибочным требованием нулевого delta за каждый
300-мс интервал. Последующий вариант включал дорогой Python Oracle между
немедленными probes; он также захватывал очередной независимый paint cycle.
Финальный runner сохраняет до четырёх settling intervals и проверяет fast
ack-A→send-B без вычисления Oracle/чтения /proc между ними. Оба reports затем
полностью валидируются; изменение counter в этой паре по-прежнему invalid.
Ни GTK Quit timeout, ни legacy state assertions не ослаблялись.

Build/test: Rust 1.97.0, offline, wrappers empty, jobs=1, directory root flock
и global with-rust-slot. Release build PASS; 12 model tests PASS; clippy
--release --all-targets -- -D warnings PASS; cargo fmt --all --check PASS;
23 existing Python driver tests + 2 private tests PASS; ruff check/format PASS.
Qt/GCC header выдаёт C++ QChar SFINAE warning; Rust clippy ошибок не дал.
Existing fake-child suite выдаёт два ResourceWarning; сторонний код не менялся.

Новые ELF, оба source archives, commands, checks/cleanup logs и полный final
runtime output сохранены вне TTL:
`/home/myrs/projects/yonik/local/artifacts/ui-probe-191-20261114-v1`.
Старые ui-readiness-20261111 ELF/bindings не изменялись. Active process
cwd/exe/fd/maps references на собственный target отсутствовали перед clean;
cargo clean удалил сборки, собственный transient root удалён. Чужие runtime
и task directories не очищались.

## Точная привязка

`probe-binding.json` хранит SHA-256 трёх новых ELF и всех 17 compiled inputs.
Native build snapshot: bench/ui subtree
85f392227d51e9801670cdce9e10a090144529ce. Финальная fixture:
aecbe04ffee46e388939ec26bf8ac60d921ec386. Между ними изменился только
**не компилируемый** private-x11-preflight.py (корректировка idle sampling и
дополнительный pending-Quit контроль); все 17 native inputs побайтно совпадают.
Оба архива сохранены, binding явно разделяет native build и финальную tooling
metadata. Ни один из этих subtree ID не объявляется полным root tree.

Кандидат готов к независимому preflight review root. Длинная кампания не
запускалась; разрешение на неё, физическое принятие и выбор toolkit отсутствуют.
