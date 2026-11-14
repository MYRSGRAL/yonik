# Частный software X11 preflight

Продолжение с утверждённым Probe/native counter: [PROBE-RESULT.md](PROBE-RESULT.md).
Описанное ниже — историческое состояние первой итерации PR191.

Это ограниченный кандидат, **не готовность к длинному benchmark**. Physical
Plasma/Wayland, GPU, энергия, screenshot geometry и toolkit winner не доказаны.
P01/P02 long campaigns могли создавать шум; их процессы не менялись.

Новая ветка основана на accepted main cce6c4e4522491c6830bb6ae533a88fbb84030db.
Сохранённые ELF не пересобирались. Manifest source_tree
26cd45d015fe29dcb89631d0774dd7153e55ff73 обозначает только bench/ui subtree.
Root уже проверил три ELF и 17 compiled inputs; helper/docs имеют отдельную
смешанную metadata, соответствие полного root tree не заявляется.

## Короткая проверка

`bench/ui/private-x11-preflight.py` использует существующие Child/Oracle,
сверяет три SHA с retained manifest, запускает собственный Xvfb через displayfd
и последовательно проверяет 1000/10000 строк. Desktop Wayland исключён;
Qt software/xcb, GTK cairo/x11, Mesa принудительно software/llvmpipe.
Это настройки runtime, не аппаратное доказательство renderer/энергии.
Xvfb использует Unix sockets, TCP отключён, `-ac` допускает локальных клиентов:
эта fixture не предназначена для hostile multi-user host.
Системные библиотеки и чужой подписанный Xvfb используются только для чтения;
никаких установок, скачиваний runtime или изменений сессии нет.

Проверяются initial frame, query, точный поиск, selection, favorite/filter,
сортировка, scroll, hidden, shown, Quit. Два отрицательных oracle-контроля
на реальном initial report меняют page_hash и event; принятие повреждения
завершает проход ошибкой. Это проверки состояния/ack, не passive frame sensitivity.
Child закрывает свою группу, Xvfb terminate/wait с kill fallback; evidence
содержит reap и отсутствие /proc своего PID. Cold означает process startup,
не холодный filesystem cache; отдельный warm-search пока не реализован.

Первый запуск: Qt 2/2 PASS; GTK 11 reports, затем Quit timeout на обоих размерах;
Slint не дошёл до frame из-за наличия WAYLAND_DISPLAY. Второй запуск исключает
WAYLAND_DISPLAY полностью: Qt и Slint 4/4 PASS; GTK 2/2 Quit timeout,
все шесть child и Xvfb reap/proc-absence подтверждены. Полные сохранённые reports и cleanup — в run2.json.
Локальные stderr и первичный запуск остаются в
`local/evidence/ui-private-preflight/{run1,run2}` данного worktree.

## Минимальное предложение общего протокола — до реализации

Существующий `report(...)` в PROTOCOL.md не содержит монотонного frame counter.
Qt `application.cpp` frameSwapped вызывает QML acknowledgeFrame, но Main.qml
отбрасывает callback при pendingToken=0. GTK main.rs frame_report ставит
одноразовый after-paint и отключает handler после ответа. Slint main.rs
AfterRendering возвращается без emit при frame_pending=false. Отсутствие
stdout во время idle поэтому не доказывает отсутствие кадров.

Предлагается benchmark-only расширение:

1. Независимый u64 rendered_frames увеличивается на **каждый** native callback:
   Qt frameSwapped, GTK постоянный after-paint observer без request_phase/tick,
   Slint AfterRendering до проверки frame_pending. Не добавлять idle timers,
   не вызывать update/queue_draw из observer. GTK after-paint означает toolkit
   paint cycle, не доказанную презентацию; определения сохранять в evidence.
2. Новый Command::Probe{nonce:u64} → Event::Probe и report `probe` с nonce,
   rendered_frames и текущим состоянием, без изменения revision и без redraw.
   Probe обрабатывается GUI thread независимо от hidden/frame_pending.
   Существующие ack и report API сохраняются; отдельный report_probe добавляет
   два поля и не создаёт ложный `frame`. На Quit pending probes отменяются.
3. Перед idle в **том же процессе**: probe A; scroll 0/199 с frame ack;
   probe B, B>A; два probe без UI mutation проверяют, что запрос сам не
   принуждает кадр (возможные settling frames отдельно сохраняются). Контроли
   frozen counter и пропущенный native callback обязаны отвергаться oracle.
   Далее probe на границах visible/hidden интервала, без probe polling.
4. Отдельный benchmark-only GTK lifecycle fix: Control::Quit должен явно
   завершать MainLoop независимо от destroy/ref lifetime. Сейчас main() держит
   сильный window reference и ждёт connect_destroy; фактический timeout
   воспроизведён. Причина lifetime требует проверки перед изменением.

Эти изменения **не реализованы**. Новая Rust-сборка до согласования не нужна.
Оригинальный tools/ui_benchmark.py и его Wayland/session guards не изменены.

## Контракт будущего запуска

Только после устранения Quit/frame blockers, same-process sensitivity и
независимого preflight review root может разрешить отдельный launch:
3 повтора × [1000,10000] × [qt,gtk,slint], последовательно, новый child на ячейку;
startup, одинаковый deterministic query/search/filter/select/sort/scroll,
повтор точного поиска после прогрева, 900 секунд visible + 900 hidden,
Show + Quit/reap. Всего 18 ячеек и 32400 секунд idle (~9 часов), timeout
2100 секунд на ячейку + 10 секунд cleanup. Условия/фон сохранять, не менять.
Frame deltas, CPU ticks, PSS/USS и main-thread context-switch proxy записывать
с исходными samples. GPU/hardware power остаются null. Это private-X11
synthetic process benchmark; physical acceptance остаётся отложенным.

Проверки: 23 существующих unit tests драйвера PASS (два ResourceWarning
из fake-child suite сохранены как ограничение); новый integrity-boundary test PASS;
ruff check/format PASS для новых Python файлов. Независимого review ещё нет.
