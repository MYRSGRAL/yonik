# Независимый P-02 SHORT: preflight и bounded proposal

Статус: **НЕ ВЫПОЛНЕН**, только статический tooling preflight.
База fresh origin/main: a29ea61610ea5de9fd188e65198295d71e9f2278.
Ветка `test/performance-p02-short-independent`; исходная N5c b010e49
остаётся в `docs/n5c-owner-context-projection-fresh`. Старые proofs не переназначены.

## Препятствие и предложение root/W3

В `src/application.cpp` штатный smoke script удерживает QTimer с interval 25 ms
(40 потенциальных timeout/s), а smoke mode безусловно вызывает shutdown через
45000 ms. Этот путь не годится для 900 секунд connected-idle. Это ограничение
тестового tooling, а не обнаруженная регрессия production idle.
На базе отсутствует `tools/p07_hidden_observer.cpp` из reference #177
(6d3b53acc929d2467be1f415d6403691f19f2018). Сам reference проверял другой workload.
Headless DesktopHost не подставлен вместо GUI.

До общей правки предлагается согласовать с root/W3 следующий узкий контракт
его P01 observer или отдельной test-private compile-time точки подключения:

- После actual Main/qrc load передать observer actual window, bridge и actual
  connect/Stop/quit QAction. Только в отдельной test-support сборке; production
  CLI и публичный QML API не расширять, произвольный QML не исполнять.
- Разрешить ограниченную подготовку synthetic source/profile через existing
  bridge dispatch, выбор pinned core и custom HTTPS health target; connect и
  Stop через actual QAction. После Connected и скрытия окна отключить все
  периодические test timers; оставить один deadline и event-driven канал Stop.
- ACK готовности содержит actual visibility/tray availability и current status;
  внешний sampler фиксирует PID/starttime/ns, actual exe/config digest и
  descendants. Отдельный Stop ACK требует reap/rebind, а не только Disconnected.
- Никаких новых production observer API в этой ветке до ответа root. Общие
  application/build/P01-файлы принадлежат W3; P03 не затрагивается.

Допустим также отдельный P02-private interposer по reference #177 после проверки
его привязки к актуальному GUI ELF; это не подтверждено данным preflight.

## Протокол после закрытия gap

Сначала короткий runtime oracle: own same-UID private bus/data, controlled
LocalSocks peer и strict TLS positive → peer negative → restored positive.
Production compiler/source bindings из #169/#173 использовать как методику,
не как результаты нового запуска. Захватить фактический config активного engine
и использовать тот же byte digest/binary для engine-only; единственный engine.
После health warmup никакого тестового proxy traffic.

Для каждого pinned core выполнить минимум три пары по 900 секунд, чередуя
engine-only/full hidden с теми же сетью/fixture/keepalive. Sampler вне product;
GUI/renderer и живой product tray-host входят в group, shared fixture/bus —
отдельная инфраструктура. Сохранять CPU time, PSS/private dirty, FD/threads,
PID identities/descendants, baseline/end и разброс. Wakeups при недоступности
null с точной runtime-причиной; context-switch proxy явно маркировать.
Known process handles и bounded deadlines, cleanup Stop/reap/rebind после пары.

Выполнено 0 повторов, resource variance неизвестен. Energy/physical Plasma,
full-system TUN и остальные оси performance spec не покрыты. Никакие runtime,
Rust build, installation, host settings или helper activation не выполнялись;
созданных transient build-каталогов нет. JSON preflight содержит source hashes
и namespace identity процесса проверки, не измеряемого приложения.
