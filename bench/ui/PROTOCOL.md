# Общий benchmark-протокол

Standalone workspace, без изменения production MSRV/зависимостей. Rust 1.97.0,
одинаковый release profile, Noto Sans 14 px, окно 800×640, строка 66 px,
ListView/виртуализация, страницы 200. Только синтетика, без профилей пользователя,
Secret Service, SQLite, proxy core или сетевых запросов. Это сравнение оболочек
на общем synthetic backend, не измерение полного приложения и не G-POWER.

Общая библиотека `ui-bench-model`:

- `pub fn start(rows: usize) -> Harness`, Harness содержит
  `pub events: std::sync::mpsc::Receiver<Event>` и
  `pub commands: std::sync::mpsc::Sender<Command>`.
- Отдельный actor `yonik-bench-data`, stdin reader `yonik-bench-input`.
  Shell создаёт один `yonik-bench-bridge`, блокирующий recv и передающий события
  в GUI event loop без polling. Actor даёт начальный Snapshot revision=1.
- `Event::{Snapshot(Snapshot),Control(Control)}`; Control::{Scroll(usize),Hide,Show,Quit}.
- `Snapshot` Clone/Serialize: revision:u64,total:usize,offset:usize,search:String,
  favorites_only:bool,sort:String,selected_id:Option<u32>,page:Vec<Row>,page_hash:String.
- `Row` Clone/Serialize: id:u32,name:String,host:String,country:String,latency_ms:u32,favorite:bool (изначально false).
  id=i+1, host=`server-{i}.example.invalid`, страны DE/NL/SE/JP по i%4,
  name=`{страна по-русски} · Сервер {i:05}`, latency=10+(i*17)%180.
- page_hash: FNV-1a 64, id LE, name+NUL, host+NUL, country+NUL, latency_ms LE,
  favorite как один байт; 16 шестнадцатеричных символов в нижнем регистре.
- Command Deserialize (tag op):
  Query{search:String,offset:usize,favorites_only:bool,sort:String},
  Select{id:u32},Favorite{id:u32,value:bool},Scroll{index:usize},Hide,Show,Quit.
  Синонимы не нужны. Query sort=source/name, limit=200; stdin <=4096 bytes/line,
  rows <=100000; неверный ввод завершает harness явным error report.
- `pub fn report(toolkit:&str,event:&str,snapshot:&Snapshot,created_total:u64,
  alive_rows:Option<usize>,visible_rows:Option<usize>,scroll_index:usize)
  -> std::io::Result<()>` пишет одну JSONL строку stdout и flush.
  Поля report: toolkit,event,revision,total,offset,model_rows,page_hash,first_id,
  last_id,selected_id,created_total,alive_rows,visible_rows,scroll_index.

Shell принимает `--rows 1000|10000`, одни и те же команды JSONL через stdin.
Все изменения виджетов — только UI thread. `frame` report после frame/layout,
не сразу после установки модели; один report на команду, никаких idle timers.
Hide/Show дают hidden/shown report, scroll — frame с индексом. Quit/EOF немедленно
отменяет pending-команды и завершает loop независимо от доступности кадра
(включая системное сворачивание). Подтверждения отменённых команд не обещаются;
драйвер ждёт ack каждого шага перед следующим и только затем посылает Quit.
Счётчики созданных/живых/пересекающих viewport строк различать, недоступный счётчик
передавать null, а не вычислять «живые» по размеру модели. Полная проверка реального
рендера и автоматизации framework-specific; frame report не заменяет screenshot QA.

Это benchmark-only Query API: действующий DesktopHost не предоставляет sort=name.
Сортировка/поиск/выбор исполняются общим actor, shell не дублирует логику.

Геометрия сравнения: внутренний отступ 20 px, промежуток 12 px, header 38 px,
поиск + кнопка поиска + sort 40 px, избранное + выбранный ID 40 px, список
320 px, footer 40 px. Строка: country 30 px, name/host раздельно 14 px, latency,
кнопка избранного; внутренние отступы 12 px, gap 14 px. Различия нативных
виджетов фиксируются как ограничение; состав и viewport должны совпадать.

## Пассивный native counter (benchmark-only)

`Command::Probe{nonce:u64}` / `Event::Probe{nonce:u64}` не меняет Model,
revision или snapshot, не требует кадра и обрабатывается GUI thread до очереди
ожидающих frame событий, включая hidden. Quit завершает actor/GUI loop и
отменяет оставшуюся работу. Невалидный nonce (тип, диапазон, неизвестные поля)
отклоняется тем же bounded input parser, что остальные команды.

`report_probe(toolkit,nonce,rendered_frames,snapshot,created_total,alive_rows,
visible_rows,scroll_index)` пишет legacy state report с event=`probe` плюс
ровно два поля `nonce` и `rendered_frames`. Legacy `report(...)` и его 14 полей
не меняются. Счётчик u64 монотонный; насыщение в u64::MAX — необратимый invalid
sentinel, report_probe возвращает ошибку вместо валидного report.

Определения различаются: Qt считает каждый QQuickWindow::frameSwapped; Slint —
каждый RenderingState::AfterRendering до проверки pending ack; GTK — каждый
GdkFrameClock::after-paint постоянным observer. GTK paint cycle не равен
presentation. Observer не ставит tick/timer, не request_phase/update/queue_draw.
GTK одноразовый frame_report по-прежнему запрашивает кадр для legacy ack;
пассивный observer этого не делает. Probe сам не изменяет UI/модель и не
инициирует redraw. Native callback не доказывает физическую видимость пикселей.
