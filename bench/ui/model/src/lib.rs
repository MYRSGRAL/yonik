//! Общий синтетический backend для сравнения UI, без доступа к данным приложения.
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;

const MAX_ROWS: usize = 100_000;
const PAGE_SIZE: usize = 200;
const MAX_LINE: usize = 4096;
const ERROR_JSON: &[u8] = b"{\"event\":\"error\",\"error\":\"invalid_input\"}\n";

#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub id: u32,
    pub name: String,
    pub host: String,
    pub country: String,
    pub latency_ms: u32,
    pub favorite: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub revision: u64,
    pub total: usize,
    pub offset: usize,
    pub search: String,
    pub favorites_only: bool,
    pub sort: String,
    pub selected_id: Option<u32>,
    pub page: Vec<Row>,
    pub page_hash: String,
}

#[derive(Debug)]
pub enum Command {
    Query {
        search: String,
        offset: usize,
        favorites_only: bool,
        sort: String,
    },
    Select {
        id: u32,
    },
    Favorite {
        id: u32,
        value: bool,
    },
    Scroll {
        index: usize,
    },
    Probe {
        nonce: u64,
    },
    Hide,
    Show,
    Quit,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum WireCommand {
    Query {
        search: String,
        offset: usize,
        favorites_only: bool,
        sort: String,
    },
    Select {
        id: u32,
    },
    Favorite {
        id: u32,
        value: bool,
    },
    Scroll {
        index: usize,
    },
    Probe {
        nonce: u64,
    },
    Hide {},
    Show {},
    Quit {},
}

impl<'de> Deserialize<'de> for Command {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match WireCommand::deserialize(deserializer)? {
            WireCommand::Query {
                search,
                offset,
                favorites_only,
                sort,
            } => Self::Query {
                search,
                offset,
                favorites_only,
                sort,
            },
            WireCommand::Select { id } => Self::Select { id },
            WireCommand::Favorite { id, value } => Self::Favorite { id, value },
            WireCommand::Scroll { index } => Self::Scroll { index },
            WireCommand::Probe { nonce } => Self::Probe { nonce },
            WireCommand::Hide {} => Self::Hide,
            WireCommand::Show {} => Self::Show,
            WireCommand::Quit {} => Self::Quit,
        })
    }
}

#[derive(Clone, Debug)]
pub enum Control {
    Scroll(usize),
    Hide,
    Show,
    Quit,
}
#[derive(Clone, Debug)]
pub enum Event {
    Probe { nonce: u64 },
    Snapshot(Snapshot),
    Control(Control),
}

pub struct Harness {
    pub events: mpsc::Receiver<Event>,
    pub commands: mpsc::Sender<Command>,
}

struct Model {
    rows: Vec<Row>,
    folded_names: Vec<String>,
    name_order: Vec<usize>,
    revision: u64,
    offset: usize,
    search: String,
    favorites_only: bool,
    sort: String,
    selected_id: Option<u32>,
}

impl Model {
    fn new(count: usize) -> Self {
        let countries = [
            ("DE", "Германия"),
            ("NL", "Нидерланды"),
            ("SE", "Швеция"),
            ("JP", "Япония"),
        ];
        let rows: Vec<Row> = (0..count)
            .map(|i| {
                let (country, name) = countries[i % countries.len()];
                Row {
                    id: (i + 1) as u32,
                    name: format!("{name} · Сервер {i:05}"),
                    host: format!("server-{i}.example.invalid"),
                    country: country.into(),
                    latency_ms: (10 + (i * 17) % 180) as u32,
                    favorite: false,
                }
            })
            .collect();
        let folded_names = rows.iter().map(|row| row.name.to_lowercase()).collect();
        let mut name_order: Vec<usize> = (0..count).collect();
        name_order.sort_unstable_by(|&a, &b| {
            rows[a]
                .name
                .cmp(&rows[b].name)
                .then(rows[a].id.cmp(&rows[b].id))
        });
        Self {
            rows,
            folded_names,
            name_order,
            revision: 1,
            offset: 0,
            search: String::new(),
            favorites_only: false,
            sort: "source".into(),
            selected_id: None,
        }
    }

    fn snapshot(&self) -> Snapshot {
        let search = self.search.to_lowercase();
        let mut total = 0;
        let mut page = Vec::with_capacity(PAGE_SIZE);
        for position in 0..self.rows.len() {
            let index = if self.sort == "name" {
                self.name_order[position]
            } else {
                position
            };
            let row = &self.rows[index];
            if (self.favorites_only && !row.favorite)
                || (!search.is_empty()
                    && !self.folded_names[index].contains(&search)
                    && !row.host.contains(&search))
            {
                continue;
            }
            if total >= self.offset && page.len() < PAGE_SIZE {
                page.push(row.clone());
            }
            total += 1;
        }
        Snapshot {
            revision: self.revision,
            total,
            offset: self.offset,
            search: self.search.clone(),
            favorites_only: self.favorites_only,
            sort: self.sort.clone(),
            selected_id: self.selected_id,
            page_hash: page_hash(&page),
            page,
        }
    }

    fn apply(&mut self, command: Command) -> Result<Event, ()> {
        match command {
            Command::Query {
                search,
                offset,
                favorites_only,
                sort,
            } => {
                if !matches!(sort.as_str(), "source" | "name") || search.len() > MAX_LINE {
                    return Err(());
                }
                self.search = search;
                self.offset = offset;
                self.favorites_only = favorites_only;
                self.sort = sort;
            }
            Command::Select { id } => {
                self.check_id(id)?;
                self.selected_id = Some(id);
            }
            Command::Favorite { id, value } => {
                self.check_id(id)?;
                self.rows[id as usize - 1].favorite = value;
            }
            Command::Scroll { index } => return Ok(Event::Control(Control::Scroll(index))),
            Command::Probe { nonce } => return Ok(Event::Probe { nonce }),
            Command::Hide => return Ok(Event::Control(Control::Hide)),
            Command::Show => return Ok(Event::Control(Control::Show)),
            Command::Quit => return Ok(Event::Control(Control::Quit)),
        }
        self.revision += 1;
        Ok(Event::Snapshot(self.snapshot()))
    }

    fn check_id(&self, id: u32) -> Result<(), ()> {
        if id > 0 && id as usize <= self.rows.len() {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// FNV-1a64: id LE, name/host/country UTF-8 с NUL, latency LE, favorite u8.
fn page_hash(page: &[Row]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for row in page {
        for byte in row
            .id
            .to_le_bytes()
            .into_iter()
            .chain(row.name.bytes())
            .chain([0])
            .chain(row.host.bytes())
            .chain([0])
            .chain(row.country.bytes())
            .chain([0])
            .chain(row.latency_ms.to_le_bytes())
            .chain([u8::from(row.favorite)])
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("{hash:016x}")
}

/// Создаёт actor и stdin-reader. Заблокированный stdin не задерживает shutdown.
pub fn start(rows: usize) -> Harness {
    launch(rows, true)
}

fn launch(rows: usize, stdin: bool) -> Harness {
    let (commands, input) = mpsc::channel();
    let (output, events) = mpsc::channel();
    let stopped = Arc::new(AtomicBool::new(false));
    let actor_stop = Arc::clone(&stopped);
    let actor_output = output.clone();
    let spawned = thread::Builder::new()
        .name("yonik-bench-data".into())
        .spawn(move || {
            if rows > MAX_ROWS {
                fail(&actor_output);
                actor_stop.store(true, Ordering::Release);
                return;
            }
            let mut model = Model::new(rows);
            if actor_output.send(Event::Snapshot(model.snapshot())).is_ok() {
                for command in input {
                    let event = match model.apply(command) {
                        Ok(event) => event,
                        Err(()) => {
                            fail(&actor_output);
                            break;
                        }
                    };
                    let quit = matches!(event, Event::Control(Control::Quit));
                    if actor_output.send(event).is_err() || quit {
                        break;
                    }
                }
            }
            actor_stop.store(true, Ordering::Release);
        });
    if spawned.is_err() {
        fail(&output);
        stopped.store(true, Ordering::Release);
    }
    if stdin && !stopped.load(Ordering::Acquire) {
        let stdin_commands = commands.clone();
        let input_stop = Arc::clone(&stopped);
        let spawned = thread::Builder::new()
            .name("yonik-bench-input".into())
            .spawn(move || {
                read_commands(io::stdin().lock(), &stdin_commands, &input_stop);
            });
        if spawned.is_err() {
            fail(&output);
            if commands.send(Command::Quit).is_err() {
                stopped.store(true, Ordering::Release);
            }
        }
    }
    Harness { events, commands }
}

fn fail(output: &mpsc::Sender<Event>) {
    if write_error(&mut io::stdout().lock()).is_err() {
        // stdout может быть закрыт потребителем; завершение всё равно обязательно.
    }
    if output.send(Event::Control(Control::Quit)).is_err() {
        // UI уже завершён, другого получателя нет.
    }
}

fn write_error(writer: &mut impl Write) -> io::Result<()> {
    writer.write_all(ERROR_JSON)?;
    writer.flush()
}

/// Чтение по одному байту не позволяет BufRead аллоцировать длинную строку.
fn bounded_line(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::with_capacity(128);
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let byte = buffer[0];
        reader.consume(1);
        if byte == b'\n' {
            return Ok(Some(line));
        }
        if line.len() == MAX_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "command too long",
            ));
        }
        line.push(byte);
    }
}

fn read_commands(mut reader: impl BufRead, commands: &mpsc::Sender<Command>, stopped: &AtomicBool) {
    while !stopped.load(Ordering::Acquire) {
        let command = match bounded_line(&mut reader) {
            Ok(Some(line)) => match serde_json::from_slice(&line) {
                Ok(command) => command,
                Err(_) => {
                    input_failure(commands);
                    return;
                }
            },
            Ok(None) => Command::Quit,
            Err(_) => {
                input_failure(commands);
                return;
            }
        };
        let quit = matches!(command, Command::Quit);
        if commands.send(command).is_err() || quit {
            return;
        }
    }
}

fn input_failure(commands: &mpsc::Sender<Command>) {
    if write_error(&mut io::stdout().lock()).is_err() {
        // Закрытый stdout не должен оставлять actor работающим.
    }
    if commands.send(Command::Quit).is_err() {
        // Actor уже завершён.
    }
}

#[derive(Serialize)]
struct Report<'a> {
    toolkit: &'a str,
    event: &'a str,
    revision: u64,
    total: usize,
    offset: usize,
    model_rows: usize,
    page_hash: &'a str,
    first_id: Option<u32>,
    last_id: Option<u32>,
    selected_id: Option<u32>,
    created_total: u64,
    alive_rows: Option<usize>,
    visible_rows: Option<usize>,
    scroll_index: usize,
}

#[allow(clippy::too_many_arguments)]
pub fn report(
    toolkit: &str,
    event: &str,
    snapshot: &Snapshot,
    created_total: u64,
    alive_rows: Option<usize>,
    visible_rows: Option<usize>,
    scroll_index: usize,
) -> io::Result<()> {
    write_report(
        &mut io::stdout().lock(),
        toolkit,
        event,
        snapshot,
        created_total,
        alive_rows,
        visible_rows,
        scroll_index,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_report(
    writer: &mut impl Write,
    toolkit: &str,
    event: &str,
    snapshot: &Snapshot,
    created_total: u64,
    alive_rows: Option<usize>,
    visible_rows: Option<usize>,
    scroll_index: usize,
) -> io::Result<()> {
    let report = state_report(
        toolkit,
        event,
        snapshot,
        created_total,
        alive_rows,
        visible_rows,
        scroll_index,
    );
    serde_json::to_writer(&mut *writer, &report)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[allow(clippy::too_many_arguments)]
fn state_report<'a>(
    toolkit: &'a str,
    event: &'a str,
    snapshot: &'a Snapshot,
    created_total: u64,
    alive_rows: Option<usize>,
    visible_rows: Option<usize>,
    scroll_index: usize,
) -> Report<'a> {
    Report {
        toolkit,
        event,
        revision: snapshot.revision,
        total: snapshot.total,
        offset: snapshot.offset,
        model_rows: snapshot.page.len(),
        page_hash: &snapshot.page_hash,
        first_id: snapshot.page.first().map(|row| row.id),
        last_id: snapshot.page.last().map(|row| row.id),
        selected_id: snapshot.selected_id,
        created_total,
        alive_rows,
        visible_rows,
        scroll_index,
    }
}

#[derive(Serialize)]
struct ProbeReport<'a> {
    #[serde(flatten)]
    state: Report<'a>,
    nonce: u64,
    rendered_frames: u64,
}

/// Пассивный снимок: u64::MAX — необратимый sentinel переполнения счётчика.
#[allow(clippy::too_many_arguments)]
pub fn report_probe(
    toolkit: &str,
    nonce: u64,
    rendered_frames: u64,
    snapshot: &Snapshot,
    created_total: u64,
    alive_rows: Option<usize>,
    visible_rows: Option<usize>,
    scroll_index: usize,
) -> io::Result<()> {
    if rendered_frames == u64::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame counter overflow",
        ));
    }
    let value = ProbeReport {
        state: state_report(
            toolkit,
            "probe",
            snapshot,
            created_total,
            alive_rows,
            visible_rows,
            scroll_index,
        ),
        nonce,
        rendered_frames,
    };
    let mut writer = io::stdout().lock();
    serde_json::to_writer(&mut writer, &value)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// Насыщение сохраняет sentinel: ни wrap, ни сброс не маскируют overflow.
pub fn count_frame(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

#[cfg(test)]
mod tests {
    use super::{
        Command, Control, Event, MAX_LINE, Model, bounded_line, launch, page_hash, read_commands,
        write_report,
    };
    use std::io::{self, Cursor, Write};
    use std::sync::{atomic::AtomicBool, mpsc};
    use std::time::Duration;

    fn query(
        model: &mut Model,
        search: &str,
        offset: usize,
        favorites_only: bool,
        sort: &str,
    ) -> super::Snapshot {
        match model
            .apply(Command::Query {
                search: search.into(),
                offset,
                favorites_only,
                sort: sort.into(),
            })
            .expect("валидный запрос")
        {
            Event::Snapshot(snapshot) => snapshot,
            Event::Probe { .. } | Event::Control(_) => panic!("запрос должен возвращать snapshot"),
        }
    }

    #[test]
    fn probe_shape_preserves_legacy_state_and_u64_precision() {
        let snapshot = Model::new(1000).snapshot();
        let mut probe = serde_json::to_value(super::ProbeReport {
            state: super::state_report("test", "probe", &snapshot, 9, None, None, 7),
            nonce: u64::MAX,
            rendered_frames: u64::MAX - 1,
        })
        .expect("probe");
        assert_eq!(probe.as_object().expect("object").len(), 16);
        assert_eq!(probe["nonce"].as_u64(), Some(u64::MAX));
        let fields = probe.as_object_mut().expect("object");
        fields.remove("nonce");
        fields.remove("rendered_frames");
        let mut legacy = Vec::new();
        write_report(&mut legacy, "test", "probe", &snapshot, 9, None, None, 7).expect("legacy");
        assert_eq!(
            probe,
            serde_json::from_slice::<serde_json::Value>(&legacy).expect("json")
        );
    }

    #[test]
    fn actor_probe_then_quit_cancels_following_commands() {
        let harness = launch(1000, false);
        assert!(matches!(
            harness.events.recv_timeout(Duration::from_secs(2)),
            Ok(Event::Snapshot(_))
        ));
        harness
            .commands
            .send(Command::Probe { nonce: 7 })
            .expect("actor");
        harness.commands.send(Command::Quit).expect("actor");
        let _ = harness.commands.send(Command::Probe { nonce: 8 });
        assert!(matches!(
            harness.events.recv_timeout(Duration::from_secs(2)),
            Ok(Event::Probe { nonce: 7 })
        ));
        assert!(matches!(
            harness.events.recv_timeout(Duration::from_secs(2)),
            Ok(Event::Control(Control::Quit))
        ));
        assert!(matches!(
            harness.events.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }

    #[test]
    fn counter_overflow_is_permanent_and_invalid() {
        let mut counter = u64::MAX - 1;
        super::count_frame(&mut counter);
        super::count_frame(&mut counter);
        assert_eq!(counter, u64::MAX);
        assert!(
            super::report_probe(
                "test",
                1,
                counter,
                &Model::new(1).snapshot(),
                0,
                None,
                None,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn probe_preserves_model_and_validates_nonce() {
        let mut model = Model::new(1000);
        let before = serde_json::to_value(model.snapshot()).expect("snapshot");
        let command: Command =
            serde_json::from_str(r#"{"op":"probe","nonce":18446744073709551615}"#)
                .expect("u64 nonce");
        assert!(matches!(
            model.apply(command),
            Ok(Event::Probe { nonce: u64::MAX })
        ));
        assert_eq!(
            before,
            serde_json::to_value(model.snapshot()).expect("snapshot")
        );
        for wire in [
            r#"{"op":"probe","nonce":-1}"#,
            r#"{"op":"probe","nonce":true}"#,
            r#"{"op":"probe","nonce":1.5}"#,
            r#"{"op":"probe","nonce":18446744073709551616}"#,
            r#"{"op":"probe"}"#,
            r#"{"op":"probe","nonce":1,"extra":0}"#,
        ] {
            assert!(serde_json::from_str::<Command>(wire).is_err(), "{wire}");
        }
    }

    #[test]
    fn deterministic_dataset_and_page_boundaries() {
        let mut model = Model::new(1000);
        let snapshot = model.snapshot();
        assert_eq!(snapshot.revision, 1);
        assert_eq!(snapshot.total, 1000);
        assert_eq!(snapshot.page.len(), 200);
        let row = &snapshot.page[0];
        assert_eq!(
            (
                row.id,
                row.name.as_str(),
                row.host.as_str(),
                row.country.as_str(),
                row.latency_ms,
                row.favorite
            ),
            (
                1,
                "Германия · Сервер 00000",
                "server-0.example.invalid",
                "DE",
                10,
                false
            )
        );
        assert_eq!(snapshot.page[199].id, 200);
        assert_eq!(snapshot.page_hash, Model::new(1000).snapshot().page_hash);
        let tail = query(&mut model, "", 999, false, "source");
        assert_eq!(tail.page.len(), 1);
        assert_eq!(tail.page[0].id, 1000);
        let empty = query(&mut model, "", usize::MAX, false, "source");
        assert!(empty.page.is_empty());
        assert_eq!(empty.total, 1000);
        assert_eq!(empty.page_hash, "cbf29ce484222325");
    }

    #[test]
    fn dataset_limit_and_invalid_input_end_actor() {
        let maximum = Model::new(super::MAX_ROWS).snapshot();
        assert_eq!(maximum.total, 100_000);
        assert_eq!(maximum.page.len(), 200);
        assert!(Model::new(0).snapshot().page.is_empty());
        let harness = launch(super::MAX_ROWS + 1, false);
        assert!(matches!(
            harness.events.recv_timeout(Duration::from_secs(2)),
            Ok(Event::Control(Control::Quit))
        ));
        assert!(matches!(
            harness.events.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
        let harness = launch(2, false);
        assert!(matches!(
            harness.events.recv_timeout(Duration::from_secs(2)),
            Ok(Event::Snapshot(_))
        ));
        harness
            .commands
            .send(Command::Select { id: 3 })
            .expect("actor");
        assert!(matches!(
            harness.events.recv_timeout(Duration::from_secs(2)),
            Ok(Event::Control(Control::Quit))
        ));
        assert!(matches!(
            harness.events.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }

    #[test]
    fn search_casefold_and_sort_preserve_ids() {
        let mut model = Model::new(1000);
        let russian = query(&mut model, "гЕРМАНИЯ", 0, false, "source");
        assert_eq!(russian.total, 250);
        assert!(russian.page.iter().all(|row| row.country == "DE"));
        let host = query(&mut model, "SERVER-17.EXAMPLE.INVALID", 0, false, "source");
        assert_eq!(host.total, 1);
        assert_eq!(host.page[0].id, 18);
        model.apply(Command::Select { id: 18 }).expect("выбор");
        let sorted = query(&mut model, "", 0, false, "name");
        assert_eq!(sorted.selected_id, Some(18));
        assert!(
            sorted
                .page
                .windows(2)
                .all(|pair| pair[0].name <= pair[1].name)
        );
        assert_eq!(sorted.page[1].id, 5);
    }

    #[test]
    fn favorite_filter_hash_and_selection_stay_consistent() {
        let mut model = Model::new(20);
        let before = model.snapshot().page_hash;
        model
            .apply(Command::Favorite { id: 7, value: true })
            .expect("избранное");
        assert_ne!(before, model.snapshot().page_hash);
        model.apply(Command::Select { id: 7 }).expect("выбор");
        let favorites = query(&mut model, "", 0, true, "name");
        assert_eq!(favorites.total, 1);
        assert_eq!(favorites.page[0].id, 7);
        assert!(favorites.page[0].favorite);
        model
            .apply(Command::Favorite {
                id: 7,
                value: false,
            })
            .expect("удаление избранного");
        assert!(model.snapshot().page.is_empty());
        assert_eq!(model.snapshot().selected_id, Some(7));
        assert!(model.apply(Command::Select { id: 0 }).is_err());
        assert!(
            model
                .apply(Command::Favorite {
                    id: 21,
                    value: true
                })
                .is_err()
        );
        assert!(
            model
                .apply(Command::Query {
                    search: String::new(),
                    offset: 0,
                    favorites_only: false,
                    sort: "invalid".into()
                })
                .is_err()
        );
    }

    #[test]
    fn hash_known_row_and_mutation() {
        let row = Model::new(1).snapshot().page.remove(0);
        assert_eq!(page_hash(std::slice::from_ref(&row)), "f84088cf6817a1b8");
        let mut changed = row.clone();
        changed.latency_ms += 1;
        assert_ne!(page_hash(&[row]), page_hash(&[changed]));
    }

    #[test]
    fn input_is_bounded_and_rejects_invalid_commands() {
        assert_eq!(
            bounded_line(&mut Cursor::new(vec![b'x'; MAX_LINE]))
                .expect("ровно лимит")
                .expect("строка")
                .len(),
            MAX_LINE
        );
        assert!(bounded_line(&mut Cursor::new(vec![b'x'; MAX_LINE + 1])).is_err());
        for input in [
            b"{}\n".as_slice(),
            b"{\"op\":\"Select\",\"id\":1}\n",
            b"{\"op\":\"hide\",\"unknown\":1}\n",
            b"\xff\n",
        ] {
            let (tx, rx) = mpsc::channel();
            read_commands(Cursor::new(input), &tx, &AtomicBool::new(false));
            assert!(matches!(rx.try_recv(), Ok(Command::Quit)));
            assert!(rx.try_recv().is_err());
        }
        let (tx, rx) = mpsc::channel();
        read_commands(
            Cursor::new(b"{\"op\":\"hide\"}\n"),
            &tx,
            &AtomicBool::new(false),
        );
        assert!(matches!(rx.try_recv(), Ok(Command::Hide)));
        assert!(matches!(rx.try_recv(), Ok(Command::Quit)));
    }

    #[test]
    fn quit_cancels_actor_without_stdin_join() {
        let harness = launch(1000, false);
        assert!(
            matches!(harness.events.recv_timeout(Duration::from_secs(2)), Ok(Event::Snapshot(snapshot)) if snapshot.revision == 1)
        );
        harness.commands.send(Command::Quit).expect("actor запущен");
        assert!(matches!(
            harness.events.recv_timeout(Duration::from_secs(2)),
            Ok(Event::Control(Control::Quit))
        ));
        assert!(matches!(
            harness.events.recv_timeout(Duration::from_secs(2)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }

    #[test]
    fn report_contains_core_fields_and_propagates_io_errors() {
        let snapshot = Model::new(3).snapshot();
        let mut output = Vec::new();
        write_report(&mut output, "test", "frame", &snapshot, 9, None, Some(2), 1).expect("report");
        assert_eq!(output.last(), Some(&b'\n'));
        let value: serde_json::Value = serde_json::from_slice(&output).expect("json");
        assert_eq!(value.as_object().expect("object").len(), 14);
        assert_eq!(value["toolkit"], "test");
        assert_eq!(value["revision"], 1);
        assert_eq!(value["model_rows"], 3);
        assert_eq!(value["first_id"], 1);
        assert_eq!(value["last_id"], 3);
        assert_eq!(value["page_hash"], snapshot.page_hash);
        assert_eq!(value["created_total"], 9);
        assert!(value["alive_rows"].is_null());
        assert_eq!(value["visible_rows"], 2);
        assert_eq!(value["scroll_index"], 1);
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        assert!(write_report(&mut Broken, "test", "frame", &snapshot, 0, None, None, 0).is_err());
    }
}
