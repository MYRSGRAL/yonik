#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod bridge;

mod bridge_impl {
    use crate::bridge::ffi;
    use cxx_qt::{CxxQtType, Threading};
    use cxx_qt_lib::QString;
    use std::{
        collections::VecDeque,
        pin::Pin,
        sync::{OnceLock, mpsc},
        thread,
    };
    use ui_bench_model::{Command, Control, Event, Snapshot};

    static ROWS: OnceLock<usize> = OnceLock::new();

    pub fn configure(rows: usize) -> Result<(), usize> {
        ROWS.set(rows)
    }

    pub struct BenchBridgeRust {
        pub snapshot_json: QString,
        pub control_json: QString,
        commands: Option<mpsc::Sender<Command>>,
        pending: VecDeque<Event>,
        waiting: bool,
        snapshot: Option<Snapshot>,
        sequence: u64,
    }

    impl Default for BenchBridgeRust {
        fn default() -> Self {
            Self {
                snapshot_json: QString::from("{}"),
                control_json: QString::from("{}"),
                commands: None,
                pending: VecDeque::new(),
                waiting: false,
                snapshot: None,
                sequence: 0,
            }
        }
    }

    impl ffi::BenchBridge {
        pub fn initialize(mut self: Pin<&mut Self>) {
            if self.commands.is_some() {
                return;
            }
            let Some(&rows) = ROWS.get() else {
                ffi::exit_application();
                return;
            };
            let harness = ui_bench_model::start(rows);
            self.as_mut().rust_mut().commands = Some(harness.commands);
            let qt_thread = self.qt_thread();
            if let Err(error) = thread::Builder::new()
                .name("yonik-bench-bridge".into())
                .spawn(move || {
                    for event in harness.events {
                        if qt_thread
                            .queue(move |mut object| {
                                // Quit отменяет очередь, в том числе при свёрнутом окне без кадров.
                                if matches!(event, Event::Control(Control::Quit)) {
                                    ffi::exit_application();
                                    return;
                                }
                                if let Event::Probe { nonce } = event {
                                    ffi::request_probe(nonce);
                                    return;
                                }
                                if matches!(event, Event::Control(Control::Show)) {
                                    ffi::resume_for_show();
                                }
                                object.as_mut().rust_mut().pending.push_back(event);
                                object.present_next();
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                })
            {
                eprintln!("Не удалось запустить bridge: {error}");
                ffi::exit_application();
            }
        }

        pub fn dispatch(self: Pin<&mut Self>, request: QString) {
            let result = serde_json::from_str::<Command>(&request.to_string());
            match (result, self.commands.as_ref()) {
                (Ok(command), Some(sender)) => {
                    if let Err(error) = sender.send(command) {
                        eprintln!("Команда не доставлена: {error}");
                        ffi::exit_application();
                    }
                }
                _ => {
                    eprintln!("Некорректная команда UI");
                    ffi::exit_application();
                }
            }
        }

        pub fn request_frame(self: Pin<&mut Self>, token: i32) {
            ffi::request_frame(token);
        }

        pub fn finish_probe(
            self: Pin<&mut Self>,
            nonce: QString,
            created: i32,
            live: i32,
            visible: i32,
            scroll: i32,
        ) {
            let result = nonce
                .to_string()
                .parse::<u64>()
                .map_err(std::io::Error::other)
                .and_then(|nonce| {
                    let snapshot = self
                        .snapshot
                        .as_ref()
                        .ok_or_else(|| std::io::Error::other("probe before snapshot"))?;
                    ui_bench_model::report_probe(
                        "qt",
                        nonce,
                        ffi::rendered_frames(),
                        snapshot,
                        created.max(0) as u64,
                        Some(live.max(0) as usize),
                        Some(visible.max(0) as usize),
                        scroll.max(0) as usize,
                    )
                });
            if let Err(error) = result {
                eprintln!("Qt probe: {error}");
                ffi::exit_application();
            }
        }

        pub fn finish(
            mut self: Pin<&mut Self>,
            event: QString,
            created: i32,
            live: i32,
            visible: i32,
            scroll: i32,
        ) {
            if let Some(snapshot) = self.snapshot.as_ref()
                && let Err(error) = ui_bench_model::report(
                    "qt",
                    &event.to_string(),
                    snapshot,
                    created.max(0) as u64,
                    Some(live.max(0) as usize),
                    Some(visible.max(0) as usize),
                    scroll.max(0) as usize,
                )
            {
                eprintln!("Не удалось записать отчёт: {error}");
                ffi::exit_application();
                return;
            }
            self.as_mut().rust_mut().waiting = false;
            self.present_next();
        }

        fn resume_if_show_pending(&self) {
            if self
                .pending
                .iter()
                .any(|event| matches!(event, Event::Control(Control::Show)))
            {
                ffi::resume_for_show();
            }
        }

        fn present_next(mut self: Pin<&mut Self>) {
            if self.waiting {
                return;
            }
            let Some(event) = self.as_mut().rust_mut().pending.pop_front() else {
                return;
            };
            self.as_mut().rust_mut().waiting = true;
            match event {
                Event::Probe { nonce } => {
                    ffi::request_probe(nonce);
                    self.as_mut().rust_mut().waiting = false;
                }
                Event::Snapshot(snapshot) => {
                    let json = match serde_json::to_string(&snapshot) {
                        Ok(json) => json,
                        Err(error) => {
                            eprintln!("Сериализация snapshot: {error}");
                            ffi::exit_application();
                            return;
                        }
                    };
                    self.as_mut().rust_mut().snapshot = Some(snapshot);
                    self.as_mut().set_snapshot_json(QString::from(&json));
                    self.resume_if_show_pending();
                }
                Event::Control(control) => {
                    self.as_mut().rust_mut().sequence += 1;
                    let (action, index) = match control {
                        Control::Scroll(index) => ("scroll", index),
                        Control::Hide => ("hide", 0),
                        Control::Show => ("show", 0),
                        Control::Quit => {
                            ffi::exit_application();
                            return;
                        }
                    };
                    let json = serde_json::json!({"action": action, "index": index, "sequence": self.sequence}).to_string();
                    self.as_mut().set_control_json(QString::from(&json));
                    self.resume_if_show_pending();
                }
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let rows = match arguments.as_slice() {
        [flag, rows] if flag == "--rows" && matches!(rows.as_str(), "1000" | "10000") => {
            rows.parse()?
        }
        _ => return Err("Использование: yonik-bench-qt --rows 1000|10000".into()),
    };
    bridge_impl::configure(rows).map_err(|_| "Конфигурация уже задана")?;
    let status = bridge::ffi::run_application();
    if status != 0 {
        return Err(format!("Qt завершился с кодом {status}").into());
    }
    Ok(())
}
