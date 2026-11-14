use std::cell::RefCell;
use std::collections::VecDeque;
use std::error::Error;
use std::sync::mpsc::Sender;

use slint::{ComponentHandle, ModelRc, RenderingState, VecModel};
use ui_bench_model::{Command, Control, Event, Snapshot};

slint::include_modules!();

#[derive(Default)]
struct UiState {
    queue: VecDeque<Event>,
    snapshot: Option<Snapshot>,
    frame_pending: bool,
    hidden: bool,
    shown_pending: bool,
    frame_event: &'static str,
    created_total: u64,
    rendered_frames: u64,
    scroll_index: usize,
}

thread_local! {
    static STATE: RefCell<UiState> = RefCell::new(UiState::default());
}

fn fail(error: impl std::fmt::Display) {
    eprintln!("Slint benchmark: {error}");
    let _ = slint::quit_event_loop();
}

fn emit(state: &UiState, event: &str) {
    if let Some(snapshot) = &state.snapshot
        && let Err(error) = ui_bench_model::report(
            "slint",
            event,
            snapshot,
            state.created_total,
            None,
            None,
            state.scroll_index,
        )
    {
        fail(error);
    }
}

fn probe(nonce: u64) {
    STATE.with(|state| {
        let state = state.borrow();
        if let Some(snapshot) = &state.snapshot {
            if let Err(error) = ui_bench_model::report_probe(
                "slint",
                nonce,
                state.rendered_frames,
                snapshot,
                state.created_total,
                None,
                None,
                state.scroll_index,
            ) {
                fail(error);
            }
        } else {
            fail("probe before snapshot");
        }
    });
}

fn apply_snapshot(app: &AppWindow, snapshot: &Snapshot) {
    let rows: Vec<_> = snapshot
        .page
        .iter()
        .map(|row| BenchRow {
            id: row.id as i32,
            name: row.name.clone().into(),
            host: row.host.clone().into(),
            country: row.country.clone().into(),
            latency: format!("{} мс", row.latency_ms).into(),
            favorite: row.favorite,
        })
        .collect();
    app.set_rows(ModelRc::new(VecModel::from(rows)));
    app.set_selected_id(snapshot.selected_id.map_or(-1, |id| id as i32));
    app.set_total(snapshot.total as i32);
    app.set_offset(snapshot.offset as i32);
    app.set_search(snapshot.search.clone().into());
    app.set_favorites_only(snapshot.favorites_only);
    app.set_sort_name(snapshot.sort == "name");
}

// Следующее изменение применяется после предыдущего отрисованного кадра.
fn drain(app: &AppWindow) {
    loop {
        let event = STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.frame_pending {
                // Скрытое окно не выдаёт кадров: Show должен разблокировать очередь.
                let control = state.queue.iter().position(|event| {
                    state.hidden && matches!(event, Event::Control(Control::Show))
                });
                control.and_then(|index| state.queue.remove(index))
            } else {
                state.queue.pop_front()
            }
        });
        let Some(event) = event else { return };
        match event {
            Event::Probe { nonce } => probe(nonce),
            Event::Snapshot(snapshot) => {
                apply_snapshot(app, &snapshot);
                app.set_scroll_y(0.0);
                STATE.with(|state| {
                    let mut state = state.borrow_mut();
                    state.snapshot = Some(snapshot);
                    state.scroll_index = 0;
                    state.frame_pending = true;
                    state.frame_event = "frame";
                });
                app.window().request_redraw();
                if STATE.with(|state| state.borrow().hidden) {
                    continue;
                }
                return;
            }
            Event::Control(Control::Scroll(index)) => {
                let index = STATE.with(|state| {
                    let mut state = state.borrow_mut();
                    let count = state.snapshot.as_ref().map_or(0, |s| s.page.len());
                    state.scroll_index = index.min(count.saturating_sub(1));
                    state.frame_pending = true;
                    state.frame_event = "frame";
                    state.scroll_index
                });
                app.invoke_scroll_to_index(index as i32);
                app.window().request_redraw();
                if STATE.with(|state| state.borrow().hidden) {
                    continue;
                }
                return;
            }
            Event::Control(Control::Hide) => {
                if let Err(error) = app.hide() {
                    fail(error);
                }
                STATE.with(|state| {
                    let mut state = state.borrow_mut();
                    state.hidden = true;
                    emit(&state, "hidden");
                });
            }
            Event::Control(Control::Show) => {
                if let Err(error) = app.show() {
                    fail(error);
                }
                STATE.with(|state| {
                    let mut state = state.borrow_mut();
                    state.hidden = false;
                    state.shown_pending = true;
                    if !state.frame_pending {
                        state.frame_pending = true;
                        state.frame_event = "shown";
                        state.shown_pending = false;
                    }
                });
                app.window().request_redraw();
                return;
            }
            Event::Control(Control::Quit) => {
                if let Err(error) = slint::quit_event_loop() {
                    fail(error);
                }
                return;
            }
        }
    }
}

fn send(sender: &Sender<Command>, command: Command) {
    if let Err(error) = sender.send(command) {
        fail(error);
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let rows = match args.as_slice() {
        [] => 1000,
        [flag, value] if flag == "--rows" && (value == "1000" || value == "10000") => {
            value.parse()?
        }
        _ => return Err("Использование: yonik-bench-slint [--rows 1000|10000]".into()),
    };
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .renderer_name("femtovg".into())
        .select()?;
    eprintln!("Slint 1.18.1; backend=winit; renderer=femtovg (OpenGL); Wayland/X11");
    let harness = ui_bench_model::start(rows);
    let app = AppWindow::new()?;
    app.window().on_close_requested(|| {
        if let Err(error) = slint::quit_event_loop() {
            fail(error);
        }
        slint::CloseRequestResponse::HideWindow
    });
    app.on_row_created(|| STATE.with(|state| state.borrow_mut().created_total += 1));
    let sender = harness.commands.clone();
    app.on_query(move |search, favorites_only, sort_name, offset| {
        send(
            &sender,
            Command::Query {
                search: search.to_string(),
                offset: offset.max(0) as usize,
                favorites_only,
                sort: if sort_name { "name" } else { "source" }.into(),
            },
        );
    });
    let sender = harness.commands.clone();
    app.on_select_row(move |id| send(&sender, Command::Select { id: id as u32 }));
    app.on_favorite_row(move |id, value| {
        send(
            &harness.commands,
            Command::Favorite {
                id: id as u32,
                value,
            },
        )
    });
    let weak = app.as_weak();
    app.window().set_rendering_notifier(move |phase, _| {
        if !matches!(phase, RenderingState::AfterRendering) {
            return;
        }
        let completed = STATE.with(|state| {
            let mut state = state.borrow_mut();
            ui_bench_model::count_frame(&mut state.rendered_frames);
            if !state.frame_pending {
                return false;
            }
            state.frame_pending = false;
            emit(&state, state.frame_event);
            if state.shown_pending {
                emit(&state, "shown");
                state.shown_pending = false;
            }
            true
        });
        if completed && let Err(error) = weak.upgrade_in_event_loop(|app| drain(&app)) {
            fail(error);
        }
    })?;
    let weak = app.as_weak();
    std::thread::Builder::new()
        .name("yonik-bench-bridge".into())
        .spawn(move || {
            while let Ok(event) = harness.events.recv() {
                if weak
                    .upgrade_in_event_loop(move |app| {
                        // Quit отменяет очередь даже при свёрнутом системным WM окне,
                        // когда AfterRendering может больше не прийти.
                        if matches!(event, Event::Control(Control::Quit)) {
                            STATE.with(|state| {
                                let mut state = state.borrow_mut();
                                state.queue.clear();
                                state.frame_pending = false;
                                state.shown_pending = false;
                            });
                            if let Err(error) = slint::quit_event_loop() {
                                fail(error);
                            }
                            return;
                        }
                        if let Event::Probe { nonce } = event {
                            probe(nonce);
                            return;
                        }
                        STATE.with(|state| state.borrow_mut().queue.push_back(event));
                        drain(&app);
                    })
                    .is_err()
                {
                    break;
                }
            }
        })?;
    app.show()?;
    slint::run_event_loop_until_quit()?;
    Ok(())
}
