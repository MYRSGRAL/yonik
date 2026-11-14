use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    error::Error,
    rc::Rc,
    sync::mpsc::Sender,
};

use gtk4::{self as gtk, gio, glib, prelude::*};
use ui_bench_model::{Command, Control, Event, Row, Snapshot};

enum UiMessage {
    Backend(Event),
    FrameDone,
}

#[derive(Default)]
struct RowStats {
    created: Cell<u64>,
    widgets: RefCell<Vec<glib::WeakRef<gtk::Widget>>>,
}

impl RowStats {
    fn counts(&self, viewport: &gtk::ScrolledWindow) -> (usize, usize) {
        let mut alive = 0;
        let mut visible = 0;
        self.widgets.borrow_mut().retain(|weak| {
            let Some(widget) = weak.upgrade() else {
                return false;
            };
            alive += 1;
            if widget.is_mapped()
                && widget.compute_bounds(viewport).is_some_and(|bounds| {
                    bounds.y() < viewport.height() as f32
                        && bounds.y() + bounds.height() > 0.0
                        && bounds.x() < viewport.width() as f32
                        && bounds.x() + bounds.width() > 0.0
                })
            {
                visible += 1;
            }
            true
        });
        (alive, visible)
    }
}

fn send(commands: &Sender<Command>, command: Command) {
    if let Err(error) = commands.send(command) {
        eprintln!("GTK: отправка команды: {error}");
    }
}

fn emit(
    event: &str,
    snapshot: &Snapshot,
    stats: &RowStats,
    viewport: &gtk::ScrolledWindow,
    scroll_index: usize,
) {
    let (alive, visible) = stats.counts(viewport);
    if let Err(error) = ui_bench_model::report(
        "gtk",
        event,
        snapshot,
        stats.created.get(),
        Some(alive),
        Some(visible),
        scroll_index,
    ) {
        eprintln!("GTK: запись отчёта: {error}");
    }
}

fn frame_report(
    list: &gtk::ListView,
    viewport: &gtk::ScrolledWindow,
    snapshot: Snapshot,
    stats: Rc<RowStats>,
    scroll_index: usize,
    completion: async_channel::Sender<UiMessage>,
    cancelled: Rc<Cell<bool>>,
) {
    let viewport = viewport.clone();
    // Tick запускает кадр; after-paint подтверждает завершение layout и рисования.
    list.add_tick_callback(move |_, clock| {
        if cancelled.get() {
            return glib::ControlFlow::Break;
        }
        let handler = Rc::new(RefCell::new(None));
        let handler_for_signal = handler.clone();
        let viewport = viewport.clone();
        let snapshot = snapshot.clone();
        let stats = stats.clone();
        let completion = completion.clone();
        let cancelled = cancelled.clone();
        *handler.borrow_mut() = Some(clock.connect_after_paint(move |clock| {
            if let Some(handler) = handler_for_signal.borrow_mut().take() {
                clock.disconnect(handler);
            }
            if cancelled.get() {
                return;
            }
            emit("frame", &snapshot, &stats, &viewport, scroll_index);
            if let Err(error) = completion.try_send(UiMessage::FrameDone) {
                eprintln!("GTK: подтверждение кадра: {error}");
            }
        }));
        clock.request_phase(gtk::gdk::FrameClockPhase::AFTER_PAINT);
        glib::ControlFlow::Break
    });
    list.queue_draw();
}

fn query(
    commands: &Sender<Command>,
    state: &RefCell<Option<Snapshot>>,
    offset: usize,
    search: Option<String>,
    favorites: Option<bool>,
    sort: Option<String>,
) {
    let snapshot = state.borrow();
    let Some(snapshot) = snapshot.as_ref() else {
        return;
    };
    send(
        commands,
        Command::Query {
            search: search.unwrap_or_else(|| snapshot.search.clone()),
            offset,
            favorites_only: favorites.unwrap_or(snapshot.favorites_only),
            sort: sort.unwrap_or_else(|| snapshot.sort.clone()),
        },
    );
}

fn build(
    harness: ui_bench_model::Harness,
    main_loop: glib::MainLoop,
) -> Result<gtk::Window, Box<dyn Error>> {
    let ui_state: Rc<RefCell<Option<Snapshot>>> = Rc::default();
    let stats = Rc::new(RowStats::default());
    let scroll_index = Rc::new(Cell::new(0usize));
    let applying = Rc::new(Cell::new(false));
    let cancelled = Rc::new(Cell::new(false));
    let window = gtk::Window::builder()
        .title("Yonik · GTK4 benchmark")
        .default_width(800)
        .default_height(640)
        .build();
    let root = gtk::Box::new(gtk::Orientation::Vertical, 12);
    root.set_margin_top(20);
    root.set_margin_bottom(20);
    root.set_margin_start(20);
    root.set_margin_end(20);
    let header = gtk::Box::new(gtk::Orientation::Horizontal, 16);
    header.set_height_request(38);
    let title = gtk::Label::new(Some("YONIK"));
    title.add_css_class("title");
    header.append(&title);
    header.append(&gtk::Label::new(Some("Серверы")));
    let toolkit_summary = gtk::Label::new(Some("GTK4 · 0"));
    toolkit_summary.set_hexpand(true);
    toolkit_summary.set_xalign(1.0);
    toolkit_summary.add_css_class("secondary");
    header.append(&toolkit_summary);
    root.append(&header);
    let controls = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    controls.set_height_request(40);
    let search = gtk::Entry::builder()
        .placeholder_text("Поиск сервера")
        .hexpand(true)
        .build();
    let find = gtk::Button::with_label("Найти");
    let sort = gtk::DropDown::from_strings(&["По порядку", "По имени"]);
    controls.append(&search);
    controls.append(&find);
    controls.append(&sort);
    root.append(&controls);
    let filters = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    filters.set_height_request(40);
    let favorites = gtk::CheckButton::with_label("Избранные");
    let selected = gtk::Label::new(Some("Выбран: —"));
    selected.set_hexpand(true);
    selected.set_xalign(1.0);
    selected.add_css_class("secondary");
    filters.append(&favorites);
    filters.append(&selected);
    root.append(&filters);
    let store = gio::ListStore::new::<glib::BoxedAnyObject>();
    let selection = gtk::SingleSelection::new(Some(store.clone()));
    selection.set_autoselect(false);
    selection.set_can_unselect(true);
    let factory = gtk::SignalListItemFactory::new();
    let setup_stats = stats.clone();
    let favorite_commands = harness.commands.clone();
    factory.connect_setup(move |_, item| {
        let Some(item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 14);
        row.set_height_request(66);
        row.add_css_class("server-row");
        let country = gtk::Label::new(None);
        country.set_width_request(30);
        country.set_xalign(0.0);
        country.add_css_class("accent");
        row.append(&country);
        let details = gtk::Box::new(gtk::Orientation::Vertical, 3);
        details.set_hexpand(true);
        details.set_valign(gtk::Align::Center);
        let name = gtk::Label::new(None);
        name.set_xalign(0.0);
        name.set_ellipsize(gtk::pango::EllipsizeMode::End);
        let host = gtk::Label::new(None);
        host.set_xalign(0.0);
        host.set_ellipsize(gtk::pango::EllipsizeMode::End);
        host.add_css_class("host");
        details.append(&name);
        details.append(&host);
        row.append(&details);
        let latency = gtk::Label::new(None);
        latency.add_css_class("accent");
        row.append(&latency);
        let favorite = gtk::Button::with_label("☆");
        favorite.set_valign(gtk::Align::Center);
        favorite.set_width_request(44);
        favorite.add_css_class("flat");
        let weak_item = item.downgrade();
        let commands = favorite_commands.clone();
        // Один handler читает текущий item после recycling, а не старый Row.
        favorite.connect_clicked(move |_| {
            if let Some(item) = weak_item.upgrade()
                && let Some(object) = item.item().and_downcast::<glib::BoxedAnyObject>()
            {
                let row = object.borrow::<Row>();
                send(
                    &commands,
                    Command::Favorite {
                        id: row.id,
                        value: !row.favorite,
                    },
                );
            }
        });
        row.append(&favorite);
        setup_stats.created.set(setup_stats.created.get() + 1);
        setup_stats
            .widgets
            .borrow_mut()
            .push(row.clone().upcast::<gtk::Widget>().downgrade());
        item.set_child(Some(&row));
    });
    factory.connect_bind(|_, item| {
        let Some(item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        let Some(object) = item.item().and_downcast::<glib::BoxedAnyObject>() else {
            return;
        };
        let row = object.borrow::<Row>();
        let country = item.child().and_then(|child| child.first_child());
        let details = country.as_ref().and_then(|child| child.next_sibling());
        let latency = details.as_ref().and_then(|child| child.next_sibling());
        let favorite = latency.as_ref().and_then(|child| child.next_sibling());
        if let Some(country) = country.and_downcast::<gtk::Label>() {
            country.set_text(&row.country);
        }
        if let Some(details) = details {
            let name = details.first_child();
            let host = name.as_ref().and_then(|child| child.next_sibling());
            if let Some(name) = name.and_downcast::<gtk::Label>() {
                name.set_text(&row.name);
            }
            if let Some(host) = host.and_downcast::<gtk::Label>() {
                host.set_text(&row.host);
            }
        }
        if let Some(latency) = latency.and_downcast::<gtk::Label>() {
            latency.set_text(&format!("{} мс", row.latency_ms));
        }
        if let Some(favorite) = favorite.and_downcast::<gtk::Button>() {
            favorite.set_label(if row.favorite { "★" } else { "☆" });
        }
    });
    factory.connect_teardown(|_, item| {
        if let Some(item) = item.downcast_ref::<gtk::ListItem>() {
            item.set_child(gtk::Widget::NONE);
        }
    });
    let list = gtk::ListView::new(Some(selection.clone()), Some(factory));
    let viewport = gtk::ScrolledWindow::builder()
        .hexpand(true)
        .vexpand(false)
        .height_request(320)
        .min_content_height(320)
        .max_content_height(320)
        .propagate_natural_height(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&list)
        .build();
    root.append(&viewport);
    let navigation = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    navigation.set_height_request(40);
    let previous = gtk::Button::with_label("Назад");
    let next = gtk::Button::with_label("Далее");
    let summary = gtk::Label::new(Some("Загрузка…"));
    summary.set_hexpand(true);
    summary.add_css_class("secondary");
    navigation.append(&previous);
    navigation.append(&summary);
    navigation.append(&next);
    root.append(&navigation);
    window.set_child(Some(&root));

    let commands = harness.commands;
    let tx = commands.clone();
    let state = ui_state.clone();
    let guard = applying.clone();
    search.connect_activate(move |entry| {
        if !guard.get() {
            query(&tx, &state, 0, Some(entry.text().to_string()), None, None);
        }
    });
    let tx = commands.clone();
    let state = ui_state.clone();
    let search_input = search.clone();
    find.connect_clicked(move |_| {
        query(
            &tx,
            &state,
            0,
            Some(search_input.text().to_string()),
            None,
            None,
        );
    });
    let tx = commands.clone();
    let state = ui_state.clone();
    let guard = applying.clone();
    let search_for_favorites = search.clone();
    favorites.connect_toggled(move |button| {
        if !guard.get() {
            query(
                &tx,
                &state,
                0,
                Some(search_for_favorites.text().to_string()),
                Some(button.is_active()),
                None,
            );
        }
    });
    let tx = commands.clone();
    let state = ui_state.clone();
    let guard = applying.clone();
    let search_for_sort = search.clone();
    sort.connect_selected_notify(move |sort| {
        if !guard.get() {
            query(
                &tx,
                &state,
                0,
                Some(search_for_sort.text().to_string()),
                None,
                Some(
                    if sort.selected() == 1 {
                        "name"
                    } else {
                        "source"
                    }
                    .into(),
                ),
            );
        }
    });
    let tx = commands.clone();
    let state = ui_state.clone();
    let search_for_previous = search.clone();
    previous.connect_clicked(move |_| {
        let offset = state
            .borrow()
            .as_ref()
            .map_or(0, |state| state.offset.saturating_sub(200));
        query(
            &tx,
            &state,
            offset,
            Some(search_for_previous.text().to_string()),
            None,
            None,
        );
    });
    let tx = commands.clone();
    let state = ui_state.clone();
    let search_for_next = search.clone();
    next.connect_clicked(move |_| {
        let offset = state
            .borrow()
            .as_ref()
            .map_or(0, |state| state.offset.saturating_add(200));
        query(
            &tx,
            &state,
            offset,
            Some(search_for_next.text().to_string()),
            None,
            None,
        );
    });
    let tx = commands.clone();
    let guard = applying.clone();
    selection.connect_selected_notify(move |selection| {
        if guard.get() {
            return;
        }
        if let Some(object) = selection
            .selected_item()
            .and_downcast::<glib::BoxedAnyObject>()
        {
            send(
                &tx,
                Command::Select {
                    id: object.borrow::<Row>().id,
                },
            );
        }
    });
    let tx = commands;
    let cancel_on_close = cancelled.clone();
    window.connect_close_request(move |_| {
        cancel_on_close.set(true);
        send(&tx, Command::Quit);
        glib::Propagation::Proceed
    });

    let (ui_tx, ui_rx) = async_channel::unbounded();
    let completion = ui_tx.clone();
    std::thread::Builder::new()
        .name("yonik-bench-bridge".into())
        .spawn(move || {
            while let Ok(event) = harness.events.recv() {
                if ui_tx.send_blocking(UiMessage::Backend(event)).is_err() {
                    break;
                }
            }
        })?;
    let frames = Rc::new(Cell::new(0_u64));
    let observed = frames.clone();
    window.connect_realize(move |window| {
        if let Some(clock) = window.frame_clock() {
            let frames = observed.clone();
            clock.connect_after_paint(move |_| {
                let mut count = frames.get();
                ui_bench_model::count_frame(&mut count);
                frames.set(count);
            });
        }
    });
    let weak_window = window.downgrade();
    glib::MainContext::default().spawn_local(async move {
        let mut backlog = VecDeque::new();
        let mut awaiting_frame = false;
        while let Ok(message) = ui_rx.recv().await {
            let Some(window) = weak_window.upgrade() else {
                break;
            };
            match message {
                UiMessage::FrameDone => awaiting_frame = false,
                UiMessage::Backend(Event::Probe { nonce }) => {
                    if !cancelled.get() {
                        let state = ui_state.borrow();
                        let snapshot = state.as_ref().ok_or("GTK probe before snapshot");
                        let result = snapshot
                            .map_err(std::io::Error::other)
                            .and_then(|snapshot| {
                                let (alive, visible) = stats.counts(&viewport);
                                ui_bench_model::report_probe(
                                    "gtk",
                                    nonce,
                                    frames.get(),
                                    snapshot,
                                    stats.created.get(),
                                    Some(alive),
                                    Some(visible),
                                    scroll_index.get(),
                                )
                            });
                        if let Err(error) = result {
                            eprintln!("GTK probe: {error}");
                            cancelled.set(true);
                            main_loop.quit();
                            break;
                        }
                    }
                }
                UiMessage::Backend(Event::Control(Control::Quit)) => {
                    cancelled.set(true);
                    backlog.clear();
                    main_loop.quit();
                    window.destroy();
                    break;
                }
                UiMessage::Backend(Event::Control(Control::Show)) if !window.is_visible() => {
                    window.present();
                    if let Some(snapshot) = ui_state.borrow().as_ref() {
                        emit("shown", snapshot, &stats, &viewport, scroll_index.get());
                    }
                }
                UiMessage::Backend(event) => backlog.push_back(event),
            }
            while !awaiting_frame {
                // Скрытая поверхность не рисует кадры: Show разблокирует очередь.
                if !window.is_visible()
                    && matches!(
                        backlog.front(),
                        Some(Event::Snapshot(_) | Event::Control(Control::Scroll(_)))
                    )
                {
                    break;
                }
                let Some(event) = backlog.pop_front() else {
                    break;
                };
                match event {
                    Event::Probe { .. } => {
                        eprintln!("GTK: probe ошибочно попал в backlog");
                        main_loop.quit();
                        return;
                    }
                    Event::Snapshot(snapshot) => {
                        applying.set(true);
                        let objects: Vec<_> = snapshot
                            .page
                            .iter()
                            .cloned()
                            .map(glib::BoxedAnyObject::new)
                            .collect();
                        store.splice(0, store.n_items(), &objects);
                        selection.set_selected(
                            snapshot
                                .selected_id
                                .and_then(|id| snapshot.page.iter().position(|row| row.id == id))
                                .map_or(gtk::INVALID_LIST_POSITION, |index| index as u32),
                        );
                        search.set_text(&snapshot.search);
                        favorites.set_active(snapshot.favorites_only);
                        sort.set_selected(u32::from(snapshot.sort == "name"));
                        summary.set_text(&format!("{} / {}", snapshot.offset, snapshot.total));
                        toolkit_summary.set_text(&format!("GTK4 · {}", snapshot.total));
                        selected.set_text(&format!(
                            "Выбран: {}",
                            snapshot
                                .selected_id
                                .map_or_else(|| "—".into(), |id| id.to_string())
                        ));
                        previous.set_sensitive(snapshot.offset > 0);
                        next.set_sensitive(snapshot.offset + snapshot.page.len() < snapshot.total);
                        scroll_index.set(0);
                        viewport.vadjustment().set_value(0.0);
                        *ui_state.borrow_mut() = Some(snapshot.clone());
                        applying.set(false);
                        awaiting_frame = true;
                        frame_report(
                            &list,
                            &viewport,
                            snapshot,
                            stats.clone(),
                            0,
                            completion.clone(),
                            cancelled.clone(),
                        );
                    }
                    Event::Control(control) => {
                        match control {
                            Control::Scroll(index) => {
                                if let Some(snapshot) = ui_state.borrow().as_ref() {
                                    let index = index.min(snapshot.page.len().saturating_sub(1));
                                    scroll_index.set(index);
                                    let adjustment = viewport.vadjustment();
                                    adjustment.set_value((index as f64 * 66.0).min(
                                        (adjustment.upper() - adjustment.page_size()).max(0.0),
                                    ));
                                    awaiting_frame = true;
                                    frame_report(
                                        &list,
                                        &viewport,
                                        snapshot.clone(),
                                        stats.clone(),
                                        index,
                                        completion.clone(),
                                        cancelled.clone(),
                                    );
                                }
                            }
                            Control::Hide => {
                                window.set_visible(false);
                                if let Some(snapshot) = ui_state.borrow().as_ref() {
                                    emit("hidden", snapshot, &stats, &viewport, scroll_index.get());
                                }
                            }
                            Control::Show => {
                                window.present();
                                if let Some(snapshot) = ui_state.borrow().as_ref() {
                                    emit("shown", snapshot, &stats, &viewport, scroll_index.get());
                                }
                            }
                            Control::Quit => {
                                main_loop.quit();
                                window.destroy();
                                break;
                            }
                        }
                    }
                }
            }
        }
    });
    Ok(window)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let rows = match (args.next().as_deref(), args.next(), args.next()) {
        (None, None, None) => 1000,
        (Some("--rows"), Some(rows), None) => rows.parse::<usize>()?,
        _ => return Err("Использование: yonik-bench-gtk [--rows ЧИСЛО]".into()),
    };
    if rows > 100_000 {
        return Err("Допускается не более 100000 строк".into());
    }
    gtk::init()?;
    let provider = gtk::CssProvider::new();
    provider.load_from_data("* { background-image: none; box-shadow: none; font-family: 'Noto Sans'; font-size: 14px; } window { background: #191919; color: #eeeeee; } listview { background: #191919; } listview > row { padding: 0; margin: 0; } .server-row { background: #191919; padding: 0 12px; border-bottom: 1px solid #303030; } listview > row:selected .server-row { background: #332b40; } button { background: #292929; color: #eeeeee; } entry, dropdown { background: #222222; color: #eeeeee; } .title, .accent { color: #c3a6ef; } .title { font-weight: bold; } .secondary { color: #b2b2b2; } .host { color: #9c9c9c; }");
    let display = gtk::gdk::Display::default().ok_or("GTK: дисплей недоступен")?;
    gtk::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
    let main_loop = glib::MainLoop::new(None, false);
    let window = build(ui_bench_model::start(rows), main_loop.clone())?;
    let quit = main_loop.clone();
    window.connect_destroy(move |_| quit.quit());
    window.present();
    main_loop.run();
    Ok(())
}
