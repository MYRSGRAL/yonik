# yonik

<img src="crates/yonik-desktop/assets/yonik.svg" alt="yonik" width="112" height="112">

[English](README.md) · [Русский](README.ru.md)

Нативный прокси-клиент с открытым исходным кодом для Linux на Rust и Qt Quick.
Рабочий пользовательский путь — локальный SOCKS5 через Xray-core или sing-box
для явно настроенных приложений. Android отложен.

GUI поддерживает импорт и обновление подписок, выбор профиля, подключение,
проверки HTTPS/TCP, избранное, трей, настройки запуска и диагностику.
Подписки и credentials хранятся зашифрованными с ключом из Secret Service.
Редактор маршрутизации сохраняет черновики; системные TUN, DNS/Fake-IP,
kill switch и применение маршрутов через GUI пока недоступны.
Наличие helper, worker и сетевых тестов не означает готовность этих функций.

[Руководство пользователя Linux](docs/user/linux-ru.md) описывает сборку,
закреплённые версии ядер, запуск, хранение данных и ограничения.
[Текущая готовность и оставшаяся работа](docs/PLAN.md).

## Сборка

Нужны Rust 1.85+, C++ toolchain, Qt6 Base/Declarative с Quick, Controls,
Widgets, Network и DBus, SQLite и совместимый linker. Для Wayland нужен
Qt Wayland, для хранилища — настроенный Secret Service. Ядра в сборку не входят.

Из корня checkout создайте отдельный каталог сборки:

```sh
yonik_build=/var/tmp/codex-myrs/transient/yonik-desktop
mkdir -p "$yonik_build"
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" CARGO_BUILD_JOBS=1 cargo build --locked --release -p yonik-desktop --features gui
```

До очистки сохраните бинарник из `$yonik_build/target/release/yonik-desktop`
в постоянном каталоге. Запуск и пользовательский пункт меню:

```sh
/permanent/path/yonik-desktop --engine-dir /absolute/path/to/engines
python3 tools/install_desktop.py --binary /permanent/path/yonik-desktop --engine-dir /absolute/path/to/engines
```

GUI не следует запускать от root. Установщик пункта меню не устанавливает
системный helper и не копирует движки. Точные версии и SHA-256 ядер приведены
в руководстве пользователя.

## Разработка и проверки

Workspace включает доменную модель, controller сессии, импорт подписок,
компилятор конфигураций, Linux host/helper/worker и desktop.
Диагностические стенды находятся в `tools/`, тесты — в `crates/`, `tests/`
и `tools/tests/`. Условия проверок с Qt, ядрами и namespace описаны в
[CI](.github/workflows/check.yml).

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo fmt --all -- --check
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" CARGO_BUILD_JOBS=1 cargo clippy --workspace --all-targets --locked -- -D warnings
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 cargo test --workspace --locked
python3 -m unittest discover -s tools/tests -v
python3 -m unittest discover -s tests -p test_check_translations.py -v
python3 tools/check_translations.py
```

После завершения процессов и сохранения нужных результатов очистите собственную
сборку под тем же lock:

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo clean
```

## Документация

- [Требования и архитектура](docs/specs/README.md).
- [Руководство Linux](docs/user/linux-ru.md).
- [Готовность и roadmap](docs/PLAN.md).
- Примеры политики: [домены](examples/policy-names.json), [IP-only](examples/policy-ip-only.json).
- [GNU GPL v3.0](LICENSE).

Исторические планы, макет интерфейса и разовая диагностика A4 удалены из текущего
дерева; исходные материалы доступны в истории Git. Шрифты GUI и их OFL-лицензии
сохранены в `design/assets/fonts/`.
