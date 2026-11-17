# yonik

<img src="crates/yonik-desktop/assets/yonik.svg" alt="yonik" width="112" height="112">

[English](README.md) · [Русский](README.ru.md)

An open-source native Linux proxy client built with Rust and Qt Quick.
The supported user workflow is local SOCKS5 through Xray-core or sing-box
for explicitly configured applications. Android is deferred.

The GUI supports subscription import and updates, profile selection, connection
control, HTTPS/TCP checks, favorites, a system tray, startup settings and diagnostics.
Subscriptions and credentials are encrypted using a key held by Secret Service.
The routing editor saves drafts; system TUN, DNS/Fake-IP, kill switch and applying
system routing through the GUI remain unavailable. Helper, worker and network
test implementations do not establish readiness of these user-facing features.

See the [Linux user guide](docs/user/linux-en.md) for build requirements, pinned
engine versions, startup, data storage and limitations, and the
[current readiness and remaining work](docs/PLAN.md).

## Build

Requires Rust 1.85+, a C++ toolchain, Qt6 Base/Declarative with Quick, Controls,
Widgets, Network and DBus, SQLite and a compatible linker. Wayland requires
Qt Wayland; encrypted storage requires a configured Secret Service.
Engines are not bundled or downloaded by the build.

From the checkout root, create a separate build directory:

```sh
yonik_build=/var/tmp/codex-myrs/transient/yonik-desktop
mkdir -p "$yonik_build"
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" CARGO_BUILD_JOBS=1 cargo build --locked --release -p yonik-desktop --features gui
```

Copy `$yonik_build/target/release/yonik-desktop` to a permanent directory before
cleaning the build. Run the application or install a user menu entry:

```sh
/permanent/path/yonik-desktop --engine-dir /absolute/path/to/engines
python3 tools/install_desktop.py --binary /permanent/path/yonik-desktop --engine-dir /absolute/path/to/engines
```

Do not run the GUI as root. The menu installer does not install the system helper
or copy engines. Consult the user guide for exact engine versions and SHA-256 pins.

## Development and checks

The workspace contains the domain model, session controller, subscription importer,
configuration compiler, Linux host/helper/worker and desktop. Diagnostic tools live
in `tools/`; tests live in `crates/`, `tests/` and `tools/tests/`. See
[CI](.github/workflows/check.yml) for Qt, engine and namespace test requirements.

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo fmt --all -- --check
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" CARGO_BUILD_JOBS=1 cargo clippy --workspace --all-targets --locked -- -D warnings
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 cargo test --workspace --locked
python3 -m unittest discover -s tools/tests -v
python3 -m unittest discover -s tests -p test_check_translations.py -v
python3 tools/check_translations.py
```

Once all build processes have stopped and required outputs have been saved, clean
your build under the same lock:

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo clean
```

## Documentation

- [Requirements and architecture](docs/specs/README.md).
- [Linux user guide](docs/user/linux-en.md).
- [Readiness and roadmap](docs/PLAN.md).
- Policy examples: [domains](examples/policy-names.json), [IP-only](examples/policy-ip-only.json).
- [GNU GPL v3.0](LICENSE).

Historical implementation plans, the UI mockup and one-off A4 diagnostics have
been removed from the current tree and remain available in Git history.
GUI fonts and their OFL licenses remain in `design/assets/fonts/`.
