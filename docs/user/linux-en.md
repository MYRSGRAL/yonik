# yonik on Linux

[Русский](linux-ru.md) · [Project home](../../README.md)

## System connection

On the current branch, system TUN and Fake DNS use an installed helper. Network
changes require access to the system D-Bus and polkit authorization. The helper
loads engines from a trusted system registry. The matrix lists the tested
distribution versions, service managers and graphical sessions.
[Tested configurations](../superpowers/plans/2026-11-18-linux-tun-dns-portability.md#матрица-проверенных-конфигураций)

For a server profile, choose **System connection** in **Connection mode**.
To enable Fake DNS, set **Fake DNS domain suffixes** and select **Proxy** as
the default action. Xray and sing-box are available in this mode. Leaving
the suffixes empty turns Fake DNS off. Yonik reads `/etc/resolv.conf`, and the
system DNS manager controls the file. Firefox using system DNS can receive a
Fake-IP. Firefox using its own DoH receives an address from its chosen provider
and sends HTTPS through the system TUN.

When CIDR rules need real addresses for Fake DNS names, enter a
**Fake DNS policy resolver** under **Settings → Connection** and select
**Save DNS**. Use `IP:port` or `[IPv6]:port` for a DNS-over-TCP server
reachable through the selected proxy. Clear the field to disable policy DNS
lookups. Stop the connection before changing the address.

The build and installation commands below cover base revision
`48ce74304a3fb7263ccc7e2c06d96394113a687d` and local SOCKS5 on
Arch/CachyOS x86-64. Full P25 acceptance still covers open work on licensing,
runtime composition and performance.

## Build and verify provenance

Use the official [repository](https://github.com/MYRSGRAL/yonik), verify the chosen
commit and Cargo.lock, and run commands from the checkout root. Requirements:
Rust >=1.85 (edition 2024), Qt6 Base/Declarative with Quick, Controls, Widgets,
Network, DBus and QML development tools, a C++ toolchain, SQLite and a compatible
linker (lld/gold/mold). Wayland needs Qt Wayland. Storage requires an existing
configured desktop Secret Service. These commands do not install dependencies.

```sh
git rev-parse HEAD
python tools/install_desktop.py --help
```

On the project workstation use its build slot. Create the directory once and
hold a lock on its root whenever using it:

```sh
yonik_build=/var/tmp/codex-myrs/transient/yonik-user-guide
mkdir -p "$yonik_build"
/home/myrs/projects/yonik/local/orchestration/with-rust-slot flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" CARGO_BUILD_JOBS=1 cargo build --locked --release -p yonik-desktop --features gui
```

Another machine may lack this orchestration wrapper: use equivalent local build
concurrency control, retaining flock, an external target and jobs=1. Before
cleanup copy the binary to a permanent directory you own and record source SHA,
toolchain and binary SHA-256. Once all processes using the build have finished,
run `cargo clean` with the same lock and `CARGO_TARGET_DIR`. Leave other temporary
directories alone.

Engines are neither bundled nor downloaded by the build. Obtain official binaries
for your platform and verify their provenance and upstream checksums through the
official supplier channel, then their local SHA-256. The GUI expects these exact
bytes; newer upstream versions or locally adapted builds do not replace its pins:

| Path inside engine-dir | SHA-256 |
| --- | --- |
| `xray-26.10.31/xray` | `cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1` |
| `sing-box-1.14.4/sing-box` | `1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a` |

The GUI verifies a snapshot and runs config-check before starting. Do not bypass
mismatches. The cleanbuild78 archive from eec7 sources is historical evidence,
not proof of the latest binary.

## Launch and menu entry

Replace these absolute paths with your permanent paths:

```sh
/permanent/path/yonik-desktop --engine-dir /absolute/path/to/engines
python tools/install_desktop.py --binary /permanent/path/yonik-desktop --engine-dir /absolute/path/to/engines
```

The installer only creates a user menu entry and icon; it does not copy binaries,
engines or install the system helper. Run the GUI as your regular user. Default
data location is `$XDG_DATA_HOME/tofu` or `~/.local/share/tofu`;
`--data-dir /absolute/private/path` chooses another directory. The legacy `tofu`
name and Secret Service identity preserve access to encrypted data. If the key
is missing, locked or unavailable, stop and restore access to the original Secret
Service. Do not delete the database/key or create a replacement for an existing
database. There is no plaintext fallback. Keep subscription URLs and credentials
out of argv, logs, screenshots and bug reports.

## Subscription, import and connection

1. Open the server card → **Servers → Add** and paste the subscription URL.
   Adding starts the download. **Advanced → Local source** allows HTTP/local
   addresses only for trusted sources. **Device ID** is off by default; enabling
   sends a random stable ID for that subscription, not a hardware ID. Device-limit
   errors never generate a new ID.
2. In **Review import**, inspect accepted/rejected/flagged counts, issue pages and
   the JSON warning. Approve only trusted sources. **Save profiles** approves the
   report; **Discard import** preserves the previous snapshot. Source JSON
   routes/DNS/inbounds do not become your network settings.
3. Select a server, return home and press the central button. Import support for a
   protocol does not imply engine support for every parameter: incompatibility
   fails explicitly instead of silently weakening TLS.
4. Obtain the SOCKS5 address from **Settings → Connection**, explicitly configure
   the application that should use it and check that application's DNS behavior.
   The OS normally selects a port; `--listen-port 10808` is a diagnostic override.
5. Select the subscription in **Servers** to refresh or cancel its current download.
   **More** offers rename/delete with confirmation. Errors, cancellation and
   discarded imports preserve the last approved snapshot. Deleting a subscription
   removes its servers from this device.

The add dialog also accepts local text or a file up to 8 MiB; manual entry is
available. Review the report and create the requested encrypted backup before
the first local save. Local sources do not download or refresh from the network.
For offline analysis of a subscription body (URI/Base64/supported JSON), use stdin,
keeping the original file private and outside git:

```sh
/home/myrs/projects/yonik/local/orchestration/with-rust-slot flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" CARGO_BUILD_JOBS=1 cargo run --quiet --locked -p yonik-import < /private/path/subscription.txt
```

This produces an analysis report, not a GUI import or activation. Exit 0 includes
reports with rejected records. Limits: 8 MiB input, 32 MiB decoded, 20,000 URIs,
64 KiB per URI, JSON depth 64. See [import limits](../validation/2026-11-09-subscription-import.md).
These paths do not fully satisfy FR-06/07.

Adding a URL uses Direct. For subscription updates in Proxy mode, configure
**Settings → Connection** with a trusted DNS-over-TCP IP:port (or [IPv6]:port);
it is used through the active SOCKS session and does not change OS/core DNS.
Disconnect before editing. An empty value disables DNS for domain endpoints.
Scheduled refresh requires confirmed power/network/visibility conditions;
unknown conditions block background work (fail closed). Do not rely on refresh
while hidden; refresh manually in the open GUI when needed.

## Status, settings and exit

`Checking` is not success. `Connected` confirms the specific HTTPS endpoint through
the current outbound at check time, not global internet connectivity. `Limited`
leaves the engine running without current HTTPS proof. Reconnect manually after a
network change. TCP in **Diagnostics** measures the server endpoint, not VPN speed.
Set a custom HTTPS URL and expected status 200–299 there. Do not publish tokenized
URLs; the input field clears after submission.

Engine, port, language and safe check URLs persist in preferences. URLs containing
query, credentials or fragment are session-only; restart uses the saved safe/default
endpoint. Preserve the original preferences file on read/write errors and resolve
permissions/access instead of deleting it. The routing editor saves a draft only;
**Apply to network** is disabled. Draft rules do not control the running SOCKS
session or application traffic.

The routing draft supports destination `tcp`/`udp` and ports 1–65535
(for example `443,8000-8080`, up to 16 ranges per rule). These are destination
conditions, not the local SOCKS listening port. Enabled transport conditions
currently block Connect as unsupported; saving them does not enforce them on
traffic. The first transport-draft save requires a verified current encrypted backup and upgrades
the database to format5; older readers refuse it. Keep a matching backup before
using an older binary.

In **Settings → Startup and updates**, login startup and autoconnect are separate
options, both off by default. Confirm the current saved profile, engine, mode and
routing revision with **Confirm current target**. Saving does not connect. A changed
target or unavailable key blocks the startup attempt; no other profile is selected
and the keyring is not unlocked automatically. Stop cancels a pending attempt.
Login startup manages only the user XDG `autostart/yonik.desktop` entry and uses
`/usr/bin/yonik-desktop --start-hidden`; the menu-entry installer does not place a
binary there. Normal launches stay visible; hidden launch requires a registered
tray, otherwise the window appears.

Closing the window with a working tray can hide it and leave the session running.
Choose **Quit** in the tray for full exit and wait for shutdown. Relaunching with
the same data-dir restores the existing instance. `CleanupError` means cleanup is
unconfirmed: repeat Stop if offered and retain a sanitized error description.
Do not report successful disconnection or manually flush network state.

Diagnostics offers a sanitized export and bounded rotating disk logs. Check
the exported contents before sharing; software checks do not establish physical
power-loss durability.

## Package install, update, rollback and removal

The Arch recipe pins its own source revision and builds the GUI, helper and
worker. Engines are supplied separately. Build in a disposable VM without
`makepkg -i/-s` and validate the archive before installation.
[Arch package recipe](../../packaging/arch/README.md)

```sh
python tools/check_arch_package.py /absolute/path/yonik.pkg.tar.zst
```

The validator checks allowlist/permissions/metadata/ELF magic, not binary authenticity
or functionality. Verify provenance separately. The clean-VM install/update/rollback
matrix remains incomplete; this is not an accepted host installer. For your own
verified package, normal package-manager actions in the VM are
`sudo pacman -U /absolute/path/yonik.pkg.tar.zst` and `sudo pacman -R yonik`.
These mutate the system and were not executed here. The package has no automatic startup hooks; login startup is an explicit GUI option,
but an explicit client request can activate the D-Bus service. Do not run the
helper manually or create an engine registry through workaround commands. The
system registry requires a separate trusted supplier; user engine-dir does not
authorize helper engines. Avoid `curl | sh`, broad sudo workarounds, flushing
nftables/routes or changing the keyring to bypass errors.

Before update/removal, stop the session and Quit. Retain the previous verified
binary/package and a private consistent backup of data while the application is
closed; the original Secret Service key must remain accessible. For user-launcher
rollback, restore the previous binary and rerun menu installation with its path.
For packages, use `pacman -U` with the previous verified archive in the VM. Old
binaries may not support a newer database schema: never open the only data copy
with an older version. Restore a matching backup separately without replacing
the key.

To remove the user launcher, remove only its created
`applications/cloud.highpriority.yonik.local.desktop` and
`icons/hicolor/scalable/apps/cloud.highpriority.yonik.local.svg` under XDG data home,
after checking ownership and the entry's managed marker. Preserve unrelated files.
You may separately remove your own binary. Preserve databases, user data and keys.
Package removal does not promise active-network cleanup; do not manually delete
`/run`, other resources or keyring data.
[Guide validation](../validation/2026-11-11-linux-user-guides.md).
