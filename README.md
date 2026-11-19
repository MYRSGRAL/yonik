# yonik

<img src="crates/yonik-desktop/assets/yonik.svg" alt="yonik" width="112" height="112">

[English](README.md) · [Русский](README.ru.md) · [GitHub](https://github.com/MYRSGRAL/yonik)

[Linux user guide](docs/user/linux-en.md).

[Implementation plan and current progress](docs/PLAN.md) (Russian).

A native, open source proxy client in development. Linux first, Android later.
The Linux client manages subscriptions, local SOCKS5 and system connections
through an installed helper. System TUN with Fake DNS has been tested with
Xray and sing-box. The matrix covers Debian, Ubuntu, Fedora, Arch Linux and
Arch Linux ARM, with graphical sessions tested on GNOME Wayland and Xfce X11.
[System TUN and Fake DNS test matrix](docs/superpowers/plans/2026-11-18-linux-tun-dns-portability.md#матрица-проверенных-конфигураций)

### Implemented

- Canonical IPv4/IPv6 CIDR validation and matching.
- Ordered routing decisions: protected private VPN networks, discovered LAN,
  user rules, presets, default action.
- Executable and destination conditions: AND between groups, OR within each group.
- Private-network blocking when its VPN route becomes unavailable.
- Synthetic Xray/sing-box TUN lifecycle and TCP/UDP IPv4/IPv6 echo tests in isolated Linux namespaces.
- Native executable-path routing checks, including two clients with the same basename.
- Portable session reducer with stale-event rejection and explicit cleanup confirmation.
- Single-use PreparedPlan guard bound to environment generations and the checked config digest.
- Bounded URI/Base64 import for VLESS, VMess, Trojan, Shadowsocks, HTTP CONNECT and SOCKS5.
- Strict single-server configuration compilers for Xray 26.10.31 and sing-box 1.14.4,
  with a loopback SOCKS listener, TLS verification and explicit unsupported-option errors.
- Linux `yonik-local` host: verifies an immutable engine snapshot, runs config-check,
  serves local SOCKS, checks HTTPS through that outbound, and stops/reaps the core.
- IDNA exact/suffix rules and a portable DNS decision model with explicit resolution,
  ambiguity, TTL/generation checks and session-bound fake mappings.
- Native domain-only or explicit IP-only policies with ordered proxy/direct/block,
  protected unavailable destinations and an authenticated outbound-only health listener.
- Staged subscription refresh with exact-report approval and stale-update rejection;
  Linux Direct HTTPS fetch with DNS/peer checks, encrypted SQLite snapshots and
  a Secret Service master-key adapter. These are library APIs; the current CLI
  still reads profiles from stdin.
- Stable server identities and encrypted favourites, search/sort pages, duplicate
  reconciliation and revision-bound selection from the same stored snapshot.
- Optional Qt Quick/CXX-Qt desktop: RU/EN screens, subscription review, profile
  selection and local-session controls; event-driven tray and one instance per data directory.

The Rust library calculates policy; the isolated suites provide the specific
network evidence described below. Full mixed domain/CIDR DNS/Fake-IP execution,
scheduled subscription updates, proxied fetch peer verification, TUN policy integration,
helper and the routing editor remain to be implemented. Desktop/tray acceptance on
live KDE Wayland and the final visual design are still open.

`yonik-application` currently implements the initial connect/check/stop loop.
Its host-provided controller ID must be unique while callbacks from an older
controller can still arrive. It does not perform I/O, recovery, reconfiguration
or persistence, and its state is not independent proof of network health.
Preparation now goes through `prepare/apply`; direct `Event::Validated` is removed.
The trusted host supplies fresh generations and a SHA-256 digest of the immutable
checked artifact. This does not replace OS authorization or atomic host-side Apply.

The strict DNS gate now has isolated native counterexamples for partial A/AAAA,
route-to-dial address changes and Fake-IP reuse before the original TTL expires.
These results keep mixed DNS/Fake-IP execution disabled; they do not mark G-DNS
as passed. [Evidence and adapter requirements](docs/validation/2026-11-09-native-dns-contracts.md).

Pinned sing-box now has experimental DNS provenance and direct TCP/UDP
`pin_resolution`: original CNAME/NODATA TTLs, selected response metadata and address
binding through retries and UDP writes. The isolated suite passed 62 scenarios;
network/policy epochs, proxy/Xray parity and Fake-IP lifecycle remain open.
The compiler keeps mixed DNS/Fake-IP disabled and the desktop engine is unchanged.
[Build and limits](adapters/sing-box/v1.14.4/README.md),
[resolution pin evidence](docs/validation/2026-11-09-resolution-pin.md).

The UI redesign direction is a nearly black theme with lavender accents and a
simple connect screen. All configuration moves to Settings. Variant A, with a
large central connect button, has been selected in the [interactive concepts](design/ui-variants.html).
The [isolated Qt/GTK4/Slint benchmark](bench/ui/README.md) is separate from the
application; real-window measurements and toolkit selection remain pending.
The native Qt prototype now implements A: server card, central connect/stop button,
and connection status. The server card opens **Servers**; a gear in the upper right
opens **Settings**. Back returns to the previous level. The home screen has no
extra action buttons, mode badge or subscription summary.
The window starts at 420×760 logical pixels (minimum 380×600). Onest/Unbounded
fonts and OFL licenses are embedded. This working UI does not wait for the benchmark or system TUN.
[UI direction](docs/specs/ui-direction.md).
[Main-screen/backend contract](docs/specs/ui-backend-contract.md).
[Native A implementation and checks](docs/validation/2026-11-09-ui-a-native.md).

## Development

### Native Linux GUI

The test suite also requires `dbus-daemon` for its private bus; it never changes
the host's D-Bus services. Runtime monitoring reports missing services explicitly.

The prototype requires Qt 6 Base/Declarative (Quick, Controls, Widgets, Network,
DBus and QML development tools), a C++ compiler, system SQLite and a compatible
linker (`lld`, `gold` or `mold`; CI installs `lld`). CXX-Qt selects one when GNU
ld.bfd is the system default. GUI dependencies
are behind the optional `gui` feature; ordinary workspace and Android checks do not
build Qt. CXX-Qt is pinned to 0.10.0, with matching CXX/cxx-gen ABI versions.

```sh
yonik_build=/var/tmp/codex-myrs/transient/yonik-dev
mkdir -p "$yonik_build"
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo build --locked -p yonik-desktop --features gui --release
"$yonik_build/target/release/yonik-desktop" --engine-dir /absolute/path/to/engines
```

The engine directory contains verified `xray-26.10.31/xray` and/or
`sing-box-1.14.4/sing-box`; binaries are not bundled. The GUI automatically chooses
a free loopback TCP/UDP port; copy the address from **Settings → Connection**.
`--listen-port PORT` remains a diagnostic fixed-port override. Configure that SOCKS proxy explicitly in the
application that should use it. The GUI does not enable TUN or system proxy.

Install a user menu entry for launching without a terminal or root:

```sh
python tools/install_desktop.py --binary /permanent/path/yonik-desktop --engine-dir /absolute/path/to/engines
```

Keep the executable at that permanent path outside a temporary build directory.
Open **Servers → Add** and paste a link; loading starts immediately.
All subscriptions and their server lists live in **Servers**. Choose a subscription
to refresh it, cancel its current download, or open **More** to rename or delete it.
Deletion requires confirmation. There is no favourites control in the current GUI.
Review and approve JSON or partial imports. The optional name and local HTTP-source
exception are under advanced options. Return home, choose a server and press the central button.
`Limited` means the core is running but the
HTTPS check failed. Data lives under `$XDG_DATA_HOME/tofu` or `~/.local/share/tofu`;
`--data-dir PATH` selects a private directory. The legacy `tofu` data-directory
name and Secret Service identity are retained
for compatibility with existing encrypted data. The master key stays in Secret Service.
A locked/missing key never triggers plaintext fallback. Never pass subscription
URLs as command-line arguments.

If your provider requires HWID, enable **Device ID** in the add dialog's advanced
options or **Servers → More** for the selected subscription. It is off by default. Enabling
it sends a random stable ID for that subscription; hardware identifiers are never
read. The ID is encrypted at rest and survives disabling the option and restarting.
Changing the setting immediately retries the download. Device-limit failures have
a separate message; the app never generates another ID to bypass the limit.
HWID applies to subscription downloads.

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

The **About** page and window title show the build ID. When updating, quit the
previous instance through its tray menu: closing a window can merely hide it,
and launching again restores the running instance.

**Settings → Diagnostics** accepts a custom HTTPS URL and expected status
(200–299); the default requires exactly 204. The GUI uses a five-second timeout,
checks TLS and rejects redirects. Settings apply to the next Connect; safe URLs persist across restarts,
while URLs with credentials, query or fragment remain session-only; editing is disabled while a core is active. The URL is hidden
by default and stays out of state/tray/trace. The active result shows HTTP status
and duration or TLS/timeout/transport failure. This is a single HTTPS measurement,
not TCP host latency or a continuous internet guarantee.

Closing hides the window when a tray is available; otherwise it requests a clean
shutdown. Quit waits for session cleanup. Tray commands use the same controller.
The current tray has basic connect/disconnect/restore/quit.
The routing editor saves drafts; network activation and full T-01…T-04 acceptance remain pending.
Engine, language and safe HTTPS check settings persist; URLs with credentials,
query or fragment remain session-only.
[GUI checks and remaining gates](docs/validation/2026-11-09-native-desktop.md).

[Configurable HTTPS checks and evidence](docs/validation/2026-11-09-configurable-health.md).

In **Settings → Diagnostics**, **Check TCP** measures the selected server separately from HTTPS.
It resolves DNS once and takes three direct TCP samples to the same winning IP,
port and IPv6 scope, closing each socket without authentication or payload.
The reported connect time is the median of three successful samples, excluding
DNS and address-race waiting. A partial failure stops the series and has no median.
All stages share a five-second total deadline.
Names use the native systemd-resolved Varlink API; literals need no resolver.
Missing resolver support is explicit, with no external DNS fallback. QUIC or an
unknown transport reports “not applicable”. Cancel stops only TCP; Stop/Quit also
cancel it. A result is tied to the selected source/profile/revision and timestamp.
This is one historical three-sample series. Observed network changes cancel pending TCP
checks and remove old results; result history is not saved. It does not prove
proxy authentication, HTTPS access or throughput.

[TCP checks and evidence](docs/validation/2026-11-09-tcp-probe.md),
[three-sample series](docs/validation/2026-11-09-tcp-series.md).

The Linux batch API schedules up to 10,000 TCP series with 1–32 active/result
slots and a bounded output channel. Cancellation, receiver closure and dropping
the batch release its I/O. It adds no runtime or task per target; the desktop
bulk-check action is still pending. [Batch contract](docs/specs/tcp-batch-contract.md).

Linux now observes route/address changes through netlink and DNS/network service
changes through system D-Bus. The GUI reports unavailable sources explicitly.
Results carry a process-local network generation; late replies from an older
generation cannot restore a successful status. A network change invalidates the
HTTPS proof and leaves the running core in `Limited`; reconnect manually to check
again. It does not launch automatic probes or reconnects. This observer is not yet
the atomic NetworkHost snapshot/apply contract required for TUN.
[Network observation and remaining limits](docs/validation/2026-11-09-network-observation.md).

The Linux library also exposes bounded read-only `read_topology` and `lookup_route`
APIs. They read links, addresses, routes from all tables, policy rules and nexthop
objects, or ask the kernel for a route with explicit UID/mark/source and TCP/UDP
selectors. Unknown attributes remain visible as incomplete interpretation. These
facts do not authorize Apply, prove reachability or enable private VPN binding.
The privileged network lifecycle and ResolverHost Apply remain pending.

For explicit diagnostics, using the build directory above:

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo build --locked -p yonik-linux --example network_inspect
printf '%s\n' '{"op":"snapshot"}' | flock -s "$yonik_build" "$yonik_build/target/debug/examples/network_inspect"
```

This CLI outputs network addresses and selectors intentionally; ordinary Debug
output is redacted. [Topology/route-get evidence and limits](docs/validation/2026-11-09-network-topology.md).

The read-only ResolverHost APIs `read_resolver_snapshot` and `subscribe_resolver`
read complete global/per-link DNS configuration through systemd Varlink. They
preserve route-only domains, nullable facts and unknown fields; they do not
configure DNS. Dump requires systemd API v259+, streaming v258+ and authorization.
The diagnostic `resolver_inspect` example prints only counts and known modes:

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo run --locked -p yonik-linux --example resolver_inspect -- snapshot
```

Use `watch` for an explicitly requested stream; it never requests interactive
authorization. On the tested host the snapshot reports `foreign` and streaming
returns `PermissionDenied`. Neither daemon availability nor a snapshot proves
system DNS ownership, namespace identity or G-DNS. The GUI observer above does
not yet consume this stream and does not guarantee complete DNS configuration
change coverage. [ResolverHost evidence and limits](docs/validation/2026-11-09-resolver-host.md).

A stdin-only diagnostic example checks one accepted record by index and emits
only counts, status and durations: `cargo run --locked -p yonik-linux --example tcp_probe -- 0`.
Pipe local profile text into stdin; subscription URLs and credentials must stay
out of argv and logs. The example supports SIGINT/SIGTERM cancellation.

### Network helper authorization

`yonik_linux::helper::PeerAuthorizer` checks the sender's bus credentials and a
fixed polkit action, pins the root-owned authority and validates raw reply senders.
It rechecks the peer and authority after the decision, bounds concurrent checks,
and cancels requests through the original authority owner. Its `PeerIdentity` is
a snapshot; Prepare/Apply must authorize again before effects. Tests use a private
bus and fake authority. No system service is installed or network changed.
[Authorization contract](docs/specs/helper-authorization.md).

`yonik_linux::helper::TrustedRegistry` reads a fixed root-owned system registry
and creates a hash-checked sealed snapshot from the same verified file descriptor.
It rejects untrusted paths, metadata and manifest entries. The normal user engine
directory remains separate. This component does not install a service or apply
network changes. [Registry contract](docs/specs/helper-trusted-registry.md).

`PreparedRequests<A>` binds checked artifacts to a bus peer and generation,
requires fresh polkit on prepare and claim, and releases each artifact once.
The real `CheckedConfig` supplies its current SHA-256. Pending work, payload size
and TTL are bounded; executable-image memory uses the shared budget described below. [Prepare/claim contract](docs/specs/helper-prepared-requests.md).

A process-wide budget now covers retained config buffers and helper executable
snapshots. Claimed artifacts retain their lease; a weak registry cache shares the
sealed inode, and expired pending data can be reclaimed across stores under pressure.
These counters are not an RSS measurement or a completed G-POWER gate.
[Memory contract](docs/specs/helper-memory-budget.md).

### Managed network resource journal

`yonik_linux::managed_network` provides a bounded, durable ownership journal for
the future privileged network helper. It records intent before effects, requires
explicit OS reconciliation after reopening, and retains unresolved cleanup items.
Session resources and the public kill-switch block have separate lifetimes.
Storage uses private permissions, directory-FD operations, an exclusive writer
lock and fsync/atomic replacement. It contains typed descriptors, without secrets
or executable commands. The journal itself does not apply routes, DNS or firewall
rules and does not enable system TUN. [Checks and limits](docs/validation/2026-11-09-network-resource-journal.md),
[helper plan](docs/superpowers/plans/2026-11-09-linux-network-helper.md).

`managed_network::nft::NftExecutor` adds creation, observation and removal of
owned empty nftables tables. It pins the namespace and trusted system `nft`,
checks the complete ownership marker, and deletes by a nonzero kernel handle.
`Journal::mark_cleanup` persists the cleanup boundary before an asynchronous
effect. Commands have bounded output, concurrency and execution time.
[Executor contract](docs/specs/helper-nftables-executor.md).

`PublicBlockPolicy` adds atomic IPv4/IPv6 output blocking with explicit LAN/VPN,
TUN and tightly bound service exceptions. Applied state requires the complete
kernel ruleset to match; replacement preserves protection in one transaction.
The library can preserve the public block after session cleanup and remove it
explicitly on Unlock. Full system-session and GUI integration
remain unfinished. [Public-block contract](docs/specs/helper-public-block.md).

Journal schema v2 persists the desired/previous policy and Unlock intent in the
same atomic file as owned resources. Durable Apply/Unlock entrypoints and
startup recovery compare actual rules; recovery never replays stored interface
exceptions automatically. Live-process command fencing and crash-boundary
tests are included. Full session recovery remains open.
[Policy recovery contract](docs/specs/helper-policy-recovery.md).

`yonik-helper` now provides versioned D-Bus Prepare/Apply/Stop/Unlock/State for
durable public blocking, with fresh polkit checks and a startup cgroup fence.
Private-bus and real isolated nft traffic tests pass. Service packaging is
provided, but it is not installed or wired to the GUI. System TUN and live
reconciliation remain open; LAN is explicitly unsupported until then.
[Service contract and evidence](docs/specs/helper-service.md).

A typed persistent TUN executor now records intent, verifies a full ownership
alias and cleans up by ifindex. Both pinned engines and the adapted sing-box
pass the single-queue traffic/lifecycle fixture; multi-queue is unsupported.
Network resources are implemented separately; DNS and service/GUI session wiring remain open.
[Owned TUN contract and evidence](docs/specs/helper-owned-tun.md).

System TUN compilation now preserves the selected profile and authenticated
probe, with helper-owned addresses/routes and IP-only policy. Xray and the
pinned sing-box external-configuration adapter pass TUN→VLESS→echo and crash
cleanup fixtures. Stock sing-box is rejected for this mode: auto_route=false
still creates IPv6 network effects. [Contract and evidence](docs/specs/helper-tun-configuration.md).
Journal-backed RPDB rules now capture unmarked traffic while marked core sockets
use the existing routing policy. Both cores pass TCP/UDP IPv4/IPv6 through a peer
in a separate namespace behind veth, followed by owned-resource cleanup.
Service/worker/GUI wiring, live reconciliation and DNS gates remain open.
[RPDB contract](docs/specs/helper-tun-rpdb.md).
The new sealed-FD worker launcher separates Check and Run, preserves the PID
across exec, and fixes the core arguments and environment. Both cores pass the
TUN fixture under a distinct nonzero UID with NET_ADMIN only and no-new-privileges;
the same profile passes Check with no capabilities. Fixed systemd units and a
supervisor bind lifecycle to InvocationID and verified cgroup emptiness.
Installed units, a dedicated UID, setsid descendants, helper crash/recovery,
and both cores’ TUN traffic passed in a
[disposable Arch VM](docs/validation/2026-11-10-installed-worker.md).
Profile Prepare/Apply and GUI integration, plus stubborn-child TERM/KILL
acceptance, remain pending. [Worker contract](docs/specs/helper-worker-runtime.md).

A closed `ServerIntent` and a helper-owned network plan now share descriptors
between the compiler and TUN executor. External topology projection and the
configure/capture/cleanup sequence pass isolated namespace gates.
[Contract and limitations](docs/specs/helper-session-network.md).
The authorized session host, worker/nft orchestration and GUI wiring remain
pending; this does not enable system TUN in the installed app.

### Rust libraries and CLIs

Rust 1.85+ (edition 2024). Application remains std-only; domain normalization uses IDNA, and the importer uses
Base64, URL/IDNA and JSON libraries. The Linux host uses Tokio, reqwest/rustls,
SHA-256 and safe rustix syscalls. Persistent subscriptions additionally use system
SQLite (`sqlite3` development headers), XChaCha20Poly1305 and Secret Service.
Cargo.lock pins MSRV-compatible dependencies.
Build artifacts belong outside the checkout. On the project development host:

```sh
yonik_build=/var/tmp/codex-myrs/transient/yonik-dev
mkdir -p "$yonik_build"
cargo fmt --all -- --check
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo test --workspace --locked
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo clippy --workspace --all-targets --locked -- -D warnings
```

Engine smoke tests require Linux, Python 3.12+, `ip`, `unshare`, `/dev/net/tun`,
unprivileged user/network namespaces and independently verified engine binaries.
They never configure the host network or system DNS:

```sh
python tools/engine_smoke.py xray /absolute/path/to/xray
python tools/engine_smoke.py sing-box /absolute/path/to/sing-box
python tools/engine_traffic.py xray /absolute/path/to/xray
python tools/engine_traffic.py sing-box /absolute/path/to/sing-box
```

If binaries are in a transient task directory, hold `flock -s` on its root for
the entire test. See [recorded checks and pinned versions](docs/validation/2026-11-09-foundation.md).
The smoke suite covers config validation and interface lifecycle. The traffic
suite sends random payloads through TUN to redirected local echo endpoints and
checks interface counters and a negative control after shutdown.
[Traffic evidence](docs/validation/2026-11-09-tun-traffic.md).
Neither suite completes the G-LINUX/G-DNS/G-APP gates: proxy outbounds, DNS,
private VPN integration and broader process attribution still require verification.

Executable attribution has a separate baseline suite:

```sh
yonik_apps=/var/tmp/codex-myrs/transient/yonik-apps
mkdir -p "$yonik_apps"
flock -s "$yonik_apps" python tools/engine_apps.py xray /absolute/path/to/xray --work-dir "$yonik_apps"
flock -s "$yonik_apps" python tools/engine_apps.py sing-box /absolute/path/to/sing-box --work-dir "$yonik_apps"
```

This verifies exact executable paths for sequential same-UID TCP/UDP IPv4/IPv6
flows, not desktop application coverage or the complete G-APP gate.
[Process routing evidence](docs/validation/2026-11-09-process-routing.md).

Never commit subscription links, credentials or real server configurations.
`local/` is ignored for private development files.

### Offline import diagnostic

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo run --quiet --locked -p yonik-import < local/subscription.txt
```

Input is a subscription body, not a download URL. The CLI only prints counts,
protocols and static issue codes/line numbers; exit 0 means an analysis report
was produced, including partial/rejected records. It never activates a profile.
Limits: 8 MiB input, 32 MiB decoded, 20,000 URI records, 64 KiB per URI, JSON depth 64.
Xray JSON objects/arrays retain their source for review and extract VLESS and
Shadowsocks outbounds into managed profiles. Source routes/DNS/inbounds are never
executed. Unknown options block compilation; unsupported protocols appear in the
report. Other JSON remains opaque. Downloads use `Happ/1.0 yonik/<version>` for
Remnawave JSON compatibility; provider response rules can override the format.
The separate compiler checks profile capabilities; the host still needs
to run the pinned engine's config-check before activation. Fatal errors preserve input
bytes in the library API; an oversized/broken stream is explicitly marked incomplete.
See [import evidence and limitations](docs/validation/2026-11-09-subscription-import.md).

### Compile one server

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo run --quiet --locked -p yonik-engine --bin yonik-compile -- xray --server 0 < local/profile.txt
```

The default output is metadata (`compiled_not_checked`), not a connection result.
Input must be a complete URI import with no rejected records; `--server` is zero-based.
Use `sing-box` to select the other engine and `--listen-port` to change 10808.
`--emit-secret-config` explicitly writes sensitive JSON to stdout: pipe it only to a
trusted consumer, never logs or a public issue. The library's `CompiledConfig` Debug
is redacted; only `write_sensitive` exports the JSON.

Supported: the six imported protocols, compatible TCP/WS/gRPC, XHTTP on Xray,
TLS with certificate verification (system CA), VLESS TCP REALITY and Vision.
Unknown/inapplicable options, insecure TLS, legacy VMess alterId, plugins and unsupported
transports/ciphers fail explicitly. Xray public plaintext VLESS is rejected; private IP
fixtures are allowed. SOCKS-over-TLS and native JSON activation are not implemented.
The listener is always `127.0.0.1`; there is one proxy outbound and no direct fallback.
This does not configure TUN, routing policy, system proxy or DNS, or start an engine.

Synthetic config-check, TCP/UDP IPv4/IPv6 forwarding and TLS negative controls:

```sh
flock -s "$yonik_build" env TMPDIR="$yonik_build" python tools/engine_compile.py "$yonik_build/target/debug/yonik-compile" /absolute/path/to/xray /absolute/path/to/sing-box
```

Requires `openssl` in addition to the namespace test tools, and the pinned engine versions.
[Compiler evidence and limitations](docs/validation/2026-11-09-engine-compiler.md).

### Run a local SOCKS session on Linux

Linux 6.3+ with executable sealed memfd and `/proc` is required. Obtain the pinned
core binary separately and verify its release archive before trusting its binary hash.
`--sha256` is the hash of the extracted executable, not the archive. For the verified
Xray Linux amd64 release used in our tests:

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo run --quiet --locked -p yonik-linux --bin yonik-local -- xray --binary /absolute/path/to/xray --sha256 cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1 --server 0 < local/subscription.txt
```

The host copies and hashes the regular ELF file into a sealed memory snapshot;
version, config-check and start use that same snapshot. Configurations stay in memory
and are passed through stdin. Core stdout/stderr are suppressed to protect secrets.
Listener ownership is verified against the child process, including during health checks.
The only managed resource is the child core and its `127.0.0.1:10808` SOCKS listener.
This does not enable system proxy, TUN, routes or system DNS.

Output is safe NDJSON. `Connected` requires the expected HTTPS status through that exact SOCKS outbound;
TLS, timeout and HTTP failures result in `Limited`, with the core still serving SOCKS.
There is no direct fallback or redirect following. `--check-url` chooses an HTTPS endpoint,
`--check-status` sets the expected status (200–299, default 204).
`--check-timeout` accepts 1–60 seconds; the default is generate_204 with 10 seconds.
Ctrl+C/SIGTERM stops and reaps the core. `--once` checks, stops and exits: 0 for success
or cancellation, 2 for a failed endpoint check, 1 for an import/config/host failure.
No automatic recovery or persistent supervisor is implemented yet; SIGKILL of the host
cannot run cleanup. The local CLI is not the complete production EngineHost.

Partial imports fail by default. After reviewing `yonik-import` results,
`--accept-partial --server N` explicitly selects one parsed record and reports the rejected
count; it never enables unsupported parameters of that record. Native JSON remains unsupported.
Indices count parsed records from zero. For sing-box use `sing-box` and its own verified
executable/hash. Engine binaries are not bundled.

Isolated host tests (also require `rustc`, `openssl`, PID/mount namespaces):

```sh
flock -s "$yonik_build" env TMPDIR="$yonik_build" python tools/engine_host.py "$yonik_build/target/debug/yonik-local" /absolute/path/to/xray /absolute/path/to/sing-box
```

[Host evidence and remaining work](docs/validation/2026-11-09-linux-engine-host.md).

### Subscription library

`yonik-subscription` stages an immutable import report before approval. Linux
`SubscriptionService` combines it with `FetchHost` and
`EncryptedSubscriptionRepository`: a new refresh, cancellation or source change
invalidates older results; SQLite compares source generation and snapshot revision
in one transaction. Errors and empty imports preserve the last approved snapshot.
`offline()` also reports whether that snapshot belongs to an older source generation.

The repository encrypts URL/name, body, metadata and validators with
XChaCha20Poly1305; record identity and generations are authenticated. The 32-byte
key comes from `subscription_master_key()` through Secret Service, never from
SQLite. Existing databases must use `allow_create = false`; a missing/locked key
is an error. The caller must choose a canonical private directory (0700); database
permissions are 0600. Finish the last GUI handle with `close().await` to keep SQLite
checkpoint work off the UI thread.

Public sources require HTTPS and public DNS/peer addresses at every redirect.
Local HTTP/private sources require an explicit source exception. Proxy fetch
currently returns `UnsupportedPeerVerification`: SOCKS exposes the proxy peer,
not the upstream peer required by the contract. There is no Direct fallback.
Native JSON may be saved after review, but this does not authorize its execution.
Scheduling, the routing UI and automatic session
reconfiguration are still pending. [Validation and limits](docs/validation/2026-11-09-subscription-snapshots.md).

Server identities use versioned connection parameters, including unknown options;
URI fragments and VMess `ps` only change the displayed name. A source-scoped HMAC
index preserves profile IDs and favourites on rename/reorder. A changed endpoint,
credential or option creates a new identity; absent and explicit defaults may
conservatively differ. Duplicates collapse to the first parsed record. Removed
favourites stay visible as unavailable and recover their ID when they return;
removed non-favourites are pruned and their IDs are never reused.

`profiles()` returns bounded search/sort pages; `select_profile(id, revision)`
returns an owned parsed server from that exact snapshot, rejecting a stale page
instead of applying an obsolete ordinal. Schema v2 migrates v1 transactionally
and builds old snapshot indexes lazily. The master key remains unchanged.
[Identity, migration and load checks](docs/validation/2026-11-09-profile-identities.md).

### Routing policy

Both CLIs accept `--policy FILE --policy-mode names|ip-only --probe-port PORT`
together. `names` supports exact/suffix domain rules and a default action; it rejects
CIDR/LAN combinations requiring real DNS. `ip-only` supports CIDR/LAN rules and blocks
domain SOCKS destinations before routing. It does not silently discard domain rules.
Process attribution through local SOCKS and available private-VPN bindings are not yet
proven and fail explicitly. Disabled user/preset rules have no routing effect.

```sh
flock -s "$yonik_build" env CARGO_TARGET_DIR="$yonik_build/target" cargo run --quiet --locked -p yonik-linux --bin yonik-local -- xray --binary /absolute/path/to/xray --sha256 cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1 --server 0 --policy examples/policy-names.json --policy-mode names --probe-port 10809 < local/subscription.txt
```

[Names example](examples/policy-names.json) and [IP-only example](examples/policy-ip-only.json)
use documentation destinations: edit them for your own rules. Schema version 1:
`default_action`, `user_rules`, `preset_rules`, `lan`, `private_networks`, `private_domains`.
Rules have `id`, `action`, optional `enabled` and `conditions` containing `domain`,
`domain_suffix`, `ip_cidr`, `executable_paths` arrays. Группы executable, домена и CIDR соединены через И;
значения внутри каждой группы — через ИЛИ. Пустая группа означает любое значение. User order precedes presets. Protected unavailable
networks/zones precede LAN and user rules. `available: true` is not an authorization
to use a VPN: native compilation requires a future verified NetworkHost binding.

Limits: 2 MiB JSON, 10,000 rules, 100,000 selector values. Unknown/duplicate fields,
duplicate IDs within a group and invalid names/CIDRs fail. Policy names normalize IDNA,
case and the root dot; the native SOCKS ingress accepts canonical ASCII/punycode names.
Raw Unicode/root-dot/invalid wire names are rejected to prevent fallback around rules.

The separate health listener requires a random 256-bit password held only by the host
and sensitive compiled config. Ordinary applications cannot use it anonymously to bypass
rules. HTTPS checks always select proxy, even with default DIRECT/BLOCK. Known protected
probe addresses/zones are rejected before sending a request. No system routes/DNS change.

The portable evaluator covers the D-01…D-07 decision cases. Native mixed domain/CIDR
execution is still gated: a reproducible pinned Xray `IPOnDemand` SERVFAIL case falls
through to a younger domain rule. This is not accepted as the required fail-closed behavior.

```sh
flock -s "$yonik_build" env TMPDIR="$yonik_build" python tools/policy_traffic.py "$yonik_build/target/release/yonik-compile" "$yonik_build/target/release/yonik-local" /absolute/path/to/xray /absolute/path/to/sing-box
flock -s "$yonik_build" env TMPDIR="$yonik_build" python tools/dns_policy_gap.py /absolute/path/to/xray
```

The second command intentionally reproduces an upstream semantic gap using synthetic
data; its exit 0 does not mean G-DNS passes. [Policy evidence and limitations](docs/validation/2026-11-09-policy-routing.md).

### Documentation and license

- [Requirements, architecture and roadmap (Russian)](docs/specs/README.md)
- [Initial implementation plan (Russian)](docs/superpowers/plans/2026-11-09-linux-foundation.md)
- [GNU GPL v3.0](LICENSE); SPDX variant and dependency notices remain a release prerequisite.
