"""P02 SHORT: actual GUI и byte-identical engine-only, own controlled fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine_host import https_server, peer  # noqa: E402


def digest(path: Path) -> str:
    """Хешировать реальный artifact."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def port() -> int:
    """Выбрать свободный loopback порт для собственной fixture."""
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        return reserve.getsockname()[1]


def descendants(pid: int) -> set[int]:
    """Обойти только потомков известного собственного процесса."""
    result: set[int] = set()
    for task in Path(f"/proc/{pid}/task").iterdir():
        result.update(map(int, (task / "children").read_text().split()))
    for child in list(result):
        result.update(descendants(child))
    return result


def sample(pid: int) -> dict:
    """Снять process identity и ресурсы без kernel probes."""
    root = Path(f"/proc/{pid}")
    stat = (root / "stat").read_text().rsplit(") ", 1)[1].split()
    rollup = {
        line.split(":")[0]: int(line.split()[1])
        for line in (root / "smaps_rollup").read_text().splitlines()[1:]
    }
    status = (root / "status").read_text().splitlines()
    switches = {
        line.split(":")[0]: int(line.split()[1])
        for line in status
        if "ctxt_switches:" in line
    }
    return {
        "pid": pid,
        "descendants": sorted(descendants(pid)),
        "starttime": stat[19],
        "cpu_ticks": int(stat[11]) + int(stat[12]),
        "pss_kib": rollup["Pss"],
        "private_dirty_kib": rollup["Private_Dirty"],
        "fd": len(list((root / "fd").iterdir())),
        "threads": len(list((root / "task").iterdir())),
        "main_thread_context_switches_proxy_not_wakeups": switches,
        "wakeups": None,
        "wakeups_reason": "Без kernel tracing /proc не содержит точного per-process wakeup count; context switches опубликованы только как proxy.",
        "namespaces": {
            n: os.readlink(root / "ns" / n) for n in ["pid", "user", "net", "mnt"]
        },
    }


def terminate_process(process: subprocess.Popen, timeout: float = 5) -> None:
    """Остановить и reap собственного child, включая игнорирование SIGTERM."""
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)


def terminate_pidfd(descriptor: int, timeout: float = 5) -> None:
    """Подтвердить exit точного engine, затем оставить reap его родителю."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if select.select([descriptor], [], [], 0)[0]:
            return
        try:
            signal.pidfd_send_signal(descriptor, sig)
        except ProcessLookupError:
            return
        if select.select([descriptor], [], [], timeout)[0]:
            return
    raise TimeoutError("Owned engine did not exit after SIGKILL")


def validate_group(current: list[dict], reference: list[dict]) -> None:
    """Исключить подмену identity и неучтённого потомка в каждом sample."""
    expected = {row["pid"]: row for row in reference}
    actual = {row["pid"]: row for row in current}
    if len(actual) != len(current) or set(actual) != set(expected):
        raise RuntimeError("Product group membership changed")
    for pid, row in actual.items():
        before = expected[pid]
        if (
            row["starttime"] != before["starttime"]
            or row["namespaces"] != before["namespaces"]
            or set(row["descendants"]) != set(before["descendants"])
            or not set(row["descendants"]).issubset(set(expected) - {pid})
        ):
            raise RuntimeError("Product identity/descendants changed or unaccounted")


def require_gui_tls_refusal(state: dict, requested: bool) -> None:
    """Принять только actual GUI TLS refusal до отправки HTTPS body."""
    if (
        state.get("status") != "Limited"
        or (state.get("probe_result") or {}).get("kind") != "tls"
        or requested
    ):
        raise RuntimeError("Actual GUI TLS-negative oracle failed")


class Control:
    """Event-driven закрытый протокол, без периодического GUI polling."""

    def __init__(self, channel: socket.socket, output: Path) -> None:
        self.channel = channel
        self.pending = b""
        self.last: dict = {}
        self.events = output.open("w")

    def send(self, name: str) -> None:
        self.channel.sendall(name.encode() + b"\n")

    def wait(self, predicate: Callable[[dict], bool], timeout: float = 30) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            if b"\n" in self.pending:
                line, self.pending = self.pending.split(b"\n", 1)
                record = json.loads(line)
                self.events.write(json.dumps(record, ensure_ascii=False) + "\n")
                self.events.flush()
                self.last = record
                if predicate(record):
                    return record
                if record["state"].get("closed"):
                    raise RuntimeError("GUI закрылся до ожидаемого ACK")
            else:
                self.channel.settimeout(max(0.001, deadline - time.monotonic()))
                if time.monotonic() >= deadline:
                    raise TimeoutError("ACK deadline: " + json.dumps(self.last))
                data = self.channel.recv(65536)
                if not data:
                    raise RuntimeError("GUI control EOF")
                self.pending += data
                if len(self.pending) > 2_000_000:
                    raise RuntimeError("GUI event bound")

    def state(self, predicate: Callable[[dict], bool], timeout: float = 30) -> dict:
        return self.wait(lambda r: predicate(r["state"]), timeout)["state"]


@contextmanager
def gui(
    binary: Path,
    observer: Path,
    engines: Path,
    output: Path,
    peer_port: int,
    health_port: int,
    socks_port: int,
    ca: Path,
) -> Iterator[tuple]:
    """Actual product GUI с real private Secret Service и внешней SNI fixture."""
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / "pipes").mkdir(mode=0o700)
    processes = []
    logs = []
    channel, child = socket.socketpair()
    control = Control(channel, output / "events.jsonl")
    with tempfile.TemporaryDirectory(prefix="p02-") as temporary:
        root = Path(temporary)
        env = {
            "PATH": os.defpath,
            "LANG": "C.UTF-8",
            "HOME": str(root),
            "XDG_RUNTIME_DIR": str(root),
            "XDG_DATA_HOME": str(root / "data"),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_CACHE_HOME": str(root / "cache"),
            "QT_QPA_PLATFORM": "offscreen",
            "QT_QPA_PLATFORMTHEME": "kde",
            "QT_QUICK_BACKEND": "software",
            "QT_FORCE_STDERR_LOGGING": "1",
            "SSL_CERT_FILE": str(ca),
        }
        conf = root / "bus.conf"
        conf.write_text(
            "<busconfig><type>session</type><listen>unix:tmpdir="
            + str(root)
            + '</listen><policy context="default"><allow send_destination="*"/>'
            '<allow receive_sender="*"/><allow own="*"/></policy></busconfig>'
        )
        owned_engine_handles: list[int] = []
        try:
            bus = subprocess.Popen(
                [
                    "dbus-daemon",
                    "--nofork",
                    "--print-address=1",
                    "--config-file=" + str(conf),
                ],
                stdout=subprocess.PIPE,
                env=env,
            )
            processes.append(bus)
            assert bus.stdout is not None
            if not select.select([bus.stdout], [], [], 5)[0]:
                raise TimeoutError("bus startup")
            address = bus.stdout.readline().decode().strip()
            env.update(
                DBUS_SESSION_BUS_ADDRESS=address, DBUS_SYSTEM_BUS_ADDRESS=address
            )
            rd, wr = os.pipe()
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(root / "environment"))
                listener.listen(1)
                log = (output / "secret-service.log").open("wb")
                logs.append(log)
                service = subprocess.Popen(
                    ["ksecretd", "--pam-login", str(rd), str(listener.fileno())],
                    env=env | {"PAM_KWALLET5_LOGIN": "1"},
                    pass_fds=(rd, listener.fileno()),
                    stdout=log,
                    stderr=log,
                )
                processes.append(service)
                os.close(rd)
                os.write(wr, os.urandom(56))
                os.close(wr)
                with socket.socket(socket.AF_UNIX) as sender:
                    sender.connect(str(root / "environment"))
            tray_log = (output / "tray.log").open("wb")
            logs.append(tray_log)
            tray = subprocess.Popen(
                [sys.executable, str(Path(__file__).with_name("tray_fixture.py"))],
                env=env,
                stdout=subprocess.PIPE,
                stderr=tray_log,
            )
            processes.append(tray)
            assert tray.stdout is not None
            if (
                not select.select([tray.stdout], [], [], 5)[0]
                or tray.stdout.readline().strip() != b"READY"
            ):
                raise RuntimeError("SNI startup")
            log = (output / "gui.log").open("wb")
            logs.append(log)
            env.update(
                P02_CAPTURE_ROOT=str(output / "pipes"),
                P02_CONTROL_FD=str(child.fileno()),
                P02_PEER_PORT=str(peer_port),
                P02_HEALTH_PORT=str(health_port),
                P02_BACKUP=str(root / "backup.sqlite"),
                LD_PRELOAD=str(observer),
            )
            app = subprocess.Popen(
                [
                    str(binary),
                    "--data-dir",
                    str(root / "app"),
                    "--engine-dir",
                    str(engines),
                    "--listen-port",
                    str(socks_port),
                ],
                pass_fds=(child.fileno(),),
                env=env,
                stdout=log,
                stderr=log,
            )
            processes.append(app)
            child.close()
            control.wait(
                lambda r: (
                    r["state"].get("ready") is True and r["tray_available"] is True
                )
            )
            # Owner PID real Secret Service фиксируется через bus, без чтения секретов.
            owner = subprocess.run(
                [
                    "gdbus",
                    "call",
                    "--session",
                    "--dest",
                    "org.freedesktop.DBus",
                    "--object-path",
                    "/org/freedesktop/DBus",
                    "--method",
                    "org.freedesktop.DBus.GetConnectionUnixProcessID",
                    "org.freedesktop.secrets",
                ],
                env=env,
                capture_output=True,
                timeout=5,
                check=True,
            )
            if str(service.pid) not in owner.stdout.decode():
                raise RuntimeError("private SecretService owner mismatch")
            (output / "infrastructure.json").write_text(
                json.dumps(
                    {
                        "bus": bus.pid,
                        "secret_service": service.pid,
                        "tray_fixture": tray.pid,
                        "sampler": os.getpid(),
                        "product_gui": app.pid,
                    }
                )
            )
            expected_qml = digest(
                Path(__file__).resolve().parents[2]
                / "crates/yonik-desktop/qml/Main.qml"
            )
            if os.environ.get("P02_NEGATIVE_QRC_CANARY") == "1":
                expected_qml = "0" * 64
            if (
                f"P02 MAIN_SHA256 {expected_qml}"
                not in (output / "gui.log").read_text()
            ):
                raise RuntimeError("actual qrc source hash mismatch")
            if control.last.get("bridge_class") != "yonik::DesktopBridge":
                raise RuntimeError("actual bridge class mismatch")
            yield app, control, owned_engine_handles
            control.send("quit")
            control.state(lambda s: s.get("closed") is True)
            app.wait(timeout=10)
            if app.returncode != 0:
                raise RuntimeError("GUI exit nonzero")
            if not select.select([tray.stdout], [], [], 5)[0]:
                raise TimeoutError("actual SNI registration deadline")
            registered = tray.stdout.readline().decode().strip()
            (output / "tray-registration.txt").write_text(registered)
            if not registered.startswith("REGISTERED "):
                raise RuntimeError("actual SNI registration missing")
        finally:
            cleanup_errors = []
            if "app" in locals() and app.poll() is None:
                try:
                    for pid in descendants(app.pid):
                        try:
                            owned_engine_handles.append(os.pidfd_open(pid))
                        except ProcessLookupError:
                            continue
                except OSError as error:
                    cleanup_errors.append("Descendant discovery: " + str(error))
                try:
                    control.send("quit")
                    control.state(lambda s: s.get("closed") is True, 10)
                    app.wait(timeout=10)
                except (
                    OSError,
                    RuntimeError,
                    TimeoutError,
                    subprocess.TimeoutExpired,
                ) as error:
                    (output / "cleanup-fallback.txt").write_text(str(error))
            channel.close()
            child.close()
            try:
                control.events.close()
            except OSError as error:
                cleanup_errors.append("Event log close: " + str(error))
            for descriptor in owned_engine_handles:
                try:
                    terminate_pidfd(descriptor)
                except (OSError, TimeoutError) as error:
                    cleanup_errors.append(str(error))
                finally:
                    os.close(descriptor)
            for process in reversed(processes):
                try:
                    terminate_process(process)
                except (OSError, subprocess.TimeoutExpired) as error:
                    cleanup_errors.append(str(error))
            for log in logs:
                log.close()
            if cleanup_errors:
                raise RuntimeError("Incomplete owned cleanup: " + repr(cleanup_errors))


def prepare(control: Control, core: str) -> None:
    """Production backup → import → review → approve → select, без key injection."""
    control.send("backup")
    control.state(lambda s: (s.get("maintenance_ack") or {}).get("phase") == "complete")
    control.send("prepareSynthetic")
    control.state(lambda s: isinstance(s.get("pending"), dict))
    control.send("approveSynthetic")
    control.state(
        lambda s: (
            s.get("source_id") is not None
            and not s.get("busy")
            and not s.get("pending")
        )
    )
    control.send("selectSynthetic")
    control.state(lambda s: s.get("selected_profile") is not None)
    if control.last["state"].get("engine") != core:
        control.send("selectCore:" + core)
        control.state(lambda s: s.get("engine") == core)
    control.send("healthTarget")
    control.state(lambda s: s.get("probe_custom") is True)


def capture(
    app: subprocess.Popen, core_binary: Path, output: Path, handles: list[int]
) -> tuple[int, bytes]:
    """Успешно переданные stdin pipe bytes и actual executable active engine."""
    children = descendants(app.pid)
    if len(children) != 1:
        raise RuntimeError(f"Ожидался один active engine, найдены {children}")
    pid = children.pop()
    handles.append(os.pidfd_open(pid))
    actual = Path(f"/proc/{pid}/exe")
    if digest(actual) != digest(core_binary):
        raise RuntimeError("actual engine ELF pin mismatch")
    stdin_target = os.readlink(f"/proc/{pid}/fd/0")
    if not stdin_target.startswith("pipe:["):
        raise RuntimeError("expected source-bound LocalSession stdin pipe")
    inode = int(stdin_target[6:-1])
    config = (output / "pipes" / f"pipe-{inode}.bin").read_bytes()
    if len(config) > 1_000_000 or not config:
        raise RuntimeError("config bytes bound")
    json.loads(config)
    (output / "actual-config.json").write_bytes(config)
    (output / f"actual-config-{pid}.json").write_bytes(config)
    (output / f"engine-binding-{pid}.json").write_text(
        json.dumps(
            {
                "pid": pid,
                "stdin_pipe": stdin_target,
                "identity": sample(pid),
                "exe_sha256": digest(actual),
                "config_sha256": hashlib.sha256(config).hexdigest(),
                "cmdline": Path(f"/proc/{pid}/cmdline")
                .read_bytes()
                .decode()
                .split("\0"),
            }
        )
    )
    return pid, config


def stop(control: Control, pid: int, socks: int) -> None:
    """Stop ACK, pidfd readiness и повторный bind фактического SOCKS port."""
    with ExitStack() as stack:
        descriptor = os.pidfd_open(pid)
        stack.callback(os.close, descriptor)
        control.send("stop")
        control.state(
            lambda s: s.get("status") == "Disconnected" and not s.get("can_stop")
        )
        if not select.select([descriptor], [], [], 5)[0]:
            raise RuntimeError("engine not exited after Stop")
        with socket.socket() as rebound:
            rebound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            rebound.bind(("127.0.0.1", socks))


def idle(pids: list[int], seconds: int, output: Path, fixture: object) -> dict:
    """Внешний sampler: baseline и samples раз в 30 секунд, без proxy traffic."""
    fixture.requested.clear()
    rows = []
    with ExitStack() as stack:
        # Держим те же pidfd весь интервал; exit не скрывается повторным PID.
        descriptors = []
        for pid in pids:
            descriptor = os.pidfd_open(pid)
            stack.callback(os.close, descriptor)
            descriptors.append(descriptor)
        reference = [sample(pid) for pid in pids]
        validate_group(reference, reference)
        if select.select(descriptors, [], [], 0)[0]:
            raise RuntimeError("Product exited during baseline")
        started = time.monotonic()
        deadline = started + seconds
        rows.append({"elapsed_s": 0.0, "processes": reference})
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if select.select(descriptors, [], [], min(30, remaining))[0]:
                raise RuntimeError("Product exited during idle")
            processes = [sample(pid) for pid in pids]
            validate_group(processes, reference)
            if select.select(descriptors, [], [], 0)[0]:
                raise RuntimeError("Product exited during sample")
            rows.append(
                {"elapsed_s": time.monotonic() - started, "processes": processes}
            )
            (output / "samples.json").write_text(json.dumps(rows, indent=2))
    if fixture.requested.is_set():
        raise RuntimeError("unexpected HTTPS fixture traffic during idle")
    before, after = rows[0]["processes"], rows[-1]["processes"]
    hz = os.sysconf("SC_CLK_TCK")
    return {
        "duration_s": rows[-1]["elapsed_s"],
        "cpu_s": sum(
            b["cpu_ticks"] - a["cpu_ticks"] for a, b in zip(before, after, strict=True)
        )
        / hz,
        "pss_end_kib": sum(p["pss_kib"] for p in after),
        "private_dirty_end_kib": sum(p["private_dirty_kib"] for p in after),
        "group_pids": pids,
        "sampler_outside_group": os.getpid(),
        "wakeups": None,
        "wakeups_reason": before[0]["wakeups_reason"],
    }


def curl_probe(socks: int, url: str, ca: Path, success: bool, output: Path) -> None:
    """Отказной/положительный HTTPS контроль только через actual SOCKS."""
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        "5",
        "--noproxy",
        "",
        "--proxy",
        f"socks5h://127.0.0.1:{socks}",
        "--cacert",
        str(ca),
        url,
    ]
    result = subprocess.run(command, capture_output=True, timeout=8)
    output.write_text(
        json.dumps(
            {
                "command": command,
                "returncode": result.returncode,
                "stderr": result.stderr.decode(errors="replace"),
            }
        )
    )
    if (result.returncode == 0) != success:
        raise RuntimeError("HTTPS route control mismatch")


def engine_only(
    core: str,
    core_binary: Path,
    config: bytes,
    out: Path,
    socks: int,
    health: int,
    ca: Path,
    fixture: object,
    seconds: int,
) -> dict:
    """Запустить standalone с точно переданными production bytes и проверить cleanup."""
    out.mkdir()
    (out / "actual-config.json").write_bytes(config)
    with (out / "actual-config.json").open("rb") as source:
        target = "stdin:" if core == "xray" else "/dev/stdin"
        engine = subprocess.Popen(
            [str(core_binary), "run", "-c", target],
            stdin=source,
            env={"LANG": "C", "SSL_CERT_FILE": str(ca)},
            process_group=0,
            cwd="/",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    try:
        # Только health warmup до начала idle.
        from engine_compile import wait_listener

        wait_listener(engine, socks)
        curl_probe(
            socks,
            f"https://127.0.0.1:{health}/",
            ca,
            True,
            out / "health.json",
        )
        with Path(f"/proc/{engine.pid}/fd/0").open("rb") as actual:
            if os.pread(actual.fileno(), 1_000_001, 0) != config:
                raise RuntimeError("engine-only actual stdin mismatch")
        if digest(Path(f"/proc/{engine.pid}/exe")) != digest(core_binary):
            raise RuntimeError("engine-only ELF mismatch")
        summary = idle([engine.pid], seconds, out, fixture)
        if descendants(engine.pid):
            raise RuntimeError("unexpected engine descendants")
    finally:
        terminate_process(engine, timeout=10)
    with socket.socket() as rebound:
        rebound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rebound.bind(("127.0.0.1", socks))
    return summary


def campaign(args: argparse.Namespace) -> None:
    """Сначала oracle; только после обеих core-канареек разрешены long runs."""
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (args.output / "run.json").write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "starttime": sample(os.getpid())["starttime"],
                "deadline_unix": time.time() + 12000,
                "terminal_files": ["result.json", "failure.json"],
            }
        )
    )
    metadata_path = (
        Path(__file__).resolve().parents[2]
        / "packaging/licenses/linux-composition.json"
    )
    metadata = json.loads(metadata_path.read_text())
    pins = {}
    for relative in ["sing-box-1.14.4/sing-box", "xray-26.10.31/xray"]:
        expected = metadata["cores"][relative]["sha256"]
        actual = digest(args.engines / relative)
        if actual != expected:
            raise RuntimeError("composition pin mismatch: " + relative)
        pins[relative] = actual
    binding = {
        "pins": pins,
        "composition_sha256": digest(metadata_path),
        "build_profile": "dev/unoptimized debuginfo; not release budget acceptance",
        "binary": str(args.binary),
        "binary_sha256": digest(args.binary),
        "observer_sha256": digest(args.observer),
        "seconds": args.seconds,
        "repeats": args.repeats,
        "scope": "LocalSocks/no-app-rules/offscreen actual Qt GUI/private SNI; not physical Plasma/energy/TUN",
        "source_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
    }
    (args.output / "binding.json").write_text(json.dumps(binding, indent=2))
    summaries = []
    with (
        tempfile.TemporaryDirectory(prefix="p02-fixture-") as temporary,
        ExitStack() as stack,
    ):
        root = Path(temporary)
        fixture = stack.enter_context(https_server(root, "health", 0, "127.0.0.1"))
        stack.enter_context(https_server(root, "untrusted", 0, "127.0.0.1"))
        health = fixture.server_port
        trusted_ca = root / "health.ca.pem"
        wrong_ca = root / "untrusted.ca.pem"
        peer_port, socks = port(), port()
        peer_binary = args.engines / "sing-box-1.14.4" / "sing-box"
        configs: dict[str, bytes] = {}
        for core, directory in [
            ("sing-box", "sing-box-1.14.4"),
            ("xray", "xray-26.10.31"),
        ]:
            core_binary = args.engines / directory / core
            # Это actual GUI health client с неверным CA, не curl control.
            negative_out = args.output / (core + "-gui-tls-negative")
            with gui(
                args.binary,
                args.observer,
                args.engines,
                negative_out,
                peer_port,
                health,
                socks,
                wrong_ca,
            ) as (app, control, handles):
                prepare(control, core)
                with peer(peer_binary, "sing-box", root, peer_port):
                    fixture.requested.clear()
                    control.send("connect")
                    denied = control.state(
                        lambda state: state.get("status") in ("Connected", "Limited")
                    )
                    require_gui_tls_refusal(denied, fixture.requested.is_set())
                    denied_pid, _ = capture(app, core_binary, negative_out, handles)
                    (negative_out / "actual-gui-tls-negative.json").write_text(
                        json.dumps(denied)
                    )
                    stop(control, denied_pid, socks)
            out = args.output / (core + "-oracle")
            with gui(
                args.binary,
                args.observer,
                args.engines,
                out,
                peer_port,
                health,
                socks,
                trusted_ca,
            ) as (app, control, handles):
                prepare(control, core)
                with peer(peer_binary, "sing-box", root, peer_port):
                    fixture.requested.clear()
                    control.send("connect")
                    control.state(lambda s: s.get("status") == "Connected")
                    if not fixture.requested.is_set():
                        raise RuntimeError(
                            "actual GUI health did not reach HTTPS fixture"
                        )
                    pid, config = capture(app, core_binary, out, handles)
                    curl_probe(
                        socks,
                        f"https://127.0.0.1:{health}/",
                        wrong_ca,
                        False,
                        out / "strict-tls-negative.json",
                    )
                    curl_probe(
                        socks,
                        f"https://127.0.0.1:{health}/",
                        trusted_ca,
                        True,
                        out / "strict-tls-restored.json",
                    )
                    stop(control, pid, socks)
                fixture.requested.clear()
                control.send("connect")
                control.state(lambda s: s.get("status") == "Limited")
                denied_pid, denied_config = capture(app, core_binary, out, handles)
                if fixture.requested.is_set():
                    raise RuntimeError("peer-negative control differs/reaches fixture")
                stop(control, denied_pid, socks)
                with peer(peer_binary, "sing-box", root, peer_port):
                    control.send("connect")
                    control.state(lambda s: s.get("status") == "Connected")
                    restored, restored_config = capture(app, core_binary, out, handles)
                    json.loads(restored_config)
                    control.send("hide")
                    control.wait(lambda r: not r["visible"] and r["tray_available"])
                    idle([app.pid, restored], 2, out, fixture)
                    stop(control, restored, socks)
                    if descendants(app.pid):
                        raise RuntimeError("children after Stop")
                configs[core] = config
                (out / "oracle.json").write_text(
                    json.dumps(
                        {
                            "outcome": "SHORT_ORACLE_PASS_NOT_900S",
                            "config_sha256": hashlib.sha256(config).hexdigest(),
                        }
                    )
                )
        with peer(peer_binary, "sing-box", root, peer_port):
            for core, directory in [
                ("sing-box", "sing-box-1.14.4"),
                ("xray", "xray-26.10.31"),
            ]:
                engine_only(
                    core,
                    args.engines / directory / core,
                    configs[core],
                    args.output / (core + "-baseline-oracle"),
                    socks,
                    health,
                    trusted_ca,
                    fixture,
                    2,
                )
        if args.oracle_only:
            return
        if args.seconds != 900 or args.repeats < 3:
            raise ValueError("SHORT gate требует 900 секунд и >=3 повтора")
        # Одна и та же fixture и один и тот же peer/core/config для обеих групп.
        with peer(peer_binary, "sing-box", root, peer_port):
            for core, directory in [
                ("sing-box", "sing-box-1.14.4"),
                ("xray", "xray-26.10.31"),
            ]:
                core_binary = args.engines / directory / core
                for repeat in range(args.repeats):
                    order = ["full", "engine"]
                    for group in order:
                        out = args.output / f"{core}-{repeat + 1}-{group}"
                        if group == "full":
                            with gui(
                                args.binary,
                                args.observer,
                                args.engines,
                                out,
                                peer_port,
                                health,
                                socks,
                                trusted_ca,
                            ) as (app, control, handles):
                                prepare(control, core)
                                control.send("connect")
                                control.state(lambda s: s.get("status") == "Connected")
                                pid, config = capture(app, core_binary, out, handles)
                                configs[core] = config
                                control.send("hide")
                                control.wait(
                                    lambda r: not r["visible"] and r["tray_available"]
                                )
                                summary = idle(
                                    [app.pid, pid], args.seconds, out, fixture
                                )
                                if descendants(app.pid) != {pid}:
                                    raise RuntimeError("unexpected product descendants")
                                stop(control, pid, socks)
                        else:
                            summary = engine_only(
                                core,
                                core_binary,
                                configs[core],
                                out,
                                socks,
                                health,
                                trusted_ca,
                                fixture,
                                args.seconds,
                            )
                        summary.update(core=core, repeat=repeat + 1, group=group)
                        (out / "summary.json").write_text(json.dumps(summary, indent=2))
                        summaries.append(summary)
                        (args.output / "progress.json").write_text(
                            json.dumps(summaries, indent=2)
                        )
    variance = {}
    for core in ["sing-box", "xray"]:
        variance[core] = {}
        for group in ["engine", "full"]:
            rows = [r for r in summaries if r["core"] == core and r["group"] == group]
            variance[core][group] = {
                metric: {
                    "min": min(r[metric] for r in rows),
                    "max": max(r[metric] for r in rows),
                    "median": statistics.median(r[metric] for r in rows),
                }
                for metric in ["cpu_s", "pss_end_kib", "private_dirty_end_kib"]
            }
    (args.output / "result.json").write_text(
        json.dumps(
            {"outcome": "MEASURED_SHORT_SCOPE_NOT_ENERGY", "variance": variance},
            indent=2,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("observer", type=Path)
    parser.add_argument("engines", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--oracle-only", action="store_true")
    parser.add_argument("--seconds", type=int, default=900)
    parser.add_argument("--repeats", type=int, default=3)
    options = parser.parse_args()
    for name in ["binary", "observer", "engines", "output"]:
        setattr(options, name, getattr(options, name).resolve())

    def interrupted(signum: int, frame: object) -> None:
        raise TimeoutError(f"Owned campaign interrupted: signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(12000)
    try:
        campaign(options)
    except BaseException as error:
        if options.output.exists():
            (options.output / "failure.json").write_text(
                json.dumps({"outcome": "FAILED_NOT_SHORT_PASS", "error": repr(error)})
            )
        raise
    finally:
        signal.alarm(0)
