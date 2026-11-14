"""Короткий actual-GUI preflight в собственном bus, без изменения host settings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def run(binary: Path, observer: Path, output: Path) -> None:
    """Проверить actual qrc/bridge и доступность private Secret Service."""
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    temporary = tempfile.TemporaryDirectory(prefix="p02-private-")
    root = Path(temporary.name)
    config = root / "bus.conf"
    config.write_text(
        "<busconfig><type>session</type><listen>unix:tmpdir="
        + str(root)
        + '</listen><policy context="default"><allow send_destination="*"/>'
        '<allow receive_sender="*"/><allow own="*"/></policy></busconfig>'
    )
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "QT_QPA_PLATFORMTHEME": "generic"}
    env.update(
        HOME=str(root),
        XDG_RUNTIME_DIR=str(root),
        XDG_DATA_HOME=str(root / "data"),
        XDG_CONFIG_HOME=str(root / "config"),
        XDG_CACHE_HOME=str(root / "cache"),
        QT_QPA_PLATFORM="offscreen",
        QT_QUICK_BACKEND="software",
    )
    processes: list[subprocess.Popen[bytes]] = []
    handles = []
    parent, child = socket.socketpair()
    records: list[dict] = []
    try:
        bus = subprocess.Popen(
            [
                "dbus-daemon",
                "--nofork",
                "--print-address=1",
                "--config-file=" + str(config),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        processes.append(bus)
        assert bus.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(bus.stdout, selectors.EVENT_READ)
            if not selector.select(5):
                raise TimeoutError("private bus startup")
        address = bus.stdout.readline().decode().strip()
        env.update(DBUS_SESSION_BUS_ADDRESS=address, DBUS_SYSTEM_BUS_ADDRESS=address)
        # Собственный случайный hash только для новой private коллекции KSecretD.
        # Реальный daemon создаёт wallet через свой штатный --pam-login путь.
        key_read, key_write = os.pipe()
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(root / "environment"))
        listener.listen(1)
        log = (output / "ksecretd.log").open("wb")
        handles.append(log)
        service = subprocess.Popen(
            ["ksecretd", "--pam-login", str(key_read), str(listener.fileno())],
            env=env | {"PAM_KWALLET5_LOGIN": "1"},
            pass_fds=(key_read, listener.fileno()),
            stdout=log,
            stderr=log,
        )
        processes.append(service)
        os.close(key_read)
        os.write(key_write, os.urandom(56))
        os.close(key_write)
        with socket.socket(socket.AF_UNIX) as environment:
            environment.connect(str(root / "environment"))
        listener.close()
        log = (output / "gui.log").open("wb")
        handles.append(log)
        app_env = env | {
            "LD_PRELOAD": str(observer),
            "P02_CONTROL_FD": str(child.fileno()),
        }
        app = subprocess.Popen(
            [str(binary), "--data-dir", str(root / "app")],
            env=app_env,
            pass_fds=(child.fileno(),),
            stdout=log,
            stderr=log,
        )
        processes.append(app)
        child.close()
        identity = {
            "pid": app.pid,
            "stat": Path(f"/proc/{app.pid}/stat").read_text(),
            "namespaces": {
                n: os.readlink(f"/proc/{app.pid}/ns/{n}")
                for n in ["pid", "user", "net", "mnt"]
            },
        }
        deadline = time.monotonic() + 25
        parent.settimeout(25)
        pending = b""
        requested = False
        while time.monotonic() < deadline:
            parent.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                data = parent.recv(65536)
            except TimeoutError:
                break
            if not data:
                break
            pending += data
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                record = json.loads(line)
                records.append(record)
                if record["state"].get("ready") and not requested:
                    requested = True
                    parent.sendall(b"snapshot\n")
                    deadline = min(deadline, time.monotonic() + 1)
        (output / "events.json").write_text(
            json.dumps(records, ensure_ascii=False, indent=2)
        )
        result = {
            "scope": "private actual-GUI tooling preflight; older ELF, not P02 measurement",
            "binary": str(binary),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "observer_sha256": hashlib.sha256(observer.read_bytes()).hexdigest(),
            "identity": identity,
            "events": len(records),
            "ready": any(r["state"].get("ready") for r in records),
            "runs_900s": 0,
            "resource_variance": None,
        }
        (output / "result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2)
        )
    finally:
        parent.close()
        child.close()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for handle in handles:
            handle.close()
        temporary.cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("observer", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    run(args.binary.resolve(), args.observer.resolve(), args.output.resolve())
