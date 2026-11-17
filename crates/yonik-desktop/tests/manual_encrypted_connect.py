"""Qt manual → encrypted repository → новый GUI → Connect → pinned traffic."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import manual_entry_smoke
from manual_native_traffic import oracle, peer_config

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from desktop_ui_smoke import execute, ui  # noqa: E402
from engine_compile import probe, stop, wait_listener  # noqa: E402
from engine_smoke import links  # noqa: E402
from traffic_echo import (  # noqa: E402
    PAYLOAD_SIZE,
    RESPONSE_PREFIX,
    echo_servers,
    receive_exact,
)


def inspect_core(binary: Path, source: dict, engine: str, gui_pid: int) -> int:
    """Проверить actual stdin config и hash sealed executable собственного ядра."""
    expected_hash = hashlib.sha256(binary.read_bytes()).digest()
    core_pid = None
    observed = Path(os.environ["YONIK_MANUAL_WRITE_OBSERVER"])
    configs = [json.loads(line) for line in observed.read_text().splitlines()]
    assert len(configs) >= 2, "Не наблюдались check/run записи actual config"
    oracle(configs[-1], source, engine)
    assert configs[-1] == configs[-2], "Check/run получили разные config"
    pending = [gui_pid]
    processes = []
    while pending:
        pid = pending.pop()
        process = Path(f"/proc/{pid}")
        processes.append(process)
        try:
            for task in (process / "task").iterdir():
                pending.extend(map(int, (task / "children").read_text().split()))
        except OSError:
            continue
    for process in processes:
        try:
            target = str((process / "exe").readlink())
            if "memfd:yonik-engine" in target:
                if (
                    hashlib.sha256((process / "exe").read_bytes()).digest()
                    == expected_hash
                ):
                    core_pid = int(process.name)
        except (OSError, ProcessLookupError):
            continue
    if core_pid is not None:
        return core_pid
    raise RuntimeError("Actual core config/pinned executable не найдены")


def main() -> None:
    binary, engines, root, evidence = [Path(p).resolve() for p in sys.argv[1:5]]
    assert links() == {"lo"}, "Требуется отдельный network namespace"
    for relative, digest in [
        (
            "xray-26.10.31/xray",
            "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1",
        ),
        (
            "sing-box-1.14.4/sing-box",
            "1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a",
        ),
    ]:
        assert hashlib.sha256((engines / relative).read_bytes()).hexdigest() == digest
    root.mkdir(exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=yonik.test",
            "-addext",
            "subjectAltName=DNS:yonik.test",
            "-keyout",
            str(root / "key.pem"),
            "-out",
            str(root / "certificate.pem"),
        ],
        check=True,
        capture_output=True,
    )
    (root / "empty-roots").mkdir(exist_ok=True)
    os.environ.update(
        SSL_CERT_FILE=str(root / "certificate.pem"),
        SSL_CERT_DIR=str(root / "empty-roots"),
    )
    observer = root / "observer.so"
    subprocess.run(
        [
            "cc",
            "-shared",
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(Path(__file__).with_name("support") / "manual_write_observer.c"),
            "-ldl",
            "-o",
            str(observer),
        ],
        check=True,
    )
    original = subprocess.Popen
    gui_pids = []

    def launch(command: list[str], **kwargs: object) -> subprocess.Popen:
        if command[0] == str(binary):
            command = [*command, "--editor-persistence"]
            environment = dict(kwargs["env"])
            environment["LD_PRELOAD"] = str(observer)
            environment["YONIK_MANUAL_WRITE_OBSERVER"] = str(root / "observed.jsonl")
            kwargs["env"] = environment
        process = original(command, **kwargs)
        if command[0] == str(binary):
            gui_pids.append(process.pid)
        return process

    short = sys.argv[5:] == ["--short"]
    assert not sys.argv[5:] or short, "Неизвестные параметры"
    results = []
    with echo_servers(), patch("desktop_ui_smoke.subprocess.Popen", launch):
        for engine, relative in [
            ("xray", "xray-26.10.31/xray"),
            ("sing-box", "sing-box-1.14.4/sing-box"),
        ][: 1 if short else 2]:
            for transport, protocol in [("ws", "vmess"), ("grpc", "trojan")][
                : 1 if short else 2
            ]:
                source = {"type": protocol, "transport": {"type": transport}, "tls": {}}

                def saved(
                    binary: Path, work: Path, steps: list, output: Path, scale: str
                ) -> None:
                    # Persistence fixture не передаёт screenshot path в Qt.
                    steps = [
                        {
                            key: value
                            for key, value in step.items()
                            if key != "capture_name"
                        }
                        for step in steps
                    ]
                    execute(binary, work, steps, output, scale)
                    database = work / "data/subscriptions.sqlite"
                    assert database.exists()
                    assert b"synthetic-manual-secret" not in database.read_bytes()
                    assert (
                        b"11111111-2222-4333-8444-555555555555"
                        not in database.read_bytes()
                    )
                    for bad in (False, True):
                        label = f"{engine}-{transport}-" + (
                            "wrong-peer" if bad else "valid"
                        )
                        out = evidence / label
                        out.mkdir(exist_ok=True)
                        peer_file = root / "peer.json"
                        peer_file.write_text(json.dumps(peer_config(source, root, bad)))
                        (root / "observed.jsonl").write_text("")
                        os.environ["YONIK_MANUAL_WRITE_OBSERVER"] = str(
                            root / "observed.jsonl"
                        )
                        errors = []
                        pids = []

                        def traffic() -> None:
                            try:
                                deadline = time.monotonic() + 20
                                while time.monotonic() < deadline:
                                    try:
                                        with socket.create_connection(
                                            ("127.0.0.1", 10808), timeout=0.1
                                        ):
                                            break
                                    except OSError:
                                        time.sleep(0.05)
                                pids.append(
                                    inspect_core(
                                        engines / relative, source, engine, gui_pids[-1]
                                    )
                                )
                                # Endpoint доступен и при неверном peer: bypass
                                # обязан провалить отрицательный контроль.
                                payload = os.urandom(PAYLOAD_SIZE)
                                with socket.create_connection(
                                    ("127.0.0.1", 24081), timeout=2
                                ) as direct:
                                    direct.sendall(payload)
                                    assert (
                                        receive_exact(
                                            direct, len(RESPONSE_PREFIX) + len(payload)
                                        )
                                        == RESPONSE_PREFIX + payload
                                    )
                                try:
                                    probe("127.0.0.1", False, timeout=2)
                                except (OSError, ConnectionError):
                                    assert bad, "Положительный echo отказал"
                                else:
                                    assert not bad, "Bypass: wrong peer пропустил echo"
                            except BaseException as error:
                                errors.append(error)

                        with original(
                            [
                                str(engines / "sing-box-1.14.4/sing-box"),
                                "run",
                                "-c",
                                str(peer_file),
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        ) as peer:
                            try:
                                wait_listener(peer, 24443)
                                thread = threading.Thread(target=traffic)
                                thread.start()
                                connect = [
                                    {
                                        "when": {"ready": True},
                                        "command": {
                                            "command": "set_engine",
                                            "engine": engine,
                                        },
                                    },
                                    {
                                        "when": {},
                                        "command": {
                                            "command": "set_listen_port",
                                            "port": 10808,
                                        },
                                    },
                                    ui("click", "serverPickerButton"),
                                    ui(
                                        "click",
                                        "profileSelect_1",
                                        when={"profiles_count": 1},
                                    ),
                                    ui(
                                        "click",
                                        "mainConnectButton",
                                        when={
                                            "selected_profile": 1,
                                            "can_connect": True,
                                        },
                                    ),
                                ]
                                connect += [
                                    ui(
                                        "key",
                                        "mainConnectButton",
                                        key="Tab",
                                        when={"can_stop": True},
                                    )
                                    for _ in range(200)
                                ]
                                connect += [
                                    ui(
                                        "click",
                                        "mainConnectButton",
                                        when={"can_stop": True},
                                    ),
                                    {
                                        "when": {
                                            "status": "Disconnected",
                                            "can_stop": False,
                                        },
                                        "command": {"command": "shutdown"},
                                    },
                                ]
                                execute(
                                    binary, work, connect, out, "1", engines=engines
                                )
                                thread.join(timeout=25)
                                assert not thread.is_alive()
                                if errors:
                                    raise errors[0]
                                assert pids and all(
                                    not Path(f"/proc/{pid}").exists() for pid in pids
                                )
                                with socket.socket() as listener:
                                    listener.setsockopt(
                                        socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
                                    )
                                    listener.bind(("127.0.0.1", 10808))
                                results.append(
                                    {
                                        "case": label,
                                        "closed": True,
                                        "reaped": pids,
                                        "oracle": True,
                                        "direct_endpoint_available": True,
                                        "peer_credentials_valid": not bad,
                                        "actual_writes_sha256": hashlib.sha256(
                                            (root / "observed.jsonl").read_bytes()
                                        ).hexdigest(),
                                        "core_sha256": hashlib.sha256(
                                            (engines / relative).read_bytes()
                                        ).hexdigest(),
                                        "database_sha256": hashlib.sha256(
                                            database.read_bytes()
                                        ).hexdigest(),
                                    }
                                )
                            finally:
                                stop(peer)

                output = evidence / f"{engine}-{transport}-save"
                with (
                    patch.object(manual_entry_smoke, "execute", saved),
                    patch.object(
                        sys,
                        "argv",
                        [
                            __file__,
                            str(binary),
                            str(output),
                            "--controlled-transports",
                            "--only-" + transport,
                        ],
                    ),
                ):
                    manual_entry_smoke.main()
    (evidence / "result.json").write_text(
        json.dumps(
            {
                "results": results,
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
