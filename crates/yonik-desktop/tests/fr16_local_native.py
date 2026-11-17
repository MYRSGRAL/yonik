"""FR16 LocalSocks: actual native startup → DesktopPage/UI/export → Stop, без worker."""

from __future__ import annotations

import hashlib
import json
import os
import select
import socket
import subprocess
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from desktop_smoke import Fixture
from desktop_ui_smoke import execute, ui
from engine_compile import UUID
from engine_host import https_server, peer


def require_native(pages: list[dict], code: str, body: str) -> list[dict]:
    rows = [row for page in pages for row in page["events"] if row["code"] == code]
    assert rows, "Нет original native event"
    assert all(
        row["source"] == "engine"
        and row.get("session_id")
        and row.get("generation")
        and body in row["technical_details"]
        for row in rows
    )
    for page in pages:
        for row in page["events"]:
            if row.get("technical_details"):
                assert row["technical_details"] in page["export"], (
                    "Разошёлся body UI/export"
                )
    return rows


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    engines = Path(sys.argv[2]).resolve(strict=True)
    output = Path(sys.argv[3]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    pins = {
        "xray": (
            "xray-26.10.31",
            "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1",
        ),
        "sing-box": (
            "sing-box-1.14.4",
            "1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a",
        ),
    }
    for engine, (directory, digest) in pins.items():
        assert (
            hashlib.sha256((engines / directory / engine).read_bytes()).hexdigest()
            == digest
        )
    with tempfile.TemporaryDirectory(
        prefix="yonik-logs-native-", dir=output
    ) as temporary:
        root = Path(temporary)
        bus = subprocess.Popen(
            ["dbus-daemon", "--session", "--nofork", "--print-address=1"],
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert bus.stdout is not None
            assert select.select([bus.stdout], [], [], 5)[0]
            address = bus.stdout.readline().strip()
            os.environ.update(
                DBUS_SYSTEM_BUS_ADDRESS=address, DBUS_SESSION_BUS_ADDRESS=address
            )
            for engine, (directory, _) in pins.items():
                work = root / engine
                work.mkdir()
                evidence = output / engine
                evidence.mkdir(exist_ok=True)
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                Fixture.body = f"vless://{UUID}@127.0.0.1:{port}#Fixture".encode()
                server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
                try:
                    with (
                        https_server(work, "health", 0, "127.0.0.1") as https,
                        peer(
                            engines / directory / engine,
                            engine,
                            work,
                            port=port,
                            target_ports="1-65535",
                        ),
                    ):
                        native = (
                            "sing-box started ("
                            if engine == "sing-box"
                            else "Xray 26.10.31 started"
                        )
                        code = (
                            "NativeSingStarted"
                            if engine == "sing-box"
                            else "NativeXrayStarted"
                        )
                        steps = [
                            {
                                "when": {"ready": True},
                                "command": {"command": "set_engine", "engine": engine},
                            },
                            {
                                "when": {"engine": engine},
                                "command": {
                                    "command": "add_source",
                                    "name": "Fixture",
                                    "url": f"http://127.0.0.1:{server.server_port}/",
                                    "local_exception": True,
                                    "route": "direct",
                                },
                            },
                            {
                                "when": {"sources_count": 1, "busy": False},
                                "command": {"command": "refresh"},
                            },
                            {
                                "when": {"profiles_count": 1, "busy": False},
                                "command": {
                                    "command": "select_profile",
                                    "id": 1,
                                    "revision": 1,
                                },
                            },
                            {
                                "when": {"selected_profile": 1},
                                "command": {
                                    "command": "set_probe_target",
                                    "url": f"https://127.0.0.1:{https.server_port}/",
                                    "expected_status": 204,
                                },
                            },
                            {
                                "when": {"probe_custom": True},
                                "command": {"command": "connect"},
                            },
                            ui("click", "settingsButton", when={"status": "Limited"}),
                            ui("click", "settingsDiagnosticsButton"),
                            ui("click", "diagnosticsLogsTab"),
                            ui("click", "logsRefresh"),
                            ui(
                                "key",
                                "logsRefresh",
                                key="Tab",
                                expect={
                                    "logsNativeDetails": {"text": {"contains": native}},
                                    "logsWithheldNotice": {"visible": True},
                                    "logsExportText": {"text": {"contains": native}},
                                },
                                capture="native-ru.png",
                            ),
                            ui("clipboard", value="synthetic-clipboard-canary"),
                            ui("click", "logsCopy"),
                            ui(
                                "key",
                                "logsRefresh",
                                key="Tab",
                                expect={"clipboard": {"text": {"contains": native}}},
                            ),
                            ui(
                                "text",
                                "logsDestination",
                                value=str(work / "events.txt"),
                            ),
                            ui("click", "logsSave"),
                            ui(
                                "key",
                                "logsRefresh",
                                key="Tab",
                                expect={"logsSave": {"enabled": True}},
                            ),
                            {
                                "when": {},
                                "command": {
                                    "command": "set_language",
                                    "language": "en",
                                },
                            },
                            ui(
                                "key",
                                "logsRefresh",
                                key="Tab",
                                expect={
                                    "logsNativeDetails": {
                                        "text": {"contains": "Technical details: "}
                                    },
                                    "logsExportText": {"text": {"contains": native}},
                                },
                                capture="native-en.png",
                            ),
                            ui("key", "logsSource", key="Down"),
                            ui("click", "logsRefresh"),
                            ui(
                                "key",
                                "logsRefresh",
                                key="Tab",
                                expect={
                                    "logsExportText": {
                                        "text": {"contains": "StartRequested"}
                                    }
                                },
                            ),
                            ui("key", "logsSource", key="Down"),
                            ui("click", "logsRefresh"),
                            ui(
                                "key",
                                "logsRefresh",
                                key="Tab",
                                expect={
                                    "logsExportText": {"text": {"contains": native}}
                                },
                            ),
                            {"when": {}, "command": {"command": "stop"}},
                            ui(
                                "click",
                                "logsRefresh",
                                when={"status": "Disconnected", "can_stop": False},
                            ),
                            ui(
                                "key",
                                "logsRefresh",
                                key="Tab",
                                expect={
                                    "logsExportText": {
                                        "text": {"contains": "ProcessExited"}
                                    }
                                },
                            ),
                            {"when": {}, "command": {"command": "shutdown"}},
                        ]
                        execute(binary, work, steps, evidence, "1", engines=engines)
                        exported = (work / "events.txt").read_text()
                        assert native in exported and code in exported
                        assert (work / "events.txt").stat().st_mode & 0o777 == 0o600
                        assert len(exported) < 65536
                        (evidence / "events.txt").write_text(exported)
                        # Smoke trace намеренно metadata-only. Проверяем сам page export,
                        # сохранённый production Page/QML safe-save, не расширяя backend DTO trace.
                        rows = []
                        bodies = {}
                        contexts = {}
                        for line in exported.splitlines():
                            fields = line.split()
                            if fields and fields[0].isdigit() and len(fields) == 4:
                                rows.append(
                                    {
                                        "id": fields[0],
                                        "source": fields[1].lower(),
                                        "code": fields[2],
                                    }
                                )
                            elif line.startswith("technical event="):
                                identity, body = line.removeprefix(
                                    "technical event="
                                ).split(" ", 1)
                                bodies[identity] = body
                            elif line.startswith("context event="):
                                metadata = dict(
                                    field.split("=", 1) for field in fields[1:]
                                )
                                contexts[metadata["event"]] = metadata
                        for row in rows:
                            row["technical_details"] = bodies.get(row["id"])
                            row["session_id"] = contexts.get(row["id"], {}).get(
                                "session"
                            )
                            row["generation"] = contexts.get(row["id"], {}).get(
                                "generation"
                            )
                        pages = [{"events": rows, "export": exported}]
                        native_rows = require_native(pages, code, native)
                        mutants = [
                            [
                                {
                                    **page,
                                    "events": [
                                        r
                                        for r in page["events"]
                                        if not r["code"].startswith("Native")
                                    ],
                                }
                                for page in pages
                            ],
                            [
                                {**page, "export": "mutant: numeric events only"}
                                for page in pages
                            ],
                        ]
                        for mutant in mutants:
                            try:
                                require_native(mutant, code, native)
                            except AssertionError:
                                pass
                            else:
                                raise AssertionError("Недостаточный native oracle")
                        disk = (work / "data/logs/events.log").read_bytes()
                        assert disk and native.encode() not in disk
                        assert any(
                            len(line.split()) == 9
                            and line.split()[3]
                            == (b"7" if engine == "sing-box" else b"9")
                            for line in disk.splitlines()
                        )
                        assert all(len(line) + 1 <= 192 for line in disk.splitlines())
                        (evidence / "events.log").write_bytes(disk)
                        for forbidden in [
                            "CANARY",
                            "\\u001b",
                            "\\u0000",
                            "\\r",
                            "vless://",
                            "--password",
                            "00112233-4455-6677-8899-aabbccddeeff",
                        ]:
                            assert forbidden not in exported
                            assert forbidden.encode() not in disk
                        (evidence / "result.json").write_text(
                            json.dumps(
                                {
                                    "engine": engine,
                                    "native_code": code,
                                    "native_rows": len(native_rows),
                                    "scope": "LocalSocks actual native startup; worker excluded",
                                    "status": "PASS",
                                    "wrapper_only_mutation": "REJECTED",
                                    "numeric_export_only_mutation": "REJECTED",
                                },
                                indent=2,
                            )
                            + "\n"
                        )
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=3)
                    assert not thread.is_alive()
        finally:
            bus.terminate()
            bus.wait(timeout=5)
            if bus.stdout is not None:
                bus.stdout.close()


if __name__ == "__main__":
    main()
