"""Настоящий Qt/DesktopHost: pinned core, loopback, явный журнал и reap."""
from __future__ import annotations

import hashlib
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


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    engines = Path(sys.argv[2]).resolve(strict=True)
    output = Path(sys.argv[3]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    pins = {
        "xray": ("xray-26.10.31", "cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1"),
        "sing-box": ("sing-box-1.14.4", "1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a"),
    }
    for engine, (directory, digest) in pins.items():
        assert hashlib.sha256((engines / directory / engine).read_bytes()).hexdigest() == digest
    with tempfile.TemporaryDirectory(prefix="yonik-logs-native-") as temporary:
        root = Path(temporary)
        bus = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--print-address=1"], stdout=subprocess.PIPE, text=True)
        try:
            assert bus.stdout is not None
            assert select.select([bus.stdout], [], [], 5)[0]
            address = bus.stdout.readline().strip()
            os.environ.update(DBUS_SYSTEM_BUS_ADDRESS=address, DBUS_SESSION_BUS_ADDRESS=address)
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
                    with https_server(work, "health", 0, "127.0.0.1") as https, peer(engines / directory / engine, engine, work, port=port, target_ports="1-65535"):
                        steps = [
                            {"when": {"ready": True}, "command": {"command": "set_engine", "engine": engine}},
                            {"when": {"engine": engine}, "command": {"command": "add_source", "name": "Fixture", "url": f"http://127.0.0.1:{server.server_port}/", "local_exception": True, "route": "direct"}},
                            {"when": {"sources_count": 1, "busy": False}, "command": {"command": "refresh"}},
                            {"when": {"profiles_count": 1, "busy": False}, "command": {"command": "select_profile", "id": 1, "revision": 1}},
                            {"when": {"selected_profile": 1}, "command": {"command": "set_probe_target", "url": f"https://127.0.0.1:{https.server_port}/", "expected_status": 204}},
                            {"when": {"probe_custom": True}, "command": {"command": "connect"}},
                            {"when": {"status": "Limited"}, "command": {"command": "stop"}},
                            ui("click", "settingsButton", when={"status": "Disconnected", "can_stop": False}),
                            ui("click", "settingsDiagnosticsButton"),
                            ui("click", "diagnosticsLogsTab"),
                            ui("click", "logsRefresh"),
                            ui("key", "logsRefresh", key="Tab", expect={"logsRows": {"count": 6}, "logsExportText": {"text": {"contains": "CleanupConfirmed"}}}, capture="logs.png"),
                            ui("text", "logsDestination", value=str(work / "events.txt")),
                            ui("click", "logsSave"),
                            ui("key", "logsRefresh", key="Tab", expect={"logsSave": {"enabled": True}}),
                            ui("click", "logsRefresh"),
                            ui("clipboard", value="save-refusal-canary"),
                            ui("click", "logsSave", expect={"logsCopy": {"enabled": True}}),
                            ui("key", "logsRefresh", key="Tab", expect={"logsSave": {"enabled": True}, "clipboard": {"text": "save-refusal-canary"}}),
                            ui("click", "logsRefresh"),
                            ui("clipboard", value="FR16 clipboard canary"),
                            {"when": {}, "command": {"command": "logs_read", "after": "SECRET-invalid", "source": "all", "request_id": "99"}},
                            ui("key", "logsRefresh", key="Tab", expect={"clipboard": {"text": "FR16 clipboard canary"}}),
                            {"when": {}, "command": {"command": "logs_read", "after": "0", "source": "unknown", "request_id": "100"}},
                            ui("key", "logsRefresh", key="Tab", expect={"clipboard": {"text": "FR16 clipboard canary"}}),
                            ui("click", "logsCopy"),
                            ui("key", "logsRefresh", key="Tab", expect={"clipboard": {"text": {"contains": "CleanupConfirmed"}}}),
                            {"when": {}, "command": {"command": "logs_read", "after": "0", "source": "engine", "request_id": "99"}},
                            ui("key", "logsRefresh", key="Tab", expect={"logsRows": {"count": 6}, "logsExportText": {"text": {"contains": "StartRequested"}}, "clipboard": {"text": {"contains": "CleanupConfirmed"}}}),
                            {"when": {}, "command": {"command": "set_language", "language": "en"}},
                            ui("key", "logsRefresh", key="Tab", expect={"logsCopy": {"text": "Copy page"}}),
                            ui("key", "logsSource", key="Down"),
                            ui("key", "logsRefresh", key="Tab", expect={"logsCopy": {"enabled": False}}),
                            ui("click", "logsRefresh"),
                            ui("key", "logsRefresh", key="Tab", expect={"logsRows": {"count": 4}, "logsExportText": {"text": {"contains": "StartRequested"}}}),
                            ui("key", "logsSource", key="Down"),
                            ui("key", "logsRefresh", key="Tab", expect={"logsCopy": {"enabled": False}}),
                            ui("click", "logsRefresh"),
                            ui("key", "logsRefresh", key="Tab", expect={"logsRows": {"count": 2}, "logsExportText": {"text": {"contains": "ProcessExited"}}}),
                            ui("click", "logsNext"),
                            ui("key", "logsRefresh", key="Tab", expect={"logsRows": {"count": 0}, "logsExportText": {"text": {"contains": "cursor=6"}}}),
                            ui("click", "logsRefresh"),
                            ui("key", "logsRefresh", key="Tab", expect={"logsRows": {"count": 2}}),
                            ui("click", "homeButton"),
                            ui("click", "homeButton"),
                            {"when": {}, "command": {"command": "connect"}},
                            {"when": {"status": "Limited"}, "command": {"command": "stop"}},
                            ui("click", "settingsButton", when={"status": "Disconnected", "can_stop": False}),
                            ui("click", "settingsDiagnosticsButton"),
                            ui("click", "diagnosticsLogsTab"),
                            ui("key", "logsRefresh", key="Tab", expect={"logsRows": {"count": 0}, "logsCopy": {"enabled": False}}),
                            ui("click", "logsRefresh"),
                            ui("key", "logsRefresh", key="Tab", expect={"logsRows": {"count": 12}}),
                            {"when": {}, "command": {"command": "shutdown"}},
                        ]
                        execute(binary, work, steps, evidence, "1", engines=engines)
                        exported = (work / "events.txt").read_text()
                        assert "CleanupConfirmed" in exported
                        assert (work / "events.txt").stat().st_mode & 0o777 == 0o600
                        assert len(exported) < 65536
                        (evidence / "events.txt").write_text(exported)
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
