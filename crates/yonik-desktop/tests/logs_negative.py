"""FR16: настоящий Main/LogsView, доверенный Rust control, private D-Bus."""

from __future__ import annotations

import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from desktop_smoke import Fixture
from desktop_tray_smoke import stop_group, wait_exit
from desktop_ui_smoke import ui
from engine_compile import UUID
from engine_host import https_server, peer


def child_pidfds(process: subprocess.Popen) -> list[int]:
    """Только прямые дети потоков собственного GUI; FD удерживает identity."""
    children: set[int] = set()
    for task in Path(f"/proc/{process.pid}/task").iterdir():
        try:
            children.update(int(pid) for pid in (task / "children").read_text().split())
        except FileNotFoundError:
            continue
    # BinarySnapshot запускает закреплённый memfd; comm не обязан быть «xray».
    assert len(children) == 1, "один принадлежащий GUI pinned core"
    descriptors = [os.pidfd_open(pid) for pid in children]
    return descriptors


def main() -> None:
    binary, engines, output = (Path(value).resolve() for value in sys.argv[1:4])
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yonik-fr16-negative-") as temporary:
        root = Path(temporary)
        bus = subprocess.Popen(
            ["dbus-daemon", "--session", "--nofork", "--print-address=1"],
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert bus.stdout is not None and select.select([bus.stdout], [], [], 5)[0]
            address = bus.stdout.readline().strip()
            env = os.environ | {
                "DBUS_SESSION_BUS_ADDRESS": address,
                "DBUS_SYSTEM_BUS_ADDRESS": address,
                "QT_QPA_PLATFORM": "offscreen",
                "QT_QUICK_BACKEND": "software",
                "QT_QUICK_CONTROLS_STYLE": "Basic",
            }
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1", 0))
                port = reserve.getsockname()[1]
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1", 0))
                socks = reserve.getsockname()[1]
            Fixture.body = f"vless://{UUID}@127.0.0.1:{port}#Fixture".encode()
            server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                with (
                    https_server(root, "health", 0, "127.0.0.1") as https,
                    peer(
                        engines / "xray-26.10.31/xray",
                        "xray",
                        root,
                        port=port,
                        target_ports="1-65535",
                    ),
                ):
                    controls: dict[int, str] = {}

                    def command(value: dict, when: dict | None = None) -> dict:
                        return {"when": when or {}, "command": value}

                    steps = [
                        command(
                            {
                                "command": "add_source",
                                "name": "Fixture",
                                "url": f"http://127.0.0.1:{server.server_port}/",
                                "local_exception": True,
                                "route": "direct",
                            },
                            {"ready": True},
                        ),
                        command(
                            {"command": "refresh"}, {"sources_count": 1, "busy": False}
                        ),
                        command(
                            {"command": "select_profile", "id": 1, "revision": 1},
                            {"profiles_count": 1, "busy": False},
                        ),
                        command(
                            {
                                "command": "set_probe_target",
                                "url": f"https://127.0.0.1:{https.server_port}/",
                                "expected_status": 204,
                            },
                            {"selected_profile": 1},
                        ),
                        command({"command": "connect"}, {"probe_custom": True}),
                        ui("click", "settingsButton", when={"status": "Limited"}),
                        ui("click", "settingsDiagnosticsButton"),
                        ui("click", "diagnosticsLogsTab"),
                    ]
                    controls[len(steps) - 2] = "fault"
                    steps += [
                        command(
                            {"command": "stop"}, {"logs_test_stage": "fault_enabled"}
                        ),
                        ui(
                            "click",
                            "logsRefresh",
                            when={"error": "cleanup_failed", "can_stop": True},
                        ),
                        ui(
                            "key",
                            "logsRefresh",
                            key="Tab",
                            expect={
                                "logsExportText": {
                                    "text": {"contains": "CleanupFailed"}
                                },
                                "logsView": {"pending": ""},
                            },
                        ),
                    ]
                    controls[len(steps) - 1] = "release"
                    steps += [
                        command(
                            {"command": "stop"}, {"logs_test_stage": "fault_released"}
                        ),
                        ui("click", "logsRefresh", when={"can_stop": False}),
                        ui(
                            "key",
                            "logsRefresh",
                            key="Tab",
                            expect={
                                "logsExportText": {
                                    "text": {"contains": "CleanupConfirmed"}
                                }
                            },
                        ),
                        command({"command": "connect"}),
                        ui("key", "logsRefresh", key="Tab", when={"status": "Limited"}),
                    ]
                    controls[len(steps) - 1] = "kill"
                    steps += [
                        ui("click", "logsRefresh", when={"can_stop": False}),
                        ui(
                            "key",
                            "logsRefresh",
                            key="Tab",
                            expect={
                                "logsExportText": {
                                    "text": {"contains": "ProcessExited Some(-9)"}
                                }
                            },
                        ),
                        ui("clipboard", value="FR16-private-clipboard"),
                    ]
                    controls[len(steps) - 2] = "queue"
                    steps += [
                        ui(
                            "click",
                            "logsRefresh",
                            when={"logs_test_stage": "queue_full"},
                        ),
                        ui(
                            "key",
                            "logsRefresh",
                            key="Tab",
                            expect={
                                "logsView": {"status": "busy", "pending": ""},
                                "clipboard": {"text": "FR16-private-clipboard"},
                            },
                        ),
                    ]
                    controls[len(steps) - 1] = "unqueue"
                    steps += [
                        ui(
                            "key",
                            "logsRefresh",
                            key="Tab",
                            when={"logs_test_stage": "queue_released"},
                            expect={"logsView": {"status": "busy"}},
                        ),
                        ui("click", "logsRefresh"),
                        ui(
                            "key",
                            "logsRefresh",
                            key="Tab",
                            expect={"logsView": {"status": "ready", "pending": ""}},
                        ),
                    ]
                    controls[len(steps) - 1] = "busy"
                    steps += [
                        ui(
                            "click",
                            "logsRefresh",
                            when={"logs_test_stage": "ring_busy"},
                        ),
                        ui(
                            "key",
                            "logsRefresh",
                            key="Tab",
                            expect={"logsView": {"status": "busy", "pending": ""}},
                        ),
                    ]
                    controls[len(steps) - 1] = "unbusy"
                    steps += [
                        ui(
                            "click",
                            "logsRefresh",
                            when={"logs_test_stage": "ring_released"},
                        ),
                        ui(
                            "key",
                            "logsRefresh",
                            key="Tab",
                            expect={
                                "logsView": {"status": "ready"},
                                "logsExportText": {"text": {"contains": "rejected=1"}},
                            },
                        ),
                    ]
                    controls[len(steps) - 1] = "fill"
                    existing = root / "existing.txt"
                    existing.write_text("preserve existing file")
                    steps += [
                        ui("click", "logsRefresh", when={"logs_test_stage": "filled"}),
                        ui(
                            "key",
                            "logsRefresh",
                            key="Tab",
                            expect={
                                "logsRows": {"count": 256},
                                "logsView": {"pending": ""},
                            },
                        ),
                        ui("text", "logsDestination", value=str(existing)),
                        ui("click", "logsSave"),
                        ui(
                            "key",
                            "logsRefresh",
                            key="Tab",
                            expect={
                                "logsView": {"saveStatus": "refused", "pending": ""},
                                "clipboard": {"text": "FR16-private-clipboard"},
                            },
                        ),
                        command({"command": "shutdown"}),
                    ]
                    script = root / "steps.json"
                    script.write_text(json.dumps({"steps": steps}))
                    trace = output / "trace.jsonl"
                    with (output / "stderr.log").open("wb") as stderr:
                        process = subprocess.Popen(
                            [
                                str(binary),
                                "--data-dir",
                                str(root / "data"),
                                "--engine-dir",
                                str(engines),
                                "--listen-port",
                                str(socks),
                                "--smoke-script",
                                str(script),
                                "--smoke-trace",
                                str(trace),
                            ],
                            env=env,
                            stdin=subprocess.PIPE,
                            stderr=stderr,
                            start_new_session=True,
                        )
                        descriptors: list[int] = []
                        try:
                            deadline = time.monotonic() + 55
                            while True:
                                if trace.exists():
                                    events = [
                                        json.loads(line)
                                        for line in trace.read_text().splitlines()
                                    ]
                                    current = max(
                                        (event.get("step", 0) for event in events),
                                        default=0,
                                    )
                                    for step, action in list(controls.items()):
                                        if current >= step:
                                            if (
                                                action in {"fault", "kill"}
                                                and events[-1].get("status")
                                                != "Limited"
                                            ):
                                                continue
                                            if action == "kill":
                                                descriptors += child_pidfds(process)
                                                signal.pidfd_send_signal(
                                                    descriptors[-1], signal.SIGKILL
                                                )
                                            else:
                                                assert process.stdin is not None
                                                process.stdin.write(
                                                    (action + "\n").encode()
                                                )
                                                process.stdin.flush()
                                            with (output / "controls.jsonl").open(
                                                "a"
                                            ) as control_trace:
                                                control_trace.write(
                                                    json.dumps(
                                                        {"step": step, "action": action}
                                                    )
                                                    + "\n"
                                                )
                                            del controls[step]
                                    if events and events[-1].get("closed"):
                                        break
                                assert time.monotonic() < deadline, (
                                    f"GUI deadline: step={current} controls={controls}"
                                )
                                time.sleep(0.02)
                            assert wait_exit(process, 5) == 0
                            assert existing.read_text() == "preserve existing file"
                            snapshots = [
                                json.loads(line)
                                for line in (root / "backend.jsonl")
                                .read_text()
                                .splitlines()
                            ]
                            pages = [
                                s["logs"]
                                for s in snapshots
                                if s.get("logs", {}).get("status") == "ready"
                            ]
                            lost = next(
                                page
                                for page in reversed(pages)
                                if int(page["evicted"]) > 0
                            )
                            assert int(lost["missed"]) > 0 and int(lost["rejected"]) > 0
                            assert len(lost["events"]) == 256
                            contextual = [
                                row
                                for page in pages
                                for row in page["events"]
                                if row.get("session_id")
                            ]
                            assert {row["session_id"] for row in contextual} >= {
                                "1",
                                "2",
                            }
                            assert all(row["generation"] == "1" for row in contextual)
                            (output / "loss.json").write_text(json.dumps(lost))
                            (output / "session-events.json").write_text(
                                json.dumps(contextual)
                            )
                        finally:
                            if (root / "backend.jsonl").exists():
                                shutil.copyfile(
                                    root / "backend.jsonl", output / "backend.jsonl"
                                )
                            if process.stdin is not None:
                                try:
                                    process.stdin.write(b"release\nunbusy\n")
                                    process.stdin.flush()
                                except BrokenPipeError:
                                    pass
                                try:
                                    process.stdin.close()
                                except BrokenPipeError:
                                    pass
                            for descriptor in descriptors:
                                try:
                                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                                os.close(descriptor)
                            stop_group(process)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
        finally:
            bus.terminate()
            bus.wait(timeout=5)
            if bus.stdout is not None:
                bus.stdout.close()


if __name__ == "__main__":
    main()
