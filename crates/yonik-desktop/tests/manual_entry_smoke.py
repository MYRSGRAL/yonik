"""Настоящие поля Qt → local review → verified backup → approve → reopen."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from desktop_ui_smoke import execute, ui  # noqa: E402


def main() -> None:
    controlled = "--controlled-transports" in sys.argv[3:]
    binary = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yonik-manual-") as temporary:
        root = Path(temporary)
        steps = [
            ui("resize", width=540, height=900, when={"ready": True}),
            ui("click", "serverPickerButton"),
        ]
        cases = [(index, None) for index in range(6)] + [
            (index, transport) for index in range(3) for transport in ("ws", "grpc")
        ]
        if controlled:
            cases = [(1, "ws"), (2, "grpc")]
            if "--only-ws" in sys.argv:
                cases = cases[:1]
            elif "--only-grpc" in sys.argv:
                cases = cases[1:]
        for case_number, (index, transport) in enumerate(cases):
            steps.extend(
                [
                    ui("click", "importMenuButton", when={"pending": False}),
                    ui("click", "manualEntryButton"),
                ]
            )
            if index:
                steps.extend(
                    [
                        ui("click", "manualProtocol"),
                        ui("click", "manualProtocolChoice_" + str(index)),
                    ]
                )
            steps.extend(
                ui(
                    "input",
                    "manual_" + field,
                    value=value,
                    expect={"manualProtocol": {"currentIndex": index}}
                    if field == "serverName"
                    else None,
                )
                for field, value in [
                    ("serverName", "Manual"),
                    ("host", "127.0.0.1" if controlled else "example.com"),
                    ("port", "24443" if controlled else "443"),
                ]
            )
            if index < 2:
                steps.append(
                    ui(
                        "text",
                        "manual_uuid",
                        value="11111111-2222-4333-8444-555555555555",
                    )
                )
            else:
                steps.append(
                    ui(
                        "text",
                        "manual_password",
                        value="synthetic-manual-secret",
                        capture="manual-filled.png",
                    )
                )
                if index >= 4:
                    steps.append(ui("text", "manual_username", value="alice"))
            if transport:
                if index == 1:
                    steps.append(ui("click", "manualTls"))
                steps.extend(
                    [
                        ui(
                            "text",
                            "manual_sni",
                            value="yonik.test" if controlled else "tls.example.com",
                        ),
                        ui(
                            "text",
                            "manual_alpn",
                            value="" if controlled else "h2,http/1.1",
                        ),
                        ui("click", "manualTransport"),
                        ui(
                            "click",
                            "manualTransportChoice_"
                            + str(1 if transport == "ws" else 2),
                        ),
                    ]
                )
                if transport == "ws":
                    steps.extend(
                        [
                            ui(
                                "text",
                                "manual_path",
                                value="/manual-echo" if controlled else "/ws",
                            ),
                            ui(
                                "text",
                                "manual_wsHost",
                                value="yonik.test" if controlled else "cdn.example.com",
                            ),
                        ]
                    )
                else:
                    steps.extend(
                        [
                            ui(
                                "text",
                                "manual_service",
                                value="manual-service"
                                if controlled
                                else "service-name",
                            ),
                        ]
                    )
            steps.append(
                ui(
                    "click",
                    "manualSubmit",
                    expect={
                        "manualTransport": {
                            "currentIndex": 1 if transport == "ws" else 2
                        }
                    }
                    if transport
                    else None,
                )
            )
            if case_number == 0:
                steps.extend(
                    [
                        ui("click", "localImportBackupButton", when={"pending": True}),
                        ui(
                            "select_file",
                            "localImportBackupDialog",
                            value=str(root / "before-manual.sqlite"),
                        ),
                    ]
                )
            steps.append(
                ui(
                    "click",
                    "approveRefreshButton",
                    when={
                        "pending": True,
                        "busy": False,
                        "ready": True,
                        **(
                            {
                                "maintenance_ack": {
                                    "request_id": 1,
                                    "phase": "complete",
                                    "error": None,
                                }
                            }
                            if case_number == 0
                            else {}
                        ),
                    },
                    expect={
                        "importAcceptedCount": {"text": "Готово к сохранению: 1"},
                        "importRejectedCount": {"visible": False},
                    },
                )
            )
        steps.extend(
            [
                {
                    "when": {"pending": False, "profiles_count": 1, "ready": True},
                    "command": {
                        "command": "maintenance_start",
                        "request_id": 2,
                        "operation": "backup",
                        "destination": str(root / "after-manual.sqlite"),
                        "revision": 1,
                    },
                },
                {
                    "when": {
                        "ready": True,
                        "profiles_count": 1,
                        "maintenance_ack": {
                            "request_id": 2,
                            "phase": "complete",
                            "error": None,
                        },
                    },
                    "command": {"command": "shutdown"},
                },
            ]
        )
        (output / "import").mkdir(exist_ok=True)
        execute(binary, root, steps, output / "import", "1")
        for artifact in output.rglob("*.log"):
            if "synthetic-manual-secret" in artifact.read_text():
                raise RuntimeError("Секрет в evidence")
        for artifact in output.rglob("*.jsonl"):
            if "synthetic-manual-secret" in artifact.read_text():
                raise RuntimeError("Секрет в trace")


if __name__ == "__main__":
    main()
