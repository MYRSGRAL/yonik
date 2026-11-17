"""Qt lifecycle локального источника: guard controls, rename/select/reopen/delete."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from desktop_ui_smoke import execute, ui  # noqa: E402


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yonik-local-lifecycle-") as temporary:
        root = Path(temporary)
        first = output / "first"
        reopened = output / "reopened"
        first.mkdir()
        reopened.mkdir()
        core_steps = []
        if "YONIK_LIFECYCLE_ENGINE" in os.environ:
            engine = os.environ["YONIK_LIFECYCLE_ENGINE"]
            expected_status = os.environ.get("YONIK_LIFECYCLE_STATUS", "Connected")
            if expected_status not in {"Connected", "Limited"}:
                raise ValueError("Неизвестный terminal status fixture")
            core_steps = [
                {
                    "when": {"selected_profile": 1},
                    "command": {"command": "set_engine", "engine": engine},
                },
                {
                    "when": {"engine": engine},
                    "command": {
                        "command": "set_probe_target",
                        "url": os.environ["YONIK_LIFECYCLE_PROBE"],
                        "expected_status": 204,
                    },
                },
                ui("click", "homeButton", when={"probe_custom": True}),
                ui(
                    "click",
                    "mainConnectButton",
                    expect={"mainConnectButton": {"visible": True, "enabled": True}},
                ),
                ui(
                    "click",
                    "mainConnectButton",
                    when={"status": expected_status, "can_stop": True},
                    expect={"mainConnectButton": {"visible": True, "enabled": True}},
                ),
            ]
        engines = (
            Path(os.environ["YONIK_LIFECYCLE_ENGINES"])
            if "YONIK_LIFECYCLE_ENGINES" in os.environ
            else None
        )
        execute(
            binary,
            root,
            [
                ui("resize", width=700, height=900, when={"ready": True}),
                ui("click", "serverPickerButton"),
                ui("click", "importMenuButton"),
                ui("click", "configImportAction"),
                ui(
                    "text",
                    "localImportTextInput",
                    value=os.environ.get(
                        "YONIK_LIFECYCLE_PROFILE",
                        "trojan://lifecycle-private@example.com:443#local",
                    ),
                ),
                ui("click", "importTextButton"),
                ui("click", "localImportBackupButton", when={"pending": True}),
                ui(
                    "select_file",
                    "localImportBackupDialog",
                    value=str(root / "backup.sqlite"),
                ),
                ui(
                    "click",
                    "approveRefreshButton",
                    when={
                        "maintenance_ack": {
                            "request_id": 1,
                            "phase": "complete",
                            "error": None,
                        },
                        "ready": True,
                        "busy": False,
                    },
                ),
                ui(
                    "click",
                    "sourceOptionsButton",
                    when={"pending": False, "source_local": True, "profiles_count": 1},
                    expect={
                        "refreshSourceButton": {"enabled": False},
                        "localSourceLabel": {
                            "visible": True,
                            "text": "Локальный источник",
                        },
                    },
                ),
                {
                    "when": {"source_local": True},
                    "command": {"command": "set_language", "language": "en"},
                },
                ui(
                    "key",
                    "sourceOptionsButton",
                    key="Tab",
                    when={"language": "en"},
                    expect={
                        "localSourceLabel": {"text": "Local source"},
                        "refreshSourceButton": {"enabled": False},
                        "subscriptionHwidChoice": {"enabled": False},
                    },
                ),
                {
                    "when": {"language": "en"},
                    "command": {"command": "set_language", "language": "ru"},
                },
                ui(
                    "click",
                    "renameSourceButton",
                    expect={"subscriptionHwidChoice": {"enabled": False}},
                ),
                ui("text", "renameSourceInput", value="Локальный переименован"),
                ui("click", "renameSourceConfirmButton"),
                ui(
                    "click",
                    "sourceOptionsButton",
                    when={
                        "source_name": "Локальный переименован",
                        "source_local": True,
                    },
                ),
                ui("click", "profileSelect_1"),
                *core_steps,
                {
                    "when": {
                        "status": "Disconnected",
                        "busy": False,
                        "can_stop": False,
                    },
                    "command": {"command": "shutdown"},
                },
            ],
            first,
            "1",
            engines=engines,
        )
        execute(
            binary,
            root,
            [
                ui(
                    "resize",
                    width=700,
                    height=900,
                    when={
                        "ready": True,
                        "source_local": True,
                        "source_name": "Локальный переименован",
                        "source_id": 1,
                        "profiles_count": 1,
                    },
                ),
                ui("click", "serverPickerButton"),
                ui(
                    "click",
                    "sourceOptionsButton",
                    expect={"refreshSourceButton": {"enabled": False}},
                ),
                ui(
                    "click",
                    "deleteSourceButton",
                    expect={"subscriptionHwidChoice": {"enabled": False}},
                ),
                ui("click", "deleteSourceConfirmButton"),
                {
                    "when": {
                        "sources_total": 0,
                        "source_local": False,
                        "profiles_count": 0,
                    },
                    "command": {"command": "shutdown"},
                },
            ],
            reopened,
            "1",
        )
        for artifact in output.rglob("*.jsonl"):
            if "lifecycle-private" in artifact.read_text():
                raise RuntimeError("Исходный секрет попал в snapshot")


if __name__ == "__main__":
    if os.environ.get("YONIK_LIFECYCLE_PERSISTENCE") == "1":
        original = subprocess.Popen

        def launch(command: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
            return original([*command, "--editor-persistence"], **kwargs)

        with patch("desktop_ui_smoke.subprocess.Popen", launch):
            main()
    else:
        main()
