"""Actual Qt: V1→V2 через backend CAS, Explain и encrypted reopen."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from desktop_ui_smoke import execute, ui  # noqa: E402


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    original = subprocess.Popen

    def launch(command: list[str], **kwargs: object) -> subprocess.Popen:
        return original([*command, "--editor-persistence"], **kwargs)

    rule = {
        "id": 41,
        "enabled": False,
        "executables": [],
        "domains": [],
        "destinations": [],
        "action": "direct",
        "platform_sources": [{"kind": "android_package", "package": "org.Example_app"}],
    }
    initial = {"version": 2, "rules": [rule], "default_action": "proxy"}
    duplicate = {**rule, "id": 42}
    draft = {**initial, "rules": [rule, duplicate]}
    with tempfile.TemporaryDirectory(prefix="yonik-p07-qt-") as temporary:
        root = Path(temporary)
        (root / "backup").mkdir(mode=0o700)
        with patch("desktop_ui_smoke.subprocess.Popen", launch):
            first = output / "migration"
            first.mkdir(exist_ok=True)
            execute(
                binary,
                root,
                [
                    ui("click", "settingsButton", when={"ready": True}),
                    ui("click", "settingsRoutingButton"),
                    {
                        "when": {"ready": True},
                        "command": {
                            "command": "maintenance_start",
                            "request_id": 91,
                            "operation": "backup",
                            "destination": str(root / "backup/v3.sqlite"),
                            "revision": 0,
                        },
                    },
                    {
                        "when": {
                            "maintenance_ack": {
                                "request_id": 91,
                                "phase": "complete",
                                "error": None,
                            }
                        },
                        "ui": {
                            "action": "key",
                            "object": "routingRulesTab",
                            "key": "Tab",
                        },
                    },
                    {
                        "when": {"routing_revision": 0},
                        "command": {
                            "command": "edit_routing",
                            "request_id": 1001,
                            "expected_revision": 0,
                            "create": True,
                            "confirm_broad": False,
                            "rule": rule,
                        },
                    },
                    ui(
                        "click",
                        "routingDuplicate41",
                        when={"routing": initial, "routing_revision": 1},
                    ),
                    ui("click", "routingSaveRule"),
                    ui("click", "routingRulesTab"),
                    ui(
                        "click",
                        "routingEdit42",
                        when={"routing": draft, "routing_revision": 2},
                    ),
                    ui("click", "routingModeButton"),
                    ui("click", "routingModeButton"),
                    ui("click", "routingSaveRule"),
                    {
                        "when": {"routing": draft, "routing_revision": 3},
                        "command": {"command": "shutdown"},
                    },
                ],
                first,
                "1",
            )
            second = output / "reopen"
            second.mkdir(exist_ok=True)
            enabled = {**rule, "enabled": True}
            active = {**draft, "rules": [enabled, duplicate]}
            enabled_duplicate = {**enabled, "id": 43}
            final = {**draft, "rules": [enabled, duplicate, enabled_duplicate]}
            execute(
                binary,
                root,
                [
                    ui(
                        "click",
                        "settingsButton",
                        when={"ready": True, "routing": draft, "routing_revision": 3},
                    ),
                    ui("click", "settingsRoutingButton"),
                    {
                        "when": {},
                        "command": {
                            "command": "edit_routing",
                            "request_id": 1002,
                            "expected_revision": 3,
                            "create": False,
                            "confirm_broad": False,
                            "rule": enabled,
                        },
                    },
                    {
                        "when": {"routing": active, "routing_revision": 4},
                        "command": {
                            "command": "routing_explain",
                            "request_id": 1003,
                            "expected_revision": 4,
                            "target": "192.0.2.1",
                        },
                    },
                    {
                        "when": {
                            "routing_explanation": {
                                "revision": 4,
                                "request_id": 1003,
                                "result": {
                                    "status": "unsupported",
                                    "reason": "unsupported_selector",
                                    "rule_id": 41,
                                },
                            }
                        },
                        "command": {"command": "connect"},
                    },
                    {
                        "when": {"error": "unsupported_option", "can_stop": False},
                        "command": {"command": "shutdown"},
                    },
                ],
                second,
                "1",
            )
            third = output / "duplicate-enabled"
            third.mkdir(exist_ok=True)
            execute(
                binary,
                root,
                [
                    ui(
                        "click",
                        "settingsButton",
                        when={"ready": True, "routing": active, "routing_revision": 4},
                    ),
                    ui("click", "settingsRoutingButton"),
                    ui("click", "routingDuplicate41"),
                    ui(
                        "click",
                        "routingSaveRule",
                        expect={"routingEnabled": {"checked": True}},
                    ),
                    {
                        "when": {"routing": final, "routing_revision": 5},
                        "command": {"command": "shutdown"},
                    },
                ],
                third,
                "1",
            )
            fourth = output / "reopen-duplicates"
            fourth.mkdir(exist_ok=True)
            execute(
                binary,
                root,
                [
                    {
                        "when": {
                            "ready": True,
                            "routing": final,
                            "routing_revision": 5,
                        },
                        "command": {"command": "shutdown"},
                    }
                ],
                fourth,
                "1",
            )
        shutil.copyfile(root / "backend.jsonl", output / "backend.jsonl")
        shutil.copytree(root / "data", output / "migrated-data")
        shutil.copytree(root / "backup", output / "backup")
        (output / "result.json").write_text(
            json.dumps(
                {
                    "launches": 4,
                    "migration": True,
                    "reopen": True,
                    "unsupported_explain": True,
                    "duplicate_disabled": True,
                    "duplicate_enabled": True,
                    "simple_advanced_preserved": True,
                }
            )
            + "\n"
        )


if __name__ == "__main__":
    main()
