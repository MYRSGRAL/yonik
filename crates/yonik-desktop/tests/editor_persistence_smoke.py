"""Реальные Qt bindings и DesktopHost: два запуска одной encrypted fixture DB."""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from desktop_ui_smoke import execute, ui  # noqa: E402


def checkpoint(
    draft: dict[str, object], revision: int, advanced: bool
) -> dict[str, object]:
    """Проверка состояния выполняется настоящим Qt smoke driver до действия."""
    return ui(
        "key",
        "routingModeButton",
        key="Tab",
        when={"routing": draft, "routing_revision": revision},
        expect={"routingEditor": {"advanced": advanced}},
    )


def stored_row(database: Path) -> tuple[int, bytes]:
    """Сверка неизменности ciphertext без расшифровки в Python."""
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        revision, payload = connection.execute(
            "SELECT revision,payload FROM routing_draft WHERE singleton=1"
        ).fetchone()
    return revision, payload


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    compound = {
        "id": 1,
        "enabled": True,
        "executables": ["/fixture/app"],
        "domains": ["*.example.org", "example.net"],
        "destinations": ["192.0.2.0/24", "2001:db8::/32"],
        "action": "proxy",
    }
    duplicate = {**compound, "id": 2, "enabled": False}
    initial = {"version": 1, "default_action": "proxy", "rules": [compound]}
    pair = {**initial, "rules": [compound, duplicate]}
    ordered = {**pair, "rules": [duplicate, compound]}
    final = {**ordered, "default_action": "direct"}
    original_popen = subprocess.Popen

    def launch(command: list[str], **kwargs: object) -> subprocess.Popen:
        # Только argv доверенного Rust fixture; Main.qml и backend не подменены.
        return original_popen([*command, "--editor-persistence"], **kwargs)

    with tempfile.TemporaryDirectory(prefix="yonik-editor-persistence-") as temporary:
        root = Path(temporary)
        with patch("desktop_ui_smoke.subprocess.Popen", launch):
            first = output / "first"
            first.mkdir(exist_ok=True)
            first_steps = [
                ui("click", "settingsButton", when={"ready": True}),
                ui("click", "settingsRoutingButton"),
                ui("click", "routingEditorTab"),
                ui(
                    "click",
                    "routingModeButton",
                    expect={"routingEditor": {"advanced": False}},
                ),
                ui("text", "routingExecutable", value="/fixture/app"),
                ui("text", "routingDomain", value="*.example.org\nexample.net"),
                ui("text", "routingCidr", value="192.0.2.0/24\n2001:db8::/32"),
                ui("click", "routingSaveRule"),
                checkpoint(initial, 1, True),
                ui("click", "routingRulesTab"),
                ui("click", "routingDuplicate1"),
                ui(
                    "click",
                    "routingEnabled",
                    expect={"routingEditor": {"selectedId": 0}},
                ),
                ui("click", "routingSaveRule"),
                checkpoint(pair, 2, True),
                ui("click", "routingRulesTab"),
                ui("click", "routingUp2"),
                checkpoint(ordered, 3, True),
                {
                    "when": {"routing": ordered, "routing_revision": 3},
                    "command": {
                        "command": "routing_default",
                        "expected_revision": 3,
                        "request_id": 1000,
                        "action": "direct",
                    },
                },
                checkpoint(final, 4, True),
                ui("click", "routingRulesTab"),
                ui("click", "routingEdit2"),
                ui(
                    "click",
                    "routingModeButton",
                    expect={"routingEditor": {"selectedId": 2}},
                ),
                checkpoint(final, 4, False),
                ui(
                    "key",
                    "routingModeButton",
                    key="Tab",
                    expect={
                        "routingDomain": {
                            "visible": False,
                            "text": "*.example.org\nexample.net",
                        },
                        "routingCidr": {
                            "visible": False,
                            "text": "192.0.2.0/24\n2001:db8::/32",
                        },
                    },
                ),
                # Save из simple должен сохранить скрытые compound-группы.
                ui("click", "routingSaveRule"),
                checkpoint(final, 5, False),
                ui("click", "routingModeButton"),
                checkpoint(final, 5, True),
                ui("text", "routingDomain", value="bad domain"),
                ui("click", "routingSaveRule"),
                ui(
                    "key",
                    "routingModeButton",
                    key="Tab",
                    when={"error": "domain", "routing": final, "routing_revision": 5},
                    expect={"routingDomain": {"text": "bad domain"}},
                ),
                ui("text", "routingDomain", value="*.example.org\nexample.net"),
                ui("click", "routingModeButton"),
                checkpoint(final, 5, False),
                {
                    "when": {"routing": final, "routing_revision": 5},
                    "command": {"command": "shutdown"},
                },
            ]
            execute(binary, root, first_steps, first, "1")
            db = root / "data" / "subscriptions.sqlite"
            encrypted = db.read_bytes()
            assert db.stat().st_mode & 0o077 == 0, "Права fixture DB"
            assert b"/fixture/app" not in encrypted
            assert b"example.org" not in encrypted
            second = output / "second"
            second.mkdir(exist_ok=True)
            second_steps = [
                ui(
                    "click",
                    "settingsButton",
                    when={"ready": True, "routing": final, "routing_revision": 5},
                ),
                ui("click", "settingsRoutingButton"),
                checkpoint(final, 5, False),
                ui("click", "routingRulesTab"),
                ui("click", "routingEdit1"),
                ui(
                    "click",
                    "routingModeButton",
                    expect={"routingEditor": {"selectedId": 1}},
                ),
                checkpoint(final, 5, True),
                ui(
                    "key",
                    "routingModeButton",
                    key="Tab",
                    expect={
                        "routingExecutable": {"text": "/fixture/app"},
                        "routingDomain": {"text": "*.example.org\nexample.net"},
                        "routingCidr": {"text": "192.0.2.0/24\n2001:db8::/32"},
                        "routingEnabled": {"checked": True},
                    },
                ),
                ui("click", "routingModeButton"),
                checkpoint(final, 5, False),
                {
                    "when": {"routing": final, "routing_revision": 5},
                    "command": {"command": "shutdown"},
                },
            ]
            execute(binary, root, second_steps, second, "1")
            shutil.copyfile(root / "backend.jsonl", output / "backend.jsonl")
        # Текущий V1 reader читает неприменимый future blob только read-only.
        legacy = root / "legacy"
        subprocess.run(
            [str(binary), "--data-dir", str(legacy / "data"), "--editor-seed-v2"],
            check=True,
        )
        original_row = stored_row(legacy / "data" / "subscriptions.sqlite")
        mutations = [
            {
                "command": "edit_routing",
                "create": create,
                "confirm_broad": False,
                "rule": {**compound, "id": 41},
            }
            for create in (False, True)
        ] + [
            {"command": "routing_order", "ids": [41]},
            {"command": "routing_delete", "id": 41},
            {"command": "routing_default", "action": "direct"},
        ]
        for attempt in range(2):
            legacy_output = output / f"v1-reader-{attempt + 1}"
            legacy_output.mkdir(exist_ok=True)
            legacy_steps = [
                ui(
                    "click",
                    "settingsButton",
                    when={
                        "ready": True,
                        "routing_revision": None,
                        "error": "routing_storage",
                    },
                ),
                ui("click", "settingsRoutingButton"),
                ui("click", "routingEditorTab"),
            ]
            for request_id, mutation in enumerate(mutations, 1):
                legacy_steps.extend(
                    [
                        {
                            "when": {"routing_revision": None},
                            "command": {
                                **mutation,
                                "expected_revision": 0,
                                "request_id": request_id,
                            },
                        },
                        ui(
                            "key",
                            "routingModeButton",
                            key="Tab",
                            when={
                                "routing_revision": None,
                                "routing_ack": {
                                    "request_id": request_id,
                                    "saved_id": None,
                                    "error": "routing_storage",
                                },
                            },
                        ),
                    ]
                )
            legacy_steps.extend(
                [
                    {
                        "when": {},
                        "command": {
                            "command": "routing_explain",
                            "expected_revision": 0,
                            "request_id": 6,
                            "target": "192.0.2.1",
                        },
                    },
                    {
                        "when": {
                            "routing_revision": None,
                            "routing_explanation": None,
                            "routing_ack": {
                                "request_id": 6,
                                "saved_id": None,
                                "error": "routing_stale",
                            },
                        },
                        "command": {"command": "shutdown"},
                    },
                ]
            )
            with patch("desktop_ui_smoke.subprocess.Popen", launch):
                execute(binary, legacy, legacy_steps, legacy_output, "1")
            subprocess.run(
                [str(binary), "--data-dir", str(legacy / "data"), "--editor-check-v2"],
                check=True,
            )
            assert stored_row(legacy / "data" / "subscriptions.sqlite") == original_row
        shutil.copyfile(legacy / "backend.jsonl", output / "v1-reader-backend.jsonl")
        (output / "result.json").write_text(
            json.dumps(
                {
                    "launches": 4,
                    "v1_reader_preserved_v2": True,
                    "steps": [len(first_steps), len(second_steps)],
                    "routing": final,
                    "revision": 5,
                    "encrypted_selectors": True,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        )


if __name__ == "__main__":
    main()
