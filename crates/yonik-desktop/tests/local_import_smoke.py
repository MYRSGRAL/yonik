"""Настоящие Qt input, review, approve/discard и safe error локального импорта."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from desktop_ui_smoke import execute, ui  # noqa: E402


def verify_redaction(output: Path) -> None:
    for artifact in [output / "trace.jsonl", output / "stderr.log"]:
        if artifact.exists():
            text = artifact.read_text()
            if any(
                secret in text
                for secret in [
                    "synthetic-text-secret",
                    "synthetic-file-secret",
                    "synthetic-cancel-secret",
                    "private-missing-path",
                ]
            ):
                raise RuntimeError("Секрет попал в UI evidence")


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yonik-local-ui-") as temporary:
        root = Path(temporary)
        selected = root / "selected.txt"
        selected.write_text("trojan://synthetic-file-secret@example.com:443#file\n")
        cancel_file = root / "cancel.txt"
        cancel_file.write_text(
            ("trojan://synthetic-cancel-secret@example.com:443#" + "cancel" * 50 + "\n")
            * 20_000
        )
        if "--preview-only" in sys.argv[3:]:
            execute(
                binary,
                root,
                [
                    ui(
                        "resize",
                        width=420,
                        height=760,
                        when={"ready": True},
                        expect={
                            "window": {
                                "title": {
                                    "contains": os.environ["YONIK_EXPECT_BUILD_ID"]
                                }
                            }
                        }
                        if "YONIK_EXPECT_BUILD_ID" in os.environ
                        else None,
                    ),
                    ui("click", "serverPickerButton"),
                    ui("click", "sourceOptionsButton"),
                    ui("click", "configImportAction"),
                    ui(
                        "text",
                        "localImportTextInput",
                        value="trojan://synthetic-text-secret@example.com:443#text\nunknown://rejected",
                    ),
                    ui("click", "importTextButton"),
                    ui(
                        "click",
                        "discardRefreshButton",
                        when={"pending": True},
                        expect={
                            "importAcceptedCount": {"text": "Готово к сохранению: 1"},
                            "importRejectedCount": {"text": "Пропущено: 1"},
                        },
                    ),
                    ui("click", "sourceOptionsButton", when={"pending": False}),
                    ui("click", "configImportAction"),
                    ui("click", "importFileButton"),
                    ui("select_file", "localImportFileDialog", value=str(selected)),
                    ui(
                        "click",
                        "discardRefreshButton",
                        when={"pending": True},
                    ),
                    ui("click", "sourceOptionsButton", when={"pending": False}),
                    ui("click", "configImportAction"),
                    ui("click", "importFileButton"),
                    ui("select_file", "localImportFileDialog", value=str(cancel_file)),
                    ui(
                        "click",
                        "cancelImportButton",
                        when={"busy": True},
                        expect={
                            "addSourceDialog": {"visible": False},
                            "localImportFileDialog": {"visible": False},
                        },
                    ),
                    {
                        "when": {"pending": False, "busy": False},
                        "command": {
                            "command": "import_file",
                            "name": "error",
                            "path": str(root / "private-missing-path"),
                        },
                    },
                    {
                        "when": {"error": "invalid_input"},
                        "command": {"command": "cancel_local_import"},
                    },
                    {"when": {"busy": False}, "command": {"command": "shutdown"}},
                ],
                output,
                "1",
            )
            verify_redaction(output)
            return
        execute(
            binary,
            root,
            [
                ui(
                    "resize",
                    width=420,
                    height=760,
                    when={"ready": True},
                    expect={
                        "window": {
                            "title": {"contains": os.environ["YONIK_EXPECT_BUILD_ID"]}
                        }
                    }
                    if "YONIK_EXPECT_BUILD_ID" in os.environ
                    else None,
                ),
                ui("click", "serverPickerButton"),
                ui("click", "sourceOptionsButton"),
                ui("click", "configImportAction"),
                ui(
                    "text",
                    "localImportTextInput",
                    value="trojan://synthetic-text-secret@example.com:443#text\nunknown://rejected",
                ),
                ui("click", "importTextButton"),
                ui("click", "localImportBackupButton", when={"pending": True}),
                ui(
                    "select_file",
                    "localImportBackupDialog",
                    value=str(root / "before-local.sqlite"),
                ),
                ui(
                    "click",
                    "approveRefreshButton",
                    when={
                        "pending": True,
                        "ready": True,
                        "busy": False,
                        "maintenance_ack": {
                            "request_id": 1,
                            "phase": "complete",
                            "error": None,
                        },
                    },
                ),
                ui(
                    "click",
                    "sourceOptionsButton",
                    when={"pending": False, "profiles_count": 1},
                ),
                ui("click", "configImportAction"),
                ui("text", "localImportTextInput", value="unknown://rejected"),
                ui("click", "importTextButton"),
                ui("click", "discardRefreshButton", when={"pending": True}),
                ui("click", "sourceOptionsButton", when={"pending": False}),
                ui("click", "configImportAction"),
                ui("click", "importFileButton"),
                ui("select_file", "localImportFileDialog", value=str(selected)),
                ui("click", "approveRefreshButton", when={"pending": True}),
                {
                    "when": {"pending": False, "profiles_count": 1},
                    "command": {
                        "command": "import_file",
                        "name": "error",
                        "path": str(root / "private-missing-path"),
                    },
                },
                {
                    "when": {"error": "invalid_input"},
                    "command": {"command": "cancel_local_import"},
                },
                {"when": {"busy": False}, "command": {"command": "shutdown"}},
            ],
            output,
            "1",
        )
        verify_redaction(output)


if __name__ == "__main__":
    main()
