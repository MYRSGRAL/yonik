"""Настоящая Qt-форма с синтетическим draft и ephemeral DB."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from desktop_ui_smoke import execute, ui  # noqa: E402


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    expected = {
        "version": 1,
        "default_action": "proxy",
        "rules": [
            {
                "id": 1,
                "enabled": True,
                "executables": [],
                "domains": ["example.org"],
                "destinations": [],
                "action": "proxy",
            }
        ],
    }
    edited = {**expected, "rules": [{**expected["rules"][0], "domains": ["example.net"]}]}
    final_draft = {**edited, "rules": [{**edited["rules"][0], "id": 2, "enabled": False, "executables": ["/fixture/app"]}, edited["rules"][0]]}
    oversized = "a" * 2000
    acknowledged = {"routingEditor": {"selectedId": 1}, "window": {"routingPending": False}}
    with tempfile.TemporaryDirectory(prefix="yonik-editor-smoke-") as temporary:
        execute(
            binary,
            Path(temporary),
            [
                ui("click", "settingsButton", when={"ready": True}),
                ui("click", "settingsRoutingButton"),
                ui("click", "routingEditorTab"),
                ui("click", "routingModeButton"),
                ui("text", "routingDomain", value="example.org"),
                ui("click", "routingSaveRule"),
                ui("click", "routingSaveRule", when={"routing": expected, "routing_revision": 1}, expect=acknowledged),
                ui("text", "routingDomain", value="example.net", when={"routing_revision": 2}, expect=acknowledged),
                ui("click", "routingSaveRule"),
                ui("text", "routingDomain", value="bad domain", when={"routing_revision": 3, "routing": edited}, expect=acknowledged),
                ui("click", "routingSaveRule"),
                ui("text", "routingDomain", value="example.net", when={"error": "domain"}, expect={**acknowledged, "routingDomain": {"text": "bad domain"}}),
                ui("click", "routingSaveRule"),
                ui("text", "routingDomain", value=oversized, when={"routing_revision": 4}, expect=acknowledged),
                *[ui("input", "routingDomain", value=oversized) for _ in range(8)],
                ui("click", "routingSaveRule"),
                ui("text", "routingDomain", value="example.net", when={"error": "invalid_input"}, expect={**acknowledged, "routingDomain": {"text": oversized * 9}}),
                ui("click", "routingSaveRule"),
                ui("click", "routingModeButton", when={"routing_revision": 5, "routing": edited}, expect=acknowledged, capture="simple.png"),
                ui("click", "routingModeButton", capture="advanced.png"),
                ui("click", "routingCheckTab"),
                ui("text", "routingExplainTarget", value="example.org"),
                ui("click", "routingExplainButton"),
                ui("text", "routingExplainTarget", value="192.0.2.1", when={"routing_explanation": {"revision": 5, "request_id": 8, "result": {"status": "unknown", "reason": "dns_witness_missing"}}}),
                ui("click", "routingExplainButton"),

                ui("click", "routingRulesTab"),
                ui("click", "routingDuplicate1", when={"routing_explanation": {"revision": 5, "request_id": 9, "result": {"status": "fixture", "action": "Proxy", "origin": "Default"}}}),
                ui("click", "routingSaveRule"),
                ui("click", "routingRulesTab"),
                ui("click", "routingUp2", when={"routing_revision": 6}),
                ui("key", "routingRulesTab", key="Tab", when={"routing_revision": 7}),
                ui("click", "routingEdit2"),
                ui("click", "routingModeButton"),
                ui("text", "routingExecutable", value="/fixture/app", expect={"routingEditor": {"selectedId": 2}}),
                ui("click", "routingEnabled"),
                ui("click", "routingSaveRule"),
                {"when": {"routing_revision": 8, "routing": final_draft, "routing_diagnostics": {"incomplete": False, "warnings": []}}, "command": {"command": "shutdown"}},

            ],
            output,
            "1",
        )


if __name__ == "__main__":
    main()
