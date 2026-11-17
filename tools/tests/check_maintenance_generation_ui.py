#!/usr/bin/env python3
"""Наблюдение actual maintenance replacement через production Main без записи snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path

from check_diagnostic_export_v2 import export_metadata
from check_scheduler_production_ui import DRIVER, INTERPOSE

FLOW = r"""
 property var original: null
 property string previous: ""
 property int completed: 0
 Timer { interval: 200; running: true; repeat: true; onTriggered: {
  require(++driver.ticks<150,"deadline")
  const backend=window.backendForDiagnostics
  const state=JSON.parse(backend.snapshot_json)
  if(step===5 && state.maintenance_ack && state.maintenance_ack.phase==="failed") {
   console.log("GEN BLOCKED " + backend.snapshot_json); step=8; backend.shutdown(); return
  }
  if(!state.ready) return
  if(step===0) {
   require(SUPPORTED ? state.error_contexts.length===0 : (state.error_contexts.length===2 && state.error_contexts.every(c=>c.reason==="scheduler_interval_invalid")),"actual input contexts")
   require(!state.preferences_warning,"safe preferences admitted")
   if(state.language!==LOCALE || window.language!==LOCALE) {
    if(driver.ticks===1) console.log("GEN LANGUAGE WAIT " + backend.snapshot_json)
    return
   }
   original=state; console.log("GEN A " + backend.snapshot_json)
   click("settingsButton"); step=1; return
  }
  if(step===1) { click("settingsDiagnosticsButton"); step=2; return }
  if(step===2) {
   click("diagnosticsLogsTab")
   require(find(window.contentItem,"copyDiagnosticsButton").text===(LOCALE==="en"?"Copy diagnostics":"Копировать диагностику"),"localized copy button")
   click("copyDiagnosticsButton"); previous=clipboard()
   require(find(window.contentItem,"diagnosticsExportResult").text===(LOCALE==="en"?"Copied":"Скопировано"),"positive native export")
   require(previous.length>0,"initial clipboard"); console.log("GEN EXPORT A " + previous)
   window.back(); step=3; return
  }
  if(step===3) { click("settingsMaintenanceButton"); step=4; return }
  if(step===4) {
   const panel=find(window.contentItem,"maintenanceBackup").parent
   require(panel.available && !panel.busy,"maintenance available")
   panel.operation=completed===0?"backup":"restore"
   panel.sourcePath=BACKUP
   panel.destinationPath=completed===0?BACKUP:RESTORED
   panel.submit(); step=5; return
  }
  if(step===5) {
   const ack=state.maintenance_ack
   if(!ack || ack.phase!=="complete") return
   require(ack.request_id===completed+1 && !ack.error,"matching complete ACK")
   require(state.scheduler_generation!==original.scheduler_generation,"replacement B")
   console.log("GEN REPLACEMENT " + backend.snapshot_json)
   completed++; window.back(); step=6; return
  }
  if(step===6) { click("settingsDiagnosticsButton"); step=7; return }
  if(step===7) {
   click("diagnosticsLogsTab")
   console.log("GEN BEFORE COPY " + backend.snapshot_json)
   click("copyDiagnosticsButton")
   console.log("GEN COPY RESULT " + JSON.stringify(find(window.contentItem,"diagnosticsExportResult").text))
   console.log("GEN CURRENT " + backend.snapshot_json)
   console.log("GEN CLIPBOARD " + clipboard())
   if(completed===1) { window.back(); step=3; return }
   step=8; backend.shutdown()
  }
 } }
 Connections { target: window ? window.backendForDiagnostics : null
  function onSnapshot_jsonChanged() {
   const raw=window.backendForDiagnostics.snapshot_json
   const state=JSON.parse(raw)
   if(state.maintenance_ack) console.log("GEN OBSERVED " + raw)
   if(state.closed) { require(step===8,"closed after scenario"); console.log("GEN CLOSED " + raw) }
  }
 }
}
"""


def assess_fence(records: dict[str, list], supported: bool = False) -> str:
    """Отличает настоящий отказ stale A от нового fault B без state injection."""
    assert records["CLOSED"][-1]["closed"], "нет closed"
    if "BLOCKED" in records:
        return "BLOCKED"
    assert len(records["A"]) == len(records["EXPORT A"]) == 1
    original = records["A"][0]
    exported = records["EXPORT A"][0]
    export_metadata(json.dumps(exported).encode())
    assert exported["errors"] == original["error_contexts"], "positive A mismatch"
    if not supported:
        assert {c["slot"] for c in original["error_contexts"]} == {"error", "source"}
        assert all(
            c["generation"] == str(original["scheduler_generation"])
            and c["stage"] == "scheduler_validation"
            and c["reason"] == "scheduler_interval_invalid"
            for c in original["error_contexts"]
        ), "не actual source context A"
    assert all(
        len(records[k]) == 2
        for k in ("REPLACEMENT", "BEFORE COPY", "CURRENT", "CLIPBOARD", "COPY RESULT")
    ), "неполный backup/restore lifecycle"
    previous_generation = original["scheduler_generation"]
    previous_clipboard = exported
    outcomes = []
    for index, replacement in enumerate(records["REPLACEMENT"]):
        ack = replacement["maintenance_ack"]
        assert ack["request_id"] == index + 1 and ack["phase"] == "complete"
        assert not ack["error"] and replacement["ready"]
        generation = replacement["scheduler_generation"]
        assert generation > previous_generation, "replacement generation не выросла"
        before = records["BEFORE COPY"][index]
        current = records["CURRENT"][index]
        assert before == current, "snapshot изменился во время copy"
        assert before["scheduler_generation"] == generation
        contexts = before["error_contexts"]
        assert contexts == replacement["error_contexts"], "contexts changed after ACK"
        clipboard = records["CLIPBOARD"][index]
        success = records["COPY RESULT"][index] in ("Скопировано", "Copied")
        if supported:
            assert not contexts
        if not contexts:
            assert not success and clipboard == previous_clipboard, "invalidation copy"
            outcomes.append("INVALIDATED")
        elif contexts and all(
            c["generation"] is not None and int(c["generation"]) < generation
            for c in contexts
        ):
            assert {c["slot"] for c in contexts} == {"error", "source"}
            assert all(
                c["stage"] == "scheduler_validation"
                and c["reason"] == "scheduler_interval_invalid"
                for c in contexts
            )
            assert not success and clipboard == previous_clipboard, "stale A exported"
            outcomes.append("STALE_REFUSED")
        else:
            assert all(c["generation"] == str(generation) for c in contexts)
            if success:
                export_metadata(json.dumps(clipboard).encode())
                assert clipboard["errors"] == contexts, "B export mismatch"
            else:
                assert clipboard == previous_clipboard
            outcomes.append("B_OVERWROTE_A_UNPROVEN")
        previous_clipboard = clipboard
        previous_generation = generation
    return ",".join(outcomes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--supported-control",
        action="store_true",
        help="Исправный interval: обязательный positive backup/restore control",
    )
    parser.add_argument("--locale", choices=("ru", "en"), default="ru")
    parser.add_argument("--preferences", type=Path)
    parser.add_argument("--binary-manifest", type=Path)
    parser.add_argument("--assess-existing", action="store_true")
    args = parser.parse_args()
    if os.environ.get("QT_QPA_PLATFORM") != "offscreen" or not os.environ.get(
        "DBUS_SESSION_BUS_ADDRESS"
    ):
        parser.error("нужны offscreen и private D-Bus")
    if args.locale == "en" and not args.preferences:
        parser.error("EN требует сохранённых preferences реального UI lifecycle")
    out = args.output.resolve()
    if args.assess_existing:
        output = (out / "qt.log").read_text()
        assert "GEN CLOSED " in output and "UI FAIL " not in output
    else:
        out.mkdir(mode=0o700, parents=True, exist_ok=False)
        environment = dict(os.environ)
        if args.preferences:
            preferences = args.preferences.read_bytes()
            assert json.loads(preferences)["language"] == args.locale
            (out / "input-preferences.json").write_bytes(preferences)
            (out / "input-preferences.json").chmod(0o600)
            environment["YONIK_UI_PREFERENCES"] = str(out / "input-preferences.json")
            environment["YONIK_UI_PREFERENCES_DESTINATION"] = str(
                out / "host/data/preferences.json"
            )
        source = out / "observer.cpp"
        source.write_text(INTERPOSE)
        library = out / "observer.so"
        flags = shlex.split(
            subprocess.check_output(
                ["pkg-config", "--cflags", "--libs", "Qt6Qml"], text=True
            )
        )
        subprocess.run(
            [
                "clang++",
                "-shared",
                "-fPIC",
                str(source),
                "-o",
                str(library),
                *flags,
                "-ldl",
            ],
            check=True,
        )
        driver = out / "driver.qml"
        driver.write_text(
            DRIVER.split(" Timer {", 1)[0]
            + FLOW.replace("LOCALE", json.dumps(args.locale))
            .replace("SUPPORTED", "true" if args.supported_control else "false")
            .replace("BACKUP", json.dumps(str(out / "backup.sqlite")))
            .replace("RESTORED", json.dumps(str(out / "restored.sqlite")))
        )
        result = subprocess.run(
            [str(args.binary.resolve()), str(out / "host")]
            + (["supported"] if args.supported_control else []),
            env=dict(
                environment,
                LD_PRELOAD=str(library),
                YONIK_UI_DRIVER=str(driver),
                QT_FORCE_STDERR_LOGGING="1",
            ),
            capture_output=True,
            text=True,
            timeout=40,
        )
        output = result.stdout + result.stderr
        (out / "qt.log").write_text(output)
        (out / "process.json").write_text(json.dumps({"exit_code": result.returncode}))
        result.check_returncode()
    records: dict[str, list[dict]] = {}
    for line in output.splitlines():
        for marker in (
            "A",
            "EXPORT A",
            "REPLACEMENT",
            "CURRENT",
            "CLIPBOARD",
            "OBSERVED",
            "CLOSED",
            "BLOCKED",
            "BEFORE COPY",
            "COPY RESULT",
        ):
            prefix = "GEN " + marker + " "
            if prefix in line:
                records.setdefault(marker, []).append(
                    json.loads(line.split(prefix, 1)[1])
                )
    if not args.supported_control:
        for value in records["EXPORT A"]:
            export_metadata(json.dumps(value).encode())
    if args.supported_control:
        assert "BLOCKED" not in records, "healthy control failed"
        assert all(not value["error_contexts"] for value in records["REPLACEMENT"])
    assert records["CLOSED"][-1]["closed"]
    if "BLOCKED" not in records:
        assert len(records["REPLACEMENT"]) == 2
    main_path = (
        Path(__file__).resolve().parents[2] / "crates/yonik-desktop/qml/Main.qml"
    )
    main_hash = hashlib.sha256(main_path.read_bytes()).hexdigest()
    binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    if args.binary_manifest:
        manifest = json.loads(args.binary_manifest.read_text())
        assert manifest["artifacts"][args.binary.name] == binary_hash
        main_hash = manifest["source_sha256"]["crates/yonik-desktop/qml/Main.qml"]
    assert "PRODUCTION MAIN SHA256 " + main_hash in output
    assert all(
        state["language"] == args.locale
        for marker in ("A", "REPLACEMENT", "BEFORE COPY", "CURRENT", "CLOSED")
        for state in records[marker]
    ), "producer language changed"
    if args.locale == "en":
        assert all(
            result
            in (
                "Copied",
                "Export unavailable: verified metadata for this error are missing.",
            )
            for result in records["COPY RESULT"]
        ), "не EN результат copy"
    assessment = assess_fence(records, args.supported_control)
    summary = {
        "locale": args.locale,
        "fence_assessment": assessment,
        "main_sha256": main_hash,
        "assessment_from_saved_log": args.assess_existing,
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "records": records,
    }
    (out / "observations.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2)
    )
    print(assessment, out)


if __name__ == "__main__":
    main()
