#!/usr/bin/env python3
"""Actual Corrupt/Full/interval через неизменённый qrc Main и штатную кнопку экспорта."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path

from check_diagnostic_export_v2 import export_metadata

INTERPOSE = r"""
#include <QQmlApplicationEngine>
#include <QQmlComponent>
#include <QQmlContext>
#include <QTimer>
#include <QFile>
#include <QCryptographicHash>
#include <dlfcn.h>
#include <cstdlib>
void QQmlApplicationEngine::load(const QUrl& url) {
    using Load = void (*)(QQmlApplicationEngine*, const QUrl&);
    auto original = reinterpret_cast<Load>(dlsym(RTLD_NEXT, "_ZN21QQmlApplicationEngine4loadERK4QUrl"));
    if (!original || url.scheme() != "qrc") std::abort();
    if (auto preferences = std::getenv("YONIK_UI_PREFERENCES")) {
        const auto destination = QString::fromUtf8(std::getenv("YONIK_UI_PREFERENCES_DESTINATION"));
        if (!QFile::copy(QString::fromUtf8(preferences), destination)) std::abort();
    }
    QFile mainResource(":" + url.path());
    if (!mainResource.open(QIODevice::ReadOnly)) std::abort();
    qWarning("PRODUCTION MAIN SHA256 %s", QCryptographicHash::hash(mainResource.readAll(), QCryptographicHash::Sha256).toHex().constData());
    original(this, url);
    qWarning("PRODUCTION QRC %s", qPrintable(url.toString()));
    if (rootObjects().isEmpty()) std::abort();
    auto root = rootObjects().first();
    QTimer::singleShot(0, this, [this, root] {
        auto context = new QQmlContext(rootContext(), this);
        context->setContextProperty("productionWindow", root);
        QQmlComponent component(this, QUrl::fromLocalFile(QString::fromUtf8(std::getenv("YONIK_UI_DRIVER"))));
        auto driver = component.create(context);
        if (!driver) { qWarning() << component.errors(); std::abort(); }
        driver->setParent(this);
    });
}
"""

DRIVER = r"""
import QtQuick
Item {
 id: driver
 property var window: productionWindow
 parent: window ? window.contentItem : null
 TextEdit { id: probe; visible: false }
 property int step: 0
 property int ticks: 0
 function require(ok, why) { if (!ok) { console.error("UI FAIL " + why); Qt.exit(3); throw Error(why) } }
 function find(item, name) {
  if (item.objectName === name) return item
  if (item.children) for (let child of item.children) { const found=find(child,name); if(found) return found }
  return null
 }
 function click(name) {
  const button=find(window.contentItem,name)
  require(button && button.visible && button.enabled, name + " visible enabled")
  button.clicked()
  console.log("UI CLICK " + name)
 }
 function clipboard() { probe.clear(); probe.paste(); return probe.text }
 Timer { interval: 200; running: true; repeat: true; onTriggered: {
  if(!window) return
  require(++driver.ticks < 150, "deadline")
  const backend=window.backendForDiagnostics
  const state=JSON.parse(backend.snapshot_json)
  if (state.closed) { console.log("UI CLOSED " + backend.snapshot_json); return }
  if(step===0) {
   if(!state.ready) return
   if(!state.error_contexts || state.error_contexts.length!==CONTEXT_COUNT) return
   require(state.error_contexts.every(c=>c.reason===REASON), "actual producer")
   require(state.ready && !state.closed && (CONTEXT_COUNT===0 || state.scheduler_generation > 0),"actual ready scheduler")
   require(state.error_contexts.every(c=>c.stage===STAGE),"actual stage")
   if(REASON==="scheduler_full") require(state.sources_total===2,"actual full sources")
   if(REASON==="scheduler_interval_invalid") require(state.sources_total===1 && state.subscription_interval_seconds===86400,"actual repository and unchanged preferences bounds")
   console.log("UI SNAPSHOT " + backend.snapshot_json)
   click("settingsButton"); step++; return
  }
  if(step===1) { click("settingsDiagnosticsButton"); step++; return }
  if(step===2 || step===7) {
   click("diagnosticsLogsTab")
   const locale=LOCALE
   require(state.language===locale && window.language===locale, "real language")
   require(state.error_contexts && state.error_contexts.length===CONTEXT_COUNT && state.error_contexts.every(c=>c.reason===REASON), "context after preferences lifecycle")
   require(find(window.contentItem,"copyDiagnosticsButton").text===(locale==="ru"?"Копировать диагностику":"Copy diagnostics"),"localized production button")
   click("copyDiagnosticsButton")
   require(find(window.contentItem,"diagnosticsExportResult").text===(locale==="ru"?"Скопировано":"Copied"),"onClicked success")
   console.log("UI EXPORT " + locale + " " + clipboard())
   if(locale==="en") { console.log("UI FINAL SNAPSHOT " + backend.snapshot_json); step=8; backend.shutdown(); return }
   window.back(); step++; return
  }
  if(step===3) { click("settingsAppearanceButton"); step++; return }
  if(step===4) {
   const choice=find(window.contentItem,"languageChoice")
   require(choice && choice.visible && choice.enabled,"language choice")
   choice.currentIndex=1; choice.activated(1); step++; return
  }
  if(step===5) {
   if(state.language!=="en") return
   console.log("UI LANGUAGE LIFECYCLE " + backend.snapshot_json)
   console.log("UI CONTEXT RETAINED " + !!(state.error_contexts && state.error_contexts.length===CONTEXT_COUNT && state.error_contexts.every(c=>c.reason===REASON)))
   console.log("UI FINAL SNAPSHOT " + backend.snapshot_json)
   step=8; backend.shutdown(); return
  }
  if(step===6) { click("settingsDiagnosticsButton"); step++; return }
 } }
 Connections { target: window ? window.backendForDiagnostics : null
  function onSnapshot_jsonChanged() {
   const state=JSON.parse(window.backendForDiagnostics.snapshot_json)
   if(state.closed) { require(step===8,"tested before closed"); console.log("UI CLOSED " + window.backendForDiagnostics.snapshot_json) }
  }
 }
}
"""


CASES = {
    "corrupt": ("scheduler_repository_corrupt", "scheduler_service"),
    "full": ("scheduler_full", "scheduler_admission"),
    "interval": ("scheduler_interval_invalid", "scheduler_validation"),
}


def production_driver(case: str, locale: str, supported: bool = False) -> str:
    """Observer проверяет companion; положительные snapshots не присваиваются."""
    reason, stage = CASES[case]
    if locale not in ("ru", "en"):
        raise ValueError("Неизвестный язык")
    return (
        DRIVER.replace("CONTEXT_COUNT", "0" if supported else "2")
        .replace("REASON", json.dumps(reason))
        .replace("STAGE", json.dumps(stage))
        .replace("LOCALE", json.dumps(locale))
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("task", type=Path)
    parser.add_argument("--case", choices=tuple(CASES), required=True)
    parser.add_argument("--locale", choices=("ru", "en"), default="ru")
    parser.add_argument("--preferences", type=Path)
    parser.add_argument("--supported", action="store_true")
    args = parser.parse_args()
    if args.supported and args.case != "interval":
        parser.error("supported контроль только для interval example")
    if args.locale == "en" and not args.preferences:
        parser.error("для EN нужны сохранённые preferences реального RU lifecycle")
    if os.environ.get("QT_QPA_PLATFORM") != "offscreen" or not os.environ.get(
        "DBUS_SESSION_BUS_ADDRESS"
    ):
        parser.error("нужны offscreen и private D-Bus")
    args.task.mkdir(mode=0o700, parents=True, exist_ok=True)
    source = args.task / "observer.cpp"
    source.write_text(INTERPOSE)
    library = args.task / "observer.so"
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
    reason, _ = CASES[args.case]
    driver = args.task / "driver.qml"
    driver.write_text(production_driver(args.case, args.locale, args.supported))
    environment = dict(os.environ)
    if args.preferences:
        environment["YONIK_UI_PREFERENCES"] = str(args.preferences.resolve())
        environment["YONIK_UI_PREFERENCES_DESTINATION"] = str(
            (args.task / "host/data/preferences.json").resolve()
        )
    result = subprocess.run(
        [
            str(args.binary.resolve()),
            str(args.task / "host"),
            *(["supported"] if args.supported else []),
        ],
        env=dict(
            environment,
            LD_PRELOAD=str(library.resolve()),
            YONIK_UI_DRIVER=str(driver.resolve()),
            QT_FORCE_STDERR_LOGGING="1",
        ),
        capture_output=True,
        text=True,
        timeout=40,
        check=False,
    )
    output = result.stdout + result.stderr
    (args.task / "qt.log").write_text(output)
    result.check_returncode()
    for locale in (args.locale,):
        prefix = f"UI EXPORT {locale} "
        value = next(
            line.split(prefix, 1)[1] for line in output.splitlines() if prefix in line
        )
        export_metadata(value.encode())
        errors = json.loads(value)["errors"]
        if len(errors) != (0 if args.supported else 2) or any(
            error.get("reason") != reason for error in errors
        ):
            raise RuntimeError("native clipboard потерял actual reason")
        (args.task / f"export-{locale}.json").write_text(value)
    for marker, filename in (
        ("UI SNAPSHOT ", "actual-snapshot.json"),
        ("UI FINAL SNAPSHOT ", "final-snapshot.json"),
        ("UI CLOSED ", "closed-snapshot.json"),
    ):
        value = next(
            line.split(marker, 1)[1] for line in output.splitlines() if marker in line
        )
        (args.task / filename).write_text(value)
    main_qml = Path(__file__).resolve().parents[2] / "crates/yonik-desktop/qml/Main.qml"
    main_hash = hashlib.sha256(main_qml.read_bytes()).hexdigest()
    if f"PRODUCTION MAIN SHA256 {main_hash}" not in output:
        raise RuntimeError("qrc Main отличается от production source")
    if "PRODUCTION QRC qrc:" not in output or "UI FAIL" in output:
        raise RuntimeError(output)
    print(output)


if __name__ == "__main__":
    main()
