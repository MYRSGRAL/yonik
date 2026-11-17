"""Пользовательские действия в собственном Qt-окне с вымышленными данными."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import subprocess
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

from desktop_smoke import Fixture, read_trace

LOG = logging.getLogger("desktop-ui-smoke")


def ui(
    action: str,
    target: str = "",
    *,
    when: dict[str, object] | None = None,
    expect: dict[str, object] | None = None,
    capture: str | None = None,
    **values: object,
) -> dict[str, object]:
    step: dict[str, object] = {
        "when": when or {},
        "ui": {"action": action, "object": target, **values},
    }
    if expect:
        step["ui_when"] = expect
    if capture:
        step["capture_name"] = capture
    return step


def script(url: str, width: int, height: int) -> list[dict[str, object]]:
    steps = [ui("resize", when={"ready": True}, width=width, height=height)]

    page = 0
    settings_origin = 0
    settings_section = ""
    source_options = False

    def click(target: str, **kwargs: Any) -> None:
        nonlocal page, settings_origin, settings_section, source_options
        steps.append(ui("click", target, **kwargs))
        if target == "settingsButton":
            settings_origin, page, settings_section = page, 2, ""
        elif target == "homeButton":
            if page == 2:
                if settings_section:
                    settings_section = ""
                else:
                    page = settings_origin
            elif source_options:
                source_options = False
            else:
                page = 0
        elif target == "serverPickerButton":
            page = 1
        elif target.startswith("settings") and target.endswith("Button"):
            settings_section = target
        elif target == "sourceOptionsButton":
            source_options = not source_options
        elif target == "sourceAddConfirmButton":
            page = 1

    def check(expect: dict[str, object], **kwargs: Any) -> None:
        target = "homeButton" if page == 2 else "settingsButton"
        steps.append(ui("key", target, key="Tab", expect=expect, **kwargs))

    def navigate(destination: int, **kwargs: Any) -> None:
        # Модель выбирает только пользовательские кнопки; состояние окна
        # дополнительно проверяется smoke driver после каждого перехода.
        first = True
        while page != destination:
            target = (
                "serverPickerButton" if page == 0 and destination == 1 else "homeButton"
            )
            click(target, **(kwargs if first else {}))
            first = False
        if first and kwargs:
            expect = {"window": {"page": destination}, **kwargs.pop("expect", {})}
            check(expect, **kwargs)
        else:
            check({"window": {"page": destination}})

    # Шестерёнка помнит исходную страницу, Back сначала закрывает подраздел.
    for origin in (0, 1):
        navigate(origin)
        click("settingsButton")
        check({"window": {"page": 2, "settingsSection": ""}})
        click("settingsAboutButton")
        click("homeButton")
        check({"window": {"page": 2, "settingsSection": ""}})
        click("homeButton")
        check({"window": {"page": origin}})
    navigate(0)
    click("serverPickerButton", capture="home-empty.png")
    click("addSourceButton")
    steps.append(
        ui("text", "sourceUrlInput", value="https://cancel.invalid/?ui-secret=hidden")
    )
    steps.append(ui("text", "sourceNameInput", value="Отменённый импорт"))
    steps.append(ui("key", "sourceUrlInput", key="Escape"))
    check({"window": {"page": 1}, "addSourceDialog": {"visible": False}})
    navigate(1)
    click("addSourceButton")
    check(
        {
            "sourceUrlInput": {"text": ""},
            "sourceNameInput": {"text": ""},
        }
    )
    steps.append(ui("key", "sourceUrlInput", key="Escape"))
    navigate(
        1,
        expect={"window": {"page": 1}, "addSourceDialog": {"visible": False}},
    )
    steps.append(ui("clipboard", value=url))
    click("addSourceButton")
    click("pasteSourceButton")
    steps.append(
        ui(
            "key",
            "sourceUrlInput",
            key="Escape",
            expect={"sourceUrlInput": {"text": url}, "window": {"page": 1}},
            capture="paste-preview.png",
        )
    )
    click("importMenuButton")
    click("localSubscriptionAction")
    click("pasteSourceButton", expect={"window": {"page": 1}})
    steps.append(ui("text", "sourceNameInput", value="Тест А"))
    click("sourceAddConfirmButton")
    check(
        {
            "refreshReviewDialog": {"visible": False},
            "sourceUrlInput": {"text": ""},
            "subscriptionFeedback": {
                "text": {"contains": "Профили сохранены: 2 · пропущено: 1"}
            },
        },
        when={"pending": False, "busy": False, "profiles_count": 2},
        capture="import-result.png",
    )
    click("refreshSourceButton")
    click("approveRefreshButton", when={"pending": True, "busy": False})
    click(
        "sourceOptionsButton",
        when={"pending": False, "busy": False, "profiles_count": 2},
    )
    click(
        "subscriptionHwidChoice", expect={"subscriptionHwidChoice": {"checked": False}}
    )
    click(
        "approveRefreshButton",
        when={"pending": True, "busy": False, "source_hwid_enabled": True},
    )
    click(
        "refreshSourceButton",
        when={"pending": False, "busy": False},
        expect={"subscriptionHwidChoice": {"checked": True}},
    )
    click(
        "approveRefreshButton",
        when={"pending": True, "busy": False, "source_hwid_enabled": True},
    )
    click(
        "renameSourceButton",
        when={"pending": False, "busy": False, "profiles_count": 2},
    )
    steps.append(ui("text", "renameSourceInput", value="Переименованная А"))
    click("renameSourceConfirmButton")
    steps.append(
        ui(
            "key",
            "sourceOptionsButton",
            key="Escape",
            when={
                "source_name": "Переименованная А",
                "source_hwid_enabled": True,
                "profiles_count": 2,
            },
            expect={"profileSourceFilter": {"currentText": "Переименованная А"}},
        )
    )
    source_options = False
    click("sourceOptionsButton", expect={"window": {"sourceOptions": False}})
    click("homeButton", expect={"window": {"sourceOptions": True}})
    click(
        "refreshSourceButton",
        expect={"window": {"sourceOptions": False}},
        capture="servers.png",
    )
    # Пока сервер держит ответ, навигация остаётся доступной, Cancel сохраняет профили.
    navigate(0, when={"busy": True})
    click("settingsButton")
    navigate(1)
    click(
        "cancelSourceRefreshButton",
        when={"busy": True},
        expect={"cancelSourceRefreshButton": {"visible": True, "enabled": True}},
        capture="refresh-cancel.png",
    )
    steps.append(
        ui(
            "input",
            "profileSearch",
            value="Plain",
            when={"busy": False, "profiles_count": 2, "pending": False},
        )
    )
    click("clearSearchButton", when={"profiles_count": 1}, capture="search.png")
    steps.append(
        ui("input", "profileSearch", value="нет-совпадений", when={"profiles_count": 2})
    )
    click(
        "emptyProfilesAction", when={"profiles_count": 0}, capture="filtered-empty.png"
    )
    click("profileSelect_1", when={"profiles_count": 2})
    page = 0
    click(
        "mainConnectButton",
        when={"selected_profile": 1, "can_connect": True},
        expect={"window": {"page": 0, "selectionConfirmed": True}},
    )
    check({"window": {"page": 0}}, when={"error": "engine_missing", "can_stop": False})
    click(
        "settingsButton",
        expect={"mainErrorLabel": {"visible": True}},
        capture="connection-error.png",
    )
    click("settingsConnectionButton")
    click(
        "proxyCopyButton", expect={"proxyAddress": {"text": {"contains": "127.0.0.1:"}}}
    )
    click("homeButton")
    click("settingsDiagnosticsButton", expect={"window": {"settingsSection": ""}})
    steps.append(ui("wheel", "diagnosticsScroll", delta=-1200))
    steps.append(
        ui(
            "wheel",
            "diagnosticsScroll",
            delta=1200,
            expect={"diagnosticsScroll": {"atEnd": True, "moving": False}},
            capture="diagnostics-bottom.png",
        )
    )
    click(
        "tcpCheckButton",
        expect={"diagnosticsScroll": {"atStart": True, "moving": False}},
    )
    steps.append(
        ui(
            "text",
            "probeUrlInput",
            value="https://health.invalid/private?ui-secret=hidden",
            when={
                "tcp_status": "reachable",
                "tcp_samples_count": 3,
                "tcp_samples_requested": 3,
                "tcp_busy": False,
            },
            capture="tcp.png",
        )
    )
    steps.append(ui("value", "probeExpectedStatus", value=200))
    click("revealProbeUrl")
    click("applyProbeTargetButton")
    click("homeButton", when={"probe_custom": True, "probe_expected_status": 200})
    click("settingsAppearanceButton")
    steps.append(
        ui(
            "key",
            "languageChoice",
            key="Down",
        )
    )
    steps.append(ui("key", "languageChoice", key="Enter"))
    steps.append(
        ui(
            "key",
            "languageChoice",
            key="Escape",
            expect={"window": {"language": "en"}},
            capture="appearance.png",
        )
    )
    settings_section = ""  # Escape возвращает из Appearance в корень настроек.
    click("settingsAboutButton", expect={"window": {"settingsSection": ""}})
    navigate(
        0,
        expect={"buildIdLabel": {"visible": True, "text": {"contains": "0.1.0"}}},
        capture="about-build.png",
    )
    click("settingsButton")
    click("settingsDiagnosticsButton")
    click(
        "resetProbeTargetButton",
        when={"probe_custom": True, "probe_expected_status": 200},
        expect={
            "probeExpectedStatus": {"value": 200},
            "probeUrlInput": {"text": ""},
            "revealProbeUrl": {"checked": False},
        },
    )
    navigate(1, when={"probe_custom": False, "probe_expected_status": 204})
    # Изменение параметров проверки очищает прошлую ошибку соединения;
    # повторная попытка создаёт её заново перед проверкой независимых scopes.
    navigate(0)
    click("mainConnectButton")
    navigate(1, when={"connection_error": "engine_missing"})
    click("refreshSourceButton")
    navigate(
        0,
        when={"busy": False, "source_error": "fetch", "profiles_count": 2},
        expect={
            "window": {"sourceError": "fetch", "connectionError": "engine_missing"}
        },
    )
    navigate(1, expect={"mainErrorLabel": {"visible": True}})
    # Ошибочный импорт сохраняет фильтр прежнего источника.
    steps.append(ui("input", "profileSearch", value="нет-совпадений"))
    navigate(0, when={"profiles_count": 0})
    navigate(1)
    click("addSourceButton")
    steps.append(ui("text", "sourceUrlInput", value="not-a-url"))
    click("sourceAddConfirmButton")
    check(
        {"window": {"page": 1}, "profileSearch": {"text": "нет-совпадений"}},
        when={"source_error": "invalid_input", "sources_total": 1, "profiles_count": 0},
    )
    # Второй источник добавляется через карточку Home; импорт сбрасывает фильтр.
    navigate(0)
    navigate(1)
    click("importMenuButton")
    click("localSubscriptionAction")
    steps.append(ui("text", "sourceUrlInput", value=url + "-second"))
    steps.append(ui("text", "sourceNameInput", value="Тест Б"))
    click("sourceAddConfirmButton")
    check(
        {
            "window": {"page": 1},
            "profileSearch": {"text": ""},
            "subscriptionFeedback": {"text": {"contains": "Profiles saved: 2"}},
        },
        when={
            "source_name": "Тест Б",
            "profiles_count": 2,
            "pending": False,
            "busy": False,
        },
    )
    steps.append(
        ui(
            "key",
            "profileSourceFilter",
            key="Up",
            when={"sources_total": 2, "pending": False, "busy": False},
        )
    )
    steps.append(ui("key", "profileSourceFilter", key="Enter"))
    click(
        "sourceOptionsButton",
        when={
            "source_name": "Переименованная А",
            "profiles_count": 2,
            "source_hwid_enabled": True,
        },
    )
    click("deleteSourceButton")
    click("deleteSourceCancelButton", expect={"deleteSourceDialog": {"visible": True}})
    click("deleteSourceButton", when={"sources_total": 2, "profiles_count": 2})
    click("deleteSourceConfirmButton")
    click(
        "deleteSourceButton",
        when={"sources_total": 1, "source_name": "Тест Б", "profiles_count": 2},
        capture="source-survivor.png",
    )
    click("deleteSourceConfirmButton")
    click(
        "emptyProfilesAction",
        when={"sources_total": 0, "profiles_count": 0},
        capture="servers-empty.png",
    )
    steps.append(
        ui(
            "key",
            "sourceNameInput",
            key="Escape",
            expect={"addSourceDialog": {"visible": True}},
        )
    )
    steps.append(
        {
            "when": {},
            "ui_when": {"window": {"page": 1}, "addSourceDialog": {"visible": False}},
            "command": {"command": "shutdown"},
            "capture_name": "final.png",
        }
    )
    return steps


def execute(
    binary: Path,
    root: Path,
    steps: list[dict[str, object]],
    output: Path,
    scale: str,
    expected_exit: int = 0,
    engines: Path | None = None,
) -> list[dict[str, Any]]:
    source = root / "steps.json"
    source.write_text(json.dumps({"steps": steps}, ensure_ascii=False))
    trace = output / "trace.jsonl"
    env = os.environ.copy()
    env.update(
        QT_QPA_PLATFORM="offscreen",
        QT_QUICK_BACKEND="software",
        QT_QUICK_CONTROLS_STYLE="Basic",
        QT_FORCE_STDERR_LOGGING="1",
        QT_SCALE_FACTOR=scale,
    )
    command = [
        str(binary),
        "--smoke-test",
        "--data-dir",
        str(root / "data"),
        "--engine-dir",
        str(engines or root / "empty-engines"),
        "--smoke-script",
        str(source),
        "--smoke-trace",
        str(trace),
        "--smoke-screenshot",
        str(output / "default.png"),
    ]
    process = subprocess.Popen(
        command,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    saved = bytearray()

    def drain() -> None:
        assert process.stderr is not None
        while chunk := process.stderr.read(8192):
            saved.extend(chunk[: max(0, 65536 - len(saved))])

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        code = process.wait(timeout=60)
    finally:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                continue
        reader.join(timeout=3)
        if process.stderr is not None:
            process.stderr.close()
        if reader.is_alive():
            raise RuntimeError("Не завершился reader собственного GUI")
        (output / "stderr.log").write_bytes(saved)
    if expected_exit == 0 and any(
        token in saved
        for token in (b"ReferenceError", b"TypeError", b"Binding loop detected")
    ):
        raise RuntimeError("QML runtime error in own window")
    events = read_trace(trace)
    if code != expected_exit or not events or not events[-1].get("closed"):
        progress = events[-1].get("step") if events else None
        raise RuntimeError(
            f"GUI exit={code}, ожидалось {expected_exit}; step={progress}\n"
            + saved[-8192:].decode(errors="replace")
        )
    if expected_exit == 0 and events[-1].get("step") != len(steps):
        raise RuntimeError("Не выполнены все UI-действия")
    if expected_exit != 0 and "Qt завершился с кодом 2".encode() not in saved:
        raise RuntimeError("Отказ не подтверждён smoke driver")
    text = trace.read_text()
    for secret in ("ui-secret", "invented-secret", "health.invalid", "subscription"):
        if secret in text:
            raise RuntimeError("Чувствительные поля попали в trace")
    if expected_exit == 0:
        for step in steps:
            if name := step.get("capture_name"):
                image = output / str(name)
                if not image.is_file() or image.stat().st_size < 1000:
                    raise RuntimeError("Нет собственного screenshot")
    return events


def run(
    binary: Path, output: Path, width: int, height: int, scale: str
) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=False)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen(8)
    listener.settimeout(0.2)
    stop = threading.Event()
    accepted: list[bool] = []
    failures: list[str] = []

    def accept_tcp() -> None:
        try:
            while not stop.is_set():
                try:
                    stream, _ = listener.accept()
                except socket.timeout:
                    continue
                with stream:
                    stream.settimeout(3)
                    if stream.recv(1) != b"":
                        raise RuntimeError("TCP probe отправил payload")
                    accepted.append(True)
        except OSError as error:
            if not stop.is_set():
                failures.append(type(error).__name__)
        except RuntimeError as error:
            failures.append(str(error))

    tcp = threading.Thread(target=accept_tcp, daemon=True)
    tcp.start()
    body = f"trojan://invented-secret@127.0.0.1:{port}#Москва • TLS\nsocks5://invented:password@192.0.2.1:1080#<b>Plain text</b>\nunknown://not-supported".encode()
    captured_hwids: list[str | None] = []
    slow_started = threading.Event()
    slow_release = threading.Event()
    slow_finished = threading.Event()

    class UiFixture(Fixture):
        def do_GET(self) -> None:
            captured_hwids.append(self.headers.get("x-hwid"))
            if len(captured_hwids) == 5:
                slow_started.set()
                try:
                    if not slow_release.wait(timeout=65):
                        failures.append("slow fixture deadline")
                finally:
                    slow_finished.set()
                return
            if len(captured_hwids) == 6:
                self.send_error(503)
                return
            if self.path.endswith("-second"):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body.rsplit(b"\n", 1)[0])
                return
            super().do_GET()

    UiFixture.body = body
    handler = UiFixture
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    http = threading.Thread(target=server.serve_forever, daemon=True)
    http.start()
    try:
        with tempfile.TemporaryDirectory(prefix="yonik-ui-actions-") as temporary:
            steps = script(
                f"http://127.0.0.1:{server.server_port}/subscription", width, height
            )
            events = execute(binary, Path(temporary), steps, output, scale)
        if not slow_started.is_set():
            raise RuntimeError("Отмена не достигла HTTP fixture")
        slow_release.set()
        if not slow_finished.wait(timeout=3):
            raise RuntimeError("Не завершился отменённый HTTP fixture")
        rejected = []
        for label, bad_step in (
            ("missing-control", ui("click", "doesNotExist", when={"ready": True})),
            (
                "capture-traversal",
                {
                    **ui("resize", when={"ready": True}, width=640, height=780),
                    "capture_name": "../outside.png",
                },
            ),
            *(
                (f"removed-{name}", ui("click", name, when={"ready": True}))
                for name in (
                    "connectionNavButton",
                    "serversNavButton",
                    "homeAddSourceButton",
                    "homeServersButton",
                    "reducedMotionChoice",
                    "homeFavoritesButton",
                    "favorite_1",
                    "settingsSubscriptionsButton",
                )
            ),
        ):
            negative_output = output / label
            negative_output.mkdir()
            with tempfile.TemporaryDirectory(prefix="yonik-ui-invalid-") as temporary:
                execute(
                    binary,
                    Path(temporary),
                    [bad_step],
                    negative_output,
                    scale,
                    expected_exit=1,
                )
            if (output / "outside.png").exists():
                raise RuntimeError("Capture вышел за пределы собственного каталога")
            rejected.append(label)
        if (
            len(captured_hwids) != 7
            or captured_hwids[0] is not None
            or captured_hwids[1] is not None
            or not captured_hwids[2]
            or captured_hwids[2] != captured_hwids[3]
            or captured_hwids[2] != captured_hwids[4]
            or captured_hwids[2] != captured_hwids[5]
            or captured_hwids[6] is not None
        ):
            raise RuntimeError("HWID opt-in/toggle wire sequence не совпадает")
        saved_trace = (output / "trace.jsonl").read_text()
        if any(value and value in saved_trace for value in captured_hwids):
            raise RuntimeError("HWID попал в GUI trace")
        if failures or len(accepted) != 3:
            raise RuntimeError(f"TCP fixture: EOF={len(accepted)}, failures={failures}")
        result = {
            "steps": len(steps),
            "events": len(events),
            "tcp_eof": len(accepted),
            "hwid_requests": len(captured_hwids),
            "cancelled_http_requests": int(slow_started.is_set()),
            "width": width,
            "height": height,
            "scale": scale,
            "rejected_scripts": rejected,
            "screenshots": [
                step["capture_name"] for step in steps if "capture_name" in step
            ],
        }
        (output / "result.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        )
        return result
    finally:
        slow_release.set()
        if slow_started.is_set() and not slow_finished.wait(timeout=3):
            failures.append("slow fixture cleanup")
        server.shutdown()
        server.server_close()
        http.join(timeout=3)
        stop.set()
        listener.close()
        tcp.join(timeout=4)
        if http.is_alive() or tcp.is_alive():
            raise RuntimeError("Не завершился собственный fixture")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--width", default=420, type=int, choices=range(380, 1601))
    parser.add_argument("--height", default=760, type=int, choices=range(600, 1401))
    parser.add_argument("--scale", default="1", choices=("1", "1.25", "1.5", "2"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        result = run(
            args.binary.resolve(strict=True),
            args.output.resolve(),
            args.width,
            args.height,
            args.scale,
        )
        LOG.info("UI actions passed: %s", result)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        LOG.error("%s", error)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
