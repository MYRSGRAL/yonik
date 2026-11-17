"""Два запуска настоящего Qt с отдельными синтетическими настройками."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from desktop_ui_smoke import execute, ui  # noqa: E402


def main() -> None:
    binary = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yonik-preferences-qt-") as temporary:
        root = Path(temporary)
        first = output / "first"
        second = output / "second"
        first.mkdir(exist_ok=True)
        second.mkdir(exist_ok=True)
        execute(
            binary,
            root,
            [
                ui("click", "settingsButton", when={"ready": True}),
                ui("click", "settingsConnectionButton"),
                ui("click", "proxyDnsDetailsButton"),
                ui("text", "proxyFetchDns", value="127.0.0.1:5353"),
                ui("click", "saveProxyFetchDns"),
                ui(
                    "text",
                    "proxyFetchDns",
                    value="resolver.example:53",
                    when={"proxy_fetch_dns": "127.0.0.1:5353"},
                ),
                ui("click", "saveProxyFetchDns"),
                {
                    "when": {
                        "error": "invalid_input",
                        "proxy_fetch_dns": "127.0.0.1:5353",
                    },
                    "command": {"command": "set_engine", "engine": "sing-box"},
                },
                {
                    "when": {"engine": "xray", "error": "engine_unavailable"},
                    "command": {
                        "command": "set_probe_target",
                        "url": "https://example.com/check",
                        "expected_status": 200,
                    },
                },
                {
                    "when": {"probe_expected_status": 200},
                    "command": {"command": "set_language", "language": "en"},
                },
                ui(
                    "key",
                    "homeButton",
                    key="Tab",
                    expect={"window": {"language": "en"}},
                ),
                {"when": {}, "command": {"command": "shutdown"}},
            ],
            first,
            "1",
        )
        # Smoke создаёт новый ephemeral key на процесс: второй запуск получает
        # только preferences, без БД с ключом первого процесса.
        reopened = root / "reopened"
        (reopened / "data").mkdir(parents=True, mode=0o700)
        shutil.copy2(
            root / "data" / "preferences.json", reopened / "data" / "preferences.json"
        )
        execute(
            binary,
            reopened,
            [
                ui(
                    "click",
                    "settingsButton",
                    when={
                        "ready": True,
                        "proxy_fetch_dns": "127.0.0.1:5353",
                        "engine": "xray",
                        "probe_custom": True,
                        "probe_expected_status": 200,
                    },
                    expect={"window": {"language": "en"}},
                ),
                {"when": {}, "command": {"command": "shutdown"}},
            ],
            second,
            "1",
        )
        settings = json.loads((root / "data" / "preferences.json").read_text())
        assert settings["proxy_fetch_dns"] == "127.0.0.1:5353"
        assert settings["language"] == "en"
        assert settings["engine"] == "xray"
        assert settings["probe_url"] == "https://example.com/check"
        (output / "result.json").write_text(
            json.dumps(
                {
                    "launches": 2,
                    "restored": [
                        "engine",
                        "probe_url",
                        "probe_status",
                        "language",
                        "proxy_fetch_dns",
                    ],
                }
            )
            + "\n"
        )


def runtime_write_failure(binary: Path, output: Path, conflict: str) -> None:
    """Ошибка после ready проверяется через видимый текст настоящего QML."""
    import subprocess
    import threading
    import time
    from unittest.mock import patch

    with tempfile.TemporaryDirectory(prefix="yonik-preferences-fault-") as temporary:
        root = Path(temporary)
        (root / "data").mkdir(mode=0o700)
        settings_path = root / "data" / "preferences.json"
        settings_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "engine": "xray",
                    "port": None,
                    "probe_url": "https://www.gstatic.com/generate_204",
                    "probe_status": 204,
                    "language": "ru",
                }
            )
        )
        settings_path.chmod(0o600)
        output.mkdir(parents=True, exist_ok=True)
        injected = threading.Event()
        faults: list[Exception] = []
        threads: list[threading.Thread] = []
        original_popen = subprocess.Popen

        def launch(*args: object, **kwargs: object) -> subprocess.Popen:
            process = original_popen(*args, **kwargs)

            def inject() -> None:
                deadline = time.monotonic() + 10
                try:
                    while time.monotonic() < deadline:
                        trace = output / "trace.jsonl"
                        if trace.exists() and '"ready":true' in trace.read_text():
                            name = (
                                f"preferences.tmp-{process.pid}"
                                if conflict == "temp"
                                else "preferences.json"
                            )
                            (root / "data" / name).write_bytes(b"foreign-preserve")
                            injected.set()
                            return
                        time.sleep(0.01)
                    raise RuntimeError("Нет ready для инъекции ошибки")
                except Exception as error:
                    faults.append(error)

            thread = threading.Thread(target=inject)
            threads.append(thread)
            thread.start()
            return process

        with patch("desktop_ui_smoke.subprocess.Popen", launch):
            execute(
                binary,
                root,
                [
                    ui("click", "settingsButton", when={"ready": True}),
                    ui("click", "settingsAppearanceButton"),
                    ui("key", "languageChoice", key="Down"),
                    ui("key", "languageChoice", key="Enter"),
                    ui(
                        "click",
                        "appearanceSaveError",
                        capture="runtime-write-error.png",
                        when={"error": "preferences_write"},
                        expect={
                            "window": {"language": "ru"},
                            "languageChoice": {"currentIndex": 0},
                            "appearanceSaveError": {
                                "visible": True,
                                "text": {"contains": "Не удалось сохранить"},
                            },
                        },
                    ),
                    {"when": {}, "command": {"command": "shutdown"}},
                ],
                output,
                "1",
            )
        for thread in threads:
            thread.join(timeout=12)
            assert not thread.is_alive()
        assert injected.is_set() and not faults, faults
        names = list((root / "data").glob("preferences.*"))
        assert any(path.read_bytes() == b"foreign-preserve" for path in names)
        (output / "result.json").write_text(
            json.dumps({"conflict": conflict, "visible_error": True, "language": "ru"})
            + "\n"
        )


if __name__ == "__main__":
    main()
    for conflict in ("temp", "changed"):
        runtime_write_failure(
            Path(sys.argv[1]).resolve(),
            Path(sys.argv[2]).resolve() / conflict,
            conflict,
        )
