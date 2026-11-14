"""Только replacement sing-box pair №2: dry-run default, execute после root-review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ARTIFACTS = Path("/home/myrs/projects/yonik/local/evidence/p02-short-private-20261114")
ENGINES = Path("/home/myrs/projects/yonik/local/engines")
OUTPUT = Path("/home/myrs/projects/yonik/local/evidence/p02-replacement-sb2-reviewed")
PINS = {
    ARTIFACTS
    / "yonik-desktop": "e3aee54cab750d072dc1f9d075a3c5eb4b0911d96360d834d5680f3bd812e8f8",
    ARTIFACTS
    / "observer.so": "e7c94f3a66b6f6c7d439ea35ca6f0b867170aff4ee0d000a9c45be4b90b092d5",
    ENGINES
    / "sing-box-1.14.4/sing-box": "1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a",
    REPO
    / "tools/p02/connected_idle.py": "508f837200ffa07aaaca6e88cc296c41dd789bf6dfbd9aa054d6bd8c43536f23",
}


def digest(path: Path) -> str:
    """Хешировать artifact потоково, не загружая GUI ELF целиком в память."""
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def parser() -> argparse.ArgumentParser:
    """Закрытый selector: параметры документированы, расширить scope ими нельзя."""
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--execute", action="store_true")
    result.add_argument("--core", choices=["sing-box"], default="sing-box")
    result.add_argument("--pair", type=int, choices=[2], default=2)
    result.add_argument("--repeats", type=int, choices=[1], default=1)
    result.add_argument("--seconds", type=int, choices=[900], default=900)
    result.add_argument("--output", type=Path, default=OUTPUT)
    return result


def plan(args: argparse.Namespace) -> dict:
    """Только проверки и JSON: нет imports driver, fixtures, mkdir или процессов."""
    if (args.core, args.pair, args.repeats, args.seconds) != ("sing-box", 2, 1, 900):
        raise ValueError("Разрешена только sing-box pair2, один повтор, 900+900 s")
    if args.output != OUTPUT:
        raise ValueError("Разрешён только отдельный фиксированный replacement output")
    if OUTPUT.exists() or OUTPUT.is_symlink():
        raise FileExistsError(OUTPUT)
    for path, expected in PINS.items():
        if digest(path) != expected:
            raise ValueError(f"Artifact/source binding mismatch: {path}")
    return {
        "mode": "execute" if args.execute else "dry-run",
        "core": "sing-box",
        "replaces_old_pair": 2,
        "windows": [{"group": name, "seconds": 900} for name in ["full", "engine"]],
        "output": str(OUTPUT),
        "bindings": {str(path): value for path, value in PINS.items()},
        "selector_sha256": digest(Path(__file__)),
        "guard_source": "51fd15a3a94c1e5e2ca400e1dcd7ccf26438715e",
        "controls": "reuse unchanged /home/myrs/projects/yonik/local/evidence/p02-r2-targeted-20261114/completion.json",
        "config": "actual full GUI captured bytes -> same bytes object to engine_only; no recompilation",
        "fixture": "existing private loopback HTTPS/peer/gui helpers; free owned ports; no caller config",
        "environment": "GUI/private bus/SecretService via gui(); engine LANG=C, SSL_CERT_FILE=own CA; same fixture/CA",
        "acceptance": "bounded observational reuse only; replacement still requires review",
    }


def write_json(path: Path, value: object) -> None:
    """Сохранить только новый собственный evidence."""
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def run_pair(driver: object, binding: dict) -> None:
    """Ровно full→engine; этот путь unit-тестируется только с fake driver."""
    binary, observer = ARTIFACTS / "yonik-desktop", ARTIFACTS / "observer.so"
    core = ENGINES / "sing-box-1.14.4/sing-box"
    with (
        tempfile.TemporaryDirectory(prefix="p02-sb2-") as temporary,
        ExitStack() as stack,
    ):
        root = Path(temporary)
        fixture = stack.enter_context(
            driver.https_server(root, "health", 0, "127.0.0.1")
        )
        peer_port, socks = driver.port(), driver.port()
        health, ca = fixture.server_port, root / "health.ca.pem"
        stack.enter_context(driver.peer(core, "sing-box", root, peer_port))
        full_out = OUTPUT / "full"
        with driver.gui(
            binary, observer, ENGINES, full_out, peer_port, health, socks, ca
        ) as (app, control, handles):
            driver.prepare(control, "sing-box")
            control.send("connect")
            control.state(lambda state: state.get("status") == "Connected")
            pid, captured = driver.capture(app, core, full_out, handles)
            control.send("hide")
            control.wait(
                lambda record: not record["visible"] and record["tray_available"]
            )
            full = driver.idle([app.pid, pid], 900, full_out, fixture)
            driver.stop(control, pid, socks)
            if driver.descendants(app.pid):
                raise RuntimeError("Product children remain after Stop")
        write_json(
            OUTPUT / "progress.json", {"completed_windows": ["full"], "summary": full}
        )
        engine = driver.engine_only(
            "sing-box",
            core,
            captured,
            OUTPUT / "engine",
            socks,
            health,
            ca,
            fixture,
            900,
        )
        full_bytes = (full_out / "actual-config.json").read_bytes()
        engine_bytes = (OUTPUT / "engine/actual-config.json").read_bytes()
        if full_bytes != captured or engine_bytes != captured:
            raise RuntimeError("Pair config bytes mismatch")
        write_json(
            OUTPUT / "result.json",
            {
                "status": "REPLACEMENT_PAIR_RECORDED_REVIEW_REQUIRED",
                "binding": binding,
                "config_sha256": hashlib.sha256(captured).hexdigest(),
                "full": full,
                "engine": engine,
            },
        )


def execute(binding: dict) -> None:
    """Единственная runtime-точка: атомарный reserve output, deadline и cleanup helpers."""
    import connected_idle as driver

    OUTPUT.mkdir(mode=0o700, exist_ok=False)
    write_json(OUTPUT / "binding.json", binding)
    write_json(
        OUTPUT / "run.json",
        {
            "identity": driver.sample(os.getpid()),
            "started_unix": time.time(),
            "deadline_unix": time.time() + 2400,
        },
    )

    def interrupted(signum: int, frame: object) -> None:
        raise TimeoutError(f"Replacement interrupted: signal {signum}")

    previous = {
        sig: signal.signal(sig, interrupted)
        for sig in [signal.SIGALRM, signal.SIGTERM, signal.SIGINT]
    }
    signal.alarm(2400)
    try:
        run_pair(driver, binding)
    except BaseException as error:
        write_json(
            OUTPUT / "failure.json", {"status": "FAILED_NO_RETRY", "error": repr(error)}
        )
        raise
    finally:
        signal.alarm(0)
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main(argv: list[str] | None = None) -> None:
    """Без --execute производится только планирование."""
    binding = plan(parser().parse_args(argv))
    if binding["mode"] == "execute":
        execute(binding)
    else:
        print(json.dumps(binding, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
