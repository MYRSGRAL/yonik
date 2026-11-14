#!/usr/bin/env python3
"""Создать новый read-only snapshot; старые ELF/bindings не перезаписываются."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FROZEN = "0c184394de3a336048c065f74075e3555fc70068"
SPEC = importlib.util.spec_from_file_location(
    "campaign_runner", Path(__file__).with_name("runner.py")
)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def frozen(path: str) -> None:
    expected = subprocess.check_output(["git", "show", f"{FROZEN}:{path}"], cwd=ROOT)
    if (ROOT / path).read_bytes() != expected:
        raise ValueError(f"Frozen source изменён: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-artifacts", type=Path, required=True)
    parser.add_argument("--xvfb", type=Path, required=True)
    parser.add_argument("--xvfb-provenance", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT) or output.is_relative_to(
        "/var/tmp/codex-myrs/transient"
    ):
        parser.error("Snapshot должен быть вне mutable worktree и TTL")
    native = json.loads((args.native_artifacts / "manifest.json").read_text())
    sources = [
        "tools/ui_benchmark.py",
        "tools/resource_counters.py",
        "bench/ui/private-x11-preflight.py",
    ]
    for path in sources:
        frozen(path)
    for path, digest in native["compiled_inputs"].items():
        frozen(path)
        if runner.sha(ROOT / path) != digest:
            raise ValueError(f"Native input SHA mismatch: {path}")
    if len(native["compiled_inputs"]) != 17:
        raise ValueError("Ожидались 17 native inputs")
    for toolkit in ("qt", "gtk", "slint"):
        name = f"yonik-bench-{toolkit}"
        if runner.sha(args.native_artifacts / name) != native["binary"][name]["sha256"]:
            raise ValueError(f"ELF mismatch: {name}")
    output.mkdir(parents=True, exist_ok=False)
    copied = []

    def copy(source: Path, relative: str, executable: bool = False) -> None:
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with source.open("rb") as original, target.open("xb") as destination:
            shutil.copyfileobj(original, destination)
            destination.flush()
            os.fsync(destination.fileno())
        target.chmod(0o555 if executable else 0o444)
        copied.append(relative)

    for path in [*sources, *native["compiled_inputs"], "bench/ui/campaign/runner.py"]:
        copy(ROOT / path, path)
    for toolkit in ("qt", "gtk", "slint"):
        name = f"yonik-bench-{toolkit}"
        copy(args.native_artifacts / name, "bin/" + name, True)
    copy(args.xvfb, "bin/Xvfb", True)
    copy(Path(__file__), "provenance/create_snapshot.py")
    copy(args.xvfb_provenance, "provenance/xvfb-runtime-inputs.json")
    copy(args.native_artifacts / "manifest.json", "provenance/native-manifest.json")
    host_paths = set()
    for executable in [
        args.xvfb,
        *[
            args.native_artifacts / f"yonik-bench-{toolkit}"
            for toolkit in ("qt", "gtk", "slint")
        ],
    ]:
        libraries = subprocess.check_output(["ldd", str(executable)], text=True)
        if "not found" in libraries:
            raise ValueError(f"Host closure неполон: {executable.name}")
        host_paths.update(
            str(Path(path).resolve()) for path in re.findall(r"/[^\s()]+", libraries)
        )
    host_paths.add(str(Path(sys.executable).resolve()))
    host_paths.add(str(Path(shutil.which("xkbcomp") or "/usr/bin/xkbcomp").resolve()))
    if not all(path.startswith("/usr/") for path in host_paths):
        raise ValueError("Host closure должен быть read-only trusted /usr")
    manifest = dict(
        schema_version=1,
        origin_worktree=str(ROOT),
        frozen_native_commit=FROZEN,
        native_build_subtree=native["source_tree"],
        native_inputs=native["compiled_inputs"],
        files={path: runner.sha(output / path) for path in copied},
        host_inputs={path: runner.sha(Path(path)) for path in sorted(host_paths)},
        python_version=sys.version,
        python_executable=str(Path(sys.executable).resolve()),
        contract=runner.CONTRACT,
        frame_definitions=runner.DEFINITIONS,
        immutability="SHA-256 + read-only permissions; cooperative same-UID integrity, not adversarial filesystem sealing",
        host_runtime="Python stdlib/extensions and trusted host shared libraries remain host inputs; not a fully hermetic OS image",
    )
    runner.atomic_json(output / "manifest.json", manifest)
    (output / "manifest.json").chmod(0o444)
    for path in sorted(output.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.is_dir():
            path.chmod(0o555)
    output.chmod(0o555)
    digest = runner.sha(output / "manifest.json")
    print(
        json.dumps(
            dict(
                snapshot=str(output),
                manifest_sha256=digest,
                future_command=[
                    "setsid",
                    "--wait",
                    manifest["python_executable"],
                    "-I",
                    "-B",
                    str(output / "bench/ui/campaign/runner.py"),
                    "--mode",
                    "campaign",
                    "--manifest-sha256",
                    digest,
                    "--output",
                    "<NEW_OUTSIDE_TTL_DIRECTORY>",
                ],
            ),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
