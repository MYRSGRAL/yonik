#!/usr/bin/env python3
"""Короткая частная X11-проверка; не физический benchmark и не idle acceptance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import ui_benchmark as driver


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_counter(report: dict, nonce: int, previous: int) -> int:
    if type(report.get("nonce")) is not int or report["nonce"] != nonce:
        raise driver.BenchmarkError("Некорректный или stale nonce")
    count = report.get("rendered_frames")
    if type(count) is not int or not previous <= count < 2**64 - 1:
        raise driver.BenchmarkError("Некорректный/убывающий/overflow frame counter")
    return count


def require_canary(before: int, after: int) -> None:
    if after <= before:
        raise driver.BenchmarkError("Frozen/disconnected native frame observation")


def exercise(
    child: driver.Child, oracle: driver.Oracle, toolkit: str, record: dict
) -> None:
    nonce = 0
    counter = 0
    record["probes"] = []
    record["actions"] = []

    def probe(
        label: str, requested_nonce: int | None = None, sample_metrics: bool = True
    ) -> int:
        nonlocal nonce, counter
        nonce = nonce + 1 if requested_nonce is None else requested_nonce
        child.send(dict(op="probe", nonce=nonce), 15)
        report, _ = child.ack(15)
        counter = validate_counter(report, nonce, counter)
        oracle.validate(
            {k: v for k, v in report.items() if k not in ("nonce", "rendered_frames")},
            "probe",
        )
        if report["toolkit"] != toolkit:
            raise driver.BenchmarkError("Probe toolkit mismatch")
        record["probes"].append(
            dict(
                label=label,
                report=report,
                process=driver.sample_process(child.process.pid)
                if sample_metrics
                else None,
            )
        )
        return counter

    def action(command: dict, label: str) -> None:
        event = oracle.apply(command)
        start = time.monotonic_ns()
        child.send(command, 15)
        report, _ = child.ack(15)
        oracle.validate(report, event)
        if report["toolkit"] != toolkit:
            raise driver.BenchmarkError("Toolkit mismatch")
        record["reports"].append(report)
        record["actions"].append(
            dict(
                label=label,
                command=command,
                latency_ms=(time.monotonic_ns() - start) / 1e6,
                process=driver.sample_process(child.process.pid),
            )
        )

    def quiet(label: str) -> None:
        # GUI не опрашивается; сохраняются settling facts до проверки двух Probe.
        for attempt in range(4):
            before = probe(f"{label}-before-{attempt}")
            deadline = time.monotonic() + 0.3
            while time.monotonic() < deadline:
                child.pump(max(0, deadline - time.monotonic()))
                child.alive()
                if child.pending or child.buffer:
                    raise driver.BenchmarkError("Unsolicited idle stdout")
            after = probe(f"{label}-after-{attempt}")
            if after == before:
                return
        # Нулевой idle frame budget не является условием preflight: GTK может
        # выдавать paint cycles без команд. Проверяем отдельную быструю пару,
        # не внося /proc sampling между GUI read-only probes.
        nonlocal nonce, counter
        pair = []
        # Между ack A и отправкой B нет Oracle/JSON state recomputation:
        # независимый Oracle на 10000 строках сам занимает часть frame interval.
        for suffix in ("A", "B"):
            nonce += 1
            child.send(dict(op="probe", nonce=nonce), 15)
            report, _ = child.ack(15)
            pair.append((nonce, suffix, report))
        counts = []
        for requested, suffix, report in pair:
            counter = validate_counter(report, requested, counter)
            oracle.validate(
                {
                    k: v
                    for k, v in report.items()
                    if k not in ("nonce", "rendered_frames")
                },
                "probe",
            )
            if report["toolkit"] != toolkit:
                raise driver.BenchmarkError("Probe pair toolkit mismatch")
            counts.append(counter)
            record["probes"].append(
                dict(label=f"{label}-immediate-{suffix}", report=report, process=None)
            )
        if counts[0] != counts[1]:
            raise driver.BenchmarkError(
                "No-mutation immediate Probe pair changed counter"
            )

    before = probe("canary-A")
    action(dict(op="scroll", index=199), "canary-scroll")
    after = probe("canary-B")
    require_canary(before, after)
    record["canary"] = dict(
        before=before,
        after=after,
        negative_control_kind="injected probe observation; native observer unchanged",
    )
    for label, observed in (("frozen", before), ("disconnected", 0)):
        try:
            injected = dict(record["probes"][-1]["report"], rendered_frames=observed)
            require_canary(before, validate_counter(injected, nonce, before))
        except driver.BenchmarkError:
            record["negative_controls"].append(label)
        else:
            raise driver.BenchmarkError("Counter negative control accepted")
    for label, patch in (
        ("stale-nonce", {"nonce": nonce - 1}),
        ("counter-overflow", {"rendered_frames": 2**64 - 1}),
    ):
        try:
            validate_counter(
                dict(record["probes"][-1]["report"], **patch), nonce, before
            )
        except driver.BenchmarkError:
            record["negative_controls"].append(label)
        else:
            raise driver.BenchmarkError("Invalid probe observation accepted")
    quiet("visible-initial")
    for command, label in (
        (driver.query(), "page"),
        (driver.query("server-0.example.invalid"), "cold-search"),
        (driver.query("server-0.example.invalid"), "warm-search"),
        (dict(op="select", id=1), "select"),
        (dict(op="favorite", id=1, value=True), "favorite"),
        (driver.query(favorites_only=True), "filter"),
        (driver.query(), "reset"),
        (driver.query(sort="name"), "sort"),
        (dict(op="scroll", index=199), "scroll"),
    ):
        action(command, label)
        probe(label)
    quiet("visible-final")
    action(dict(op="hide"), "hide")
    quiet("hidden")
    action(dict(op="show"), "show")
    probe("shown")
    quiet("shown-settle")
    probe("u64-max-nonce", 2**64 - 1)


def malformed_probe(binary: Path, output: Path, toolkit: str, records: list) -> None:
    for index, bad in enumerate((-1, True, "1", 2**64)):
        record = dict(toolkit=toolkit, malformed_nonce=bad, rejected=False)
        records.append(record)
        child = driver.Child(
            [str(binary), "--rows", "1000"],
            output / f"{toolkit}-malformed-{index}.stderr",
        )
        try:
            report, _ = child.ack(15)
            driver.Oracle(1000).validate(report, "frame")
            child.send(dict(op="probe", nonce=bad), 15)
            try:
                child.ack(15)
            except driver.BenchmarkError as error:
                if "invalid_input" not in str(error):
                    raise
                record["rejected"] = True
            else:
                raise driver.BenchmarkError("Native parser accepted malformed nonce")
            child.finish(15)
        finally:
            child.close()
            record["reaped"] = child.process.returncode is not None
            record["proc_absent"] = not Path(f"/proc/{child.process.pid}").exists()


def pending_quit(binary: Path, output: Path, toolkit: str, records: list) -> None:
    record = dict(toolkit=toolkit, valid=False)
    records.append(record)
    child = driver.Child(
        [str(binary), "--rows", "1000"], output / f"{toolkit}-pending-quit.stderr"
    )
    try:
        oracle = driver.Oracle(1000)
        report, _ = child.ack(15)
        oracle.validate(report, "frame")
        child.send(dict(op="hide"), 15)
        report, _ = child.ack(15)
        oracle.validate(report, oracle.apply(dict(op="hide")))
        child.send(dict(op="scroll", index=199), 15)
        child.send(dict(op="quit"), 15)
        try:
            child.send(dict(op="probe", nonce=1), 15)
        except driver.BenchmarkError as error:
            # Quit может закрыть stdin до доставки отменённого Probe.
            if "stdin" not in str(error):
                raise
            record["probe_write_cancelled"] = True
        child.finish(15)
        record["valid"] = True
    finally:
        child.close()
        record["reaped"] = child.process.returncode is not None
        record["proc_absent"] = not Path(f"/proc/{child.process.pid}").exists()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--xvfb", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.artifacts / "manifest.json").read_text())
    for toolkit in ("qt", "gtk", "slint"):
        name = f"yonik-bench-{toolkit}"
        if digest(args.artifacts / name) != manifest["binary"][name]["sha256"]:
            parser.error(f"SHA-256: {name}")
    args.output.mkdir(parents=True, exist_ok=False)
    os.environ.update(
        DISPLAY="",
        XDG_SESSION_TYPE="x11",
        QT_QPA_PLATFORM="xcb",
        QT_QUICK_BACKEND="software",
        GDK_BACKEND="x11",
        GSK_RENDERER="cairo",
        GTK_A11Y="none",
        LIBGL_ALWAYS_SOFTWARE="1",
        GALLIUM_DRIVER="llvmpipe",
        MESA_LOADER_DRIVER_OVERRIDE="llvmpipe",
        WINIT_UNIX_BACKEND="x11",
    )
    os.environ.pop("WAYLAND_DISPLAY", None)
    records = []
    malformed = []
    quit_pending = []
    evidence = dict(
        scope="private-X11 software-only; P01/P02 background potential noise",
        spontaneous_frames_observable=True,
        gpu=None,
        hardware_power=None,
        counter_definitions=dict(
            qt="QQuickWindow.frameSwapped",
            gtk="GdkFrameClock.after-paint; paint cycle, not presentation",
            slint="RenderingState.AfterRendering",
        ),
        source_tree_scope="bench/ui subtree only",
        xvfb_sha256=digest(args.xvfb),
        environment={
            k: os.environ[k]
            for k in (
                "QT_QPA_PLATFORM",
                "QT_QUICK_BACKEND",
                "GDK_BACKEND",
                "GSK_RENDERER",
                "LIBGL_ALWAYS_SOFTWARE",
                "GALLIUM_DRIVER",
            )
        },
        records=records,
        malformed=malformed,
        quit_pending=quit_pending,
    )
    cancellation = driver.Cancellation()
    read_fd, write_fd = os.pipe()
    server = None
    try:
        with (args.output / "xvfb.stderr").open("xb") as log:
            server = subprocess.Popen(
                [
                    str(args.xvfb),
                    "-displayfd",
                    str(write_fd),
                    "-screen",
                    "0",
                    "1024x768x24",
                    "-nolisten",
                    "tcp",
                    "-ac",
                    "-noreset",
                ],
                pass_fds=(write_fd,),
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
        os.close(write_fd)
        write_fd = -1
        if not select.select([read_fd], [], [], 10)[0]:
            raise RuntimeError("Xvfb displayfd timeout")
        display = os.read(read_fd, 64).decode().strip()
        if not display.isdecimal():
            raise RuntimeError("Xvfb displayfd invalid")
        os.environ["DISPLAY"] = ":" + display
        evidence["display"] = os.environ["DISPLAY"]
        for toolkit in ("qt", "gtk", "slint"):
            for rows in (1000, 10000):
                cancellation.check()
                record = dict(
                    toolkit=toolkit,
                    rows=rows,
                    valid=False,
                    reports=[],
                    negative_controls=[],
                )
                records.append(record)
                child = None
                try:
                    child = driver.Child(
                        [
                            str(args.artifacts / f"yonik-bench-{toolkit}"),
                            "--rows",
                            str(rows),
                        ],
                        args.output / f"{toolkit}-{rows}.stderr",
                    )
                    record["pid"] = child.process.pid
                    oracle = driver.Oracle(rows)
                    report, _ = child.ack(15)
                    oracle.validate(report, "frame")
                    record["first_frame_ms"] = (
                        time.monotonic_ns() - child.spawn_ns
                    ) / 1e6
                    record["reports"].append(report)
                    for field, value in (
                        ("page_hash", "0000000000000000"),
                        ("event", "hidden"),
                    ):
                        corrupted = dict(report, **{field: value})
                        try:
                            oracle.validate(corrupted, "frame")
                        except driver.BenchmarkError:
                            record["negative_controls"].append(field)
                        else:
                            raise RuntimeError(f"Oracle accepted corruption: {field}")
                    exercise(child, oracle, toolkit, record)
                    record["process"] = driver.sample_process(child.process.pid)
                    child.send(dict(op="quit"), 15)
                    child.finish(15)
                    record["valid"] = True
                except (driver.BenchmarkError, OSError, RuntimeError) as error:
                    record["error"] = str(error)
                finally:
                    if child is not None:
                        child.close()
                        record["reaped"] = child.process.returncode is not None
                        record["proc_absent"] = not Path(
                            f"/proc/{child.process.pid}"
                        ).exists()
        comparable = []
        for rows in (1000, 10000):
            group = [r for r in records if r["rows"] == rows and r["valid"]]
            comparable.append(
                len(group) == 3
                and all(
                    [a["command"] for a in r["actions"]]
                    == [a["command"] for a in group[0]["actions"]]
                    for r in group
                )
            )
        evidence["matched_workload"] = all(comparable)
        for toolkit in ("qt", "gtk", "slint"):
            malformed_probe(
                args.artifacts / f"yonik-bench-{toolkit}",
                args.output,
                toolkit,
                malformed,
            )
        for toolkit in ("qt", "gtk", "slint"):
            pending_quit(
                args.artifacts / f"yonik-bench-{toolkit}",
                args.output,
                toolkit,
                quit_pending,
            )
        cancellation.check()
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
            evidence["xvfb_reaped"] = server.returncode is not None
            evidence["xvfb_proc_absent"] = not Path(f"/proc/{server.pid}").exists()
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        cancellation.restore()
        (args.output / "evidence.json").write_text(
            json.dumps(evidence, ensure_ascii=False, indent=2) + "\n"
        )
    return (
        0
        if len(records) == 6
        and all(r["valid"] for r in records)
        and evidence.get("matched_workload")
        and len(quit_pending) == 3
        and all(r["valid"] for r in quit_pending)
        and len(malformed) == 12
        and all(r["rejected"] for r in malformed)
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
