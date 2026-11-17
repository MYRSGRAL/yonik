#!/usr/bin/env python3
"""Bounded stdio relay двух named test binaries; не runtime acceptance."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import subprocess
import time
from collections import deque
from pathlib import Path


def run(rust: Path, go: Path, timeout: float, case: str) -> dict[str, object]:
    env = os.environ | {"YONIK_PURE_INTEROP": "1", "YONIK_INTEROP_CASE": case}
    commands = {
        "rust": [
            str(rust),
            "pure_stateful_hosts_stdio_bridge",
            "--quiet",
            "--nocapture",
        ],
        "go": [str(go), "-test.run=^TestPureStatefulHostsStdioBridge$", "-test.v"],
    }
    # Rust test name содержит module path; filter уникален и проверен summary.
    children: dict[str, subprocess.Popen[bytes]] = {}
    trace: list[dict[str, object]] = []
    done: dict[str, object] = {}
    selector = selectors.DefaultSelector()
    buffers: dict[str, bytearray] = {}
    writes: dict[str, deque[memoryview]] = {side: deque() for side in commands}
    pending_bytes = dict.fromkeys(commands, 0)
    deadline = time.monotonic() + timeout
    total_bytes = 0

    def queue_write(side: str, payload: bytes) -> None:
        if sum(pending_bytes.values()) + len(payload) > 8 * 1024 * 1024:
            raise ValueError("relay pending write budget exhausted")
        stream = children[side].stdin
        assert stream is not None
        if not writes[side]:
            selector.register(stream, selectors.EVENT_WRITE, (side, "write"))
        writes[side].append(memoryview(payload))
        pending_bytes[side] += len(payload)

    try:
        for side, command in commands.items():
            child = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                bufsize=0,
            )
            children[side] = child
            assert child.stdout is not None
            assert child.stdin is not None
            os.set_blocking(child.stdout.fileno(), False)
            os.set_blocking(child.stdin.fileno(), False)
            selector.register(child.stdout, selectors.EVENT_READ, (side, "read"))
            buffers[side] = bytearray()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"interop deadline; trace={trace[-8:]}")
            for key, _ in selector.select(min(remaining, 1.0)):
                side, operation = key.data
                if operation == "write":
                    view = writes[side][0]
                    try:
                        count = os.write(key.fd, view)
                    except BlockingIOError:
                        continue
                    if count == 0:
                        raise BrokenPipeError(f"{side} write made no progress")
                    pending_bytes[side] -= count
                    if count == len(view):
                        writes[side].popleft()
                    else:
                        writes[side][0] = view[count:]
                    if not writes[side]:
                        selector.unregister(key.fileobj)
                    continue
                data = os.read(key.fd, 16384)
                if not data:
                    selector.unregister(key.fileobj)
                    if side not in done:
                        raise AssertionError(
                            f"{side} EOF without result; trace={trace[-12:]}"
                        )
                    continue
                buf = buffers[side]
                buf.extend(data)
                if len(buf) > 140_000:
                    raise ValueError("relay line exceeds bounded packet")
                while b"\n" in buf:
                    line, _, tail = buf.partition(b"\n")
                    buf[:] = tail
                    text = line.decode("utf-8", errors="strict")
                    total_bytes += len(line)
                    if len(trace) >= 512 or total_bytes > 8 * 1024 * 1024:
                        raise ValueError("relay transcript budget exhausted")
                    if not text.startswith("{"):
                        trace.append({"side": side, "test_output": text})
                        continue
                    value = json.loads(text)
                    if "packet" in value:
                        packet = bytes.fromhex(value["packet"])
                        if len(packet) > 65536:
                            raise ValueError("oversized packet")
                        trace.append({"side": side, "packet": packet.hex()})
                    elif "init" in value:
                        if case.startswith("system-"):
                            launch = bytes.fromhex(value["init"]["launch"])
                            if len(launch) != 192 or launch[:8] != b"YNKEXT01":
                                raise AssertionError(
                                    "System case requires exact System launch fixture"
                                )
                        trace.append({"side": side, "init": value["init"]})
                    else:
                        done[side] = value
                        trace.append({"side": side, "result": value})
                        if side == "go" and value.get("go_done"):
                            queue_write("rust", b'{"stop":true}\n')
                        continue
                    queue_write("go" if side == "rust" else "rust", line + b"\n")
        codes = {
            side: child.wait(timeout=max(0.01, deadline - time.monotonic()))
            for side, child in children.items()
        }
        if any(codes.values()) or not all(s in done for s in children):
            raise AssertionError(f"counterpart failed: {codes}; trace={trace[-12:]}")
        expected = int(case in ("positive", "system-positive"))
        expected_routes = int(case != "foreign-member")
        go_result, rust_result = done["go"], done["rust"]
        if (
            not go_result.get("go_done")
            or not go_result.get("cleanup")
            or go_result.get("attempts") != expected
            or go_result.get("kinds", [])[:7] != [55, 35, 40, 55, 35, 53, 42]
            or not rust_result.get("rust_done")
            or rust_result.get("routes") != expected_routes
            or rust_result.get("owners") != 0
            or case.startswith("system-")
            and go_result.get("mode") != 2
            or case == "system-parent-expired"
            and not (
                go_result.get("parent_expired")
                and go_result.get("permission_before_expiry")
            )
        ):
            raise AssertionError(f"incomplete actor roundtrip: {done}")
        return {
            "classification": "PURE_STATEFUL_INTEROP",
            "case": case,
            "commands": commands,
            "codes": codes,
            "results": done,
            "trace": trace,
        }
    finally:
        selector.close()
        for child in children.values():
            if child.poll() is None:
                child.terminate()
        for child in children.values():
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)
            for stream in (child.stdin, child.stdout):
                if stream is not None:
                    stream.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument(
        "--case",
        choices=(
            "positive",
            "foreign-member",
            "system-positive",
            "system-parent-expired",
        ),
        default="positive",
    )
    args = parser.parse_args()
    if not 0 < args.timeout <= 60:
        parser.error("timeout must be in (0,60]")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = run(
            args.rust.resolve(strict=True),
            args.go.resolve(strict=True),
            args.timeout,
            args.case,
        )
    except Exception as error:
        args.output.write_text(
            json.dumps(
                {
                    "classification": "PURE_STATEFUL_INTEROP",
                    "pass": False,
                    "error": str(error),
                },
                indent=2,
            )
            + "\n"
        )
        raise
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
