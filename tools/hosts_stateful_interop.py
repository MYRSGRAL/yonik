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


def check_network_cleanup(trace: list[dict[str, object]]) -> int:
    """Проверяет ACK-барьеры по реальным кадрам, не создавая ответов actor'ам."""
    pending: dict[int, tuple[int, bytes]] = {}
    roots: dict[int, int] = {}
    required: dict[int, set[tuple[int, int]]] = {}
    acknowledged: set[tuple[int, int]] = set()
    closed = 0
    permissions: set[int] = set()

    def number(body: bytes, offset: int) -> int:
        if len(body) < offset + 8:
            raise AssertionError("truncated cleanup field")
        return int.from_bytes(body[offset : offset + 8], "big")

    for event in trace:
        if "packet" not in event:
            continue
        packet = bytes.fromhex(str(event["packet"]))
        if packet[:8] != b"YNKCAP01":
            continue
        if len(packet) < 128 or int.from_bytes(packet[12:16], "big") != len(packet):
            raise AssertionError("invalid cleanup frame")
        kind = int.from_bytes(packet[10:12], "big")
        sequence = number(packet, 16)
        reply = number(packet, 24)
        body = packet[128:]
        if event["side"] == "go":
            pending[sequence] = (kind, body)
            if kind == 32 and body[:1] == b"\x03":
                root = number(body, 4)
                if root in permissions:
                    continue
                contexts = [
                    context for context, owner in roots.items() if owner == root
                ]
                if not contexts:
                    raise AssertionError("service Close32 without acquired context")
                for context in contexts:
                    missing = required[context] - acknowledged
                    if missing:
                        raise AssertionError(f"Close32 before cleanup ACK: {missing}")
                closed += 1
            continue
        if kind == 19 and body[:1] == b"\x01":
            request = pending.get(reply)
            if request is not None and request[0] == 42:
                permissions.add(number(body, 4))
        if len(body) < 3 or body[2] != 1:
            continue
        request = pending.get(reply)
        if request is None:
            continue
        request_kind, sent = request
        if kind == 56 and request_kind == 55:
            context = number(body, 8)
            roots[context] = number(sent, 8)
            required[context] = {(8, context)}
        elif kind == 36 and request_kind == 35:
            context = number(body, 24)
            if context in required:
                required[context].add((7, number(body, 8)))
                if body[60] == 1:
                    required[context].add((2, number(body, 32)))
        elif kind in (37, 39):
            context = number(body, 32)
            if context not in required:
                raise AssertionError("transport ACK without context")
            required[context].add((3 if kind == 37 else 4, number(body, 16)))
        elif kind in (46, 48) and request_kind == (45 if kind == 46 else 47):
            target, identifier = sent[2], number(sent, 8)
            if number(body, 8) != identifier:
                raise AssertionError("cleanup ACK identifier mismatch")
            if kind == 46 and (
                body[3] != target
                or number(body, 16) != number(sent, 16)
                or body[24:28] != bytes(4)
                or body[28] != 1
            ):
                raise AssertionError("Retired46 lacks joined/zero-ref evidence")
            acknowledged.add((target, identifier))
    if not closed:
        raise AssertionError("missing actual service Close32")
    return closed


def check_datagram_cleanup(trace: list[dict[str, object]]) -> int:
    """Каждый real ACK58 требует cancel9 ACK после ACK собственных contexts."""
    pending: dict[int, tuple[int, bytes]] = {}
    parents: dict[int, int] = {}
    contexts: dict[int, int] = {}
    required: set[tuple[int, int]] = set()
    acknowledged: set[tuple[int, int]] = set()

    def number(b: bytes, at: int) -> int:
        if len(b) < at + 8:
            raise AssertionError("truncated UDP cleanup field")
        return int.from_bytes(b[at : at + 8], "big")

    for event in trace:
        if "packet" not in event:
            continue
        raw = bytes.fromhex(str(event["packet"]))
        if raw[:8] != b"YNKCAP01":
            continue
        if len(raw) < 128 or int.from_bytes(raw[12:16], "big") != len(raw):
            raise AssertionError("invalid UDP frame")
        kind = int.from_bytes(raw[10:12], "big")
        body = raw[128:]
        if event["side"] == "go":
            pending[number(raw, 16)] = (kind, body)
            if (
                kind == 32
                and number(body, 4) == 1
                and any((9, parent) not in acknowledged for parent in parents)
            ):
                raise AssertionError("USER Close32 before owned parent ACK9")
            if kind == 47 and len(body) >= 16 and body[2] == 9:
                parent = number(body, 8)
                if parent not in parents or any(
                    query == parents[parent] and (8, context) not in acknowledged
                    for context, query in contexts.items()
                ):
                    raise AssertionError("cancel9 before own context ACK")
            continue
        request = pending.get(number(raw, 24))
        if request is None:
            continue
        sent_kind, sent = request
        if kind == 19 and body[:1] == b"\x01" and sent_kind == 42:
            required.add((0, number(body, 4)))
        if kind == 34 and body[:2] == b"\x03\x01" and sent_kind == 32:
            acknowledged.add((0, number(body, 4)))
        if len(body) < 3 or body[2] != 1:
            continue
        if kind == 58 and sent_kind == 57:
            parents[number(body, 8)] = number(sent, 8)
            required.add((9, number(body, 8)))
        elif kind == 56 and sent_kind == 55:
            contexts[number(body, 8)] = number(sent, 16)
            required.add((8, number(body, 8)))
        elif kind == 36 and sent_kind == 35:
            required.add((7, number(body, 8)))
        elif kind == 41 and sent_kind == 40:
            required.add((5, number(body, 8)))
        elif kind == 54 and sent_kind == 53:
            required.add((6, number(body, 8)))
        elif kind == 48 and sent_kind == 47:
            if number(body, 8) != number(sent, 8):
                raise AssertionError("UDP cancel ACK ID mismatch")
            acknowledged.add((sent[2], number(body, 8)))
    if len(parents) != 2 or required - acknowledged:
        raise AssertionError(f"missing UDP cleanup ACK: {required - acknowledged}")
    return len(required)


def run(rust: Path, go: Path, timeout: float, case: str) -> dict[str, object]:
    env = os.environ | {"YONIK_PURE_INTEROP": "1", "YONIK_INTEROP_CASE": case}
    commands = {
        "rust": [
            str(rust),
            "pure_stateful_hosts_stdio_bridge",
            "--quiet",
            "--nocapture",
        ],
        "go": [
            str(go),
            "-test.run=^TestPureStatefulDatagramHostsSSStdioBridge$"
            if "udp-hosts-" in case
            else "-test.run=^TestPureStatefulHostsStdioBridge$",
            "-test.v",
        ],
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
                    if "packet" in value or "physical" in value:
                        field = "physical" if "physical" in value else "packet"
                        packet = bytes.fromhex(value[field])
                        if len(packet) > 65536:
                            raise ValueError("oversized packet")
                        if field == "physical" and (
                            len(packet) != 192 or packet[:8] != b"DNSPHY02"
                        ):
                            raise ValueError("invalid virtual PhysicalBind")
                        trace.append({"side": side, field: packet.hex()})
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
        network = case.startswith("network-")
        datagram = "udp-hosts-" in case
        if datagram:
            negative = case.endswith(("foreign-member", "parent-cancel"))
            expected = int(not negative)
            go_result, rust_result = done["go"], done["rust"]
            if (
                not go_result.get("cleanup")
                or not go_result.get("ss_consumer")
                or go_result.get("retained_operations")
                != go_result.get("preseed_operations")
                or go_result.get("attempts") != expected
                or go_result.get("sends") != expected
                or go_result.get("socket_closes") != expected
                or go_result.get("tasks_joined") != 2 * expected
                or go_result.get("kinds", [])[:9]
                != [57, 55, 35, 40, 57, 55, 35, 53, 42]
                or not rust_result.get("rust_done")
                or rust_result.get("routes")
                != (1 if case.endswith("foreign-member") else 2)
                or rust_result.get("owners") != rust_result.get("preseed_owners")
                or len(rust_result.get("retained_routes", []))
                != int(not case.endswith("parent-cancel"))
                or rust_result.get("contexts") != 0
                or rust_result.get("services")
                or rust_result.get("unknown")
                or case.startswith("system-")
                and go_result.get("mode") != 2
                or case.endswith("replay")
                and not go_result.get("replay_rejected")
            ):
                raise AssertionError(f"incomplete UDP actor roundtrip: {done}")
            return {
                "classification": "PURE_STATEFUL_INTEROP",
                "case": case,
                "commands": commands,
                "codes": codes,
                "results": done,
                "datagram_cleanup_barriers": check_datagram_cleanup(trace),
                "trace": trace,
            }
        expected = int(case in ("positive", "system-positive", "network-positive"))
        expected_routes = (
            (5 if case == "network-positive" else 2)
            if network
            else int(case != "foreign-member")
        )
        prefix = (
            [20, 55, 35, 35, 52, 38, 40, 20, 55, 35, 53, 42]
            if case == "network-positive"
            else [20, 55, 35, 35]
            if network
            else [55, 35, 40, 55, 35, 53, 42]
        )
        go_result, rust_result = done["go"], done["rust"]
        if (
            not go_result.get("go_done")
            or (
                not go_result.get("cleanup")
                and not (
                    case == "network-no-permit"
                    and go_result.get("unknown")
                    and go_result.get("retained_operations", 0) > 0
                )
            )
            or go_result.get("attempts") != expected
            or go_result.get("kinds", [])[: len(prefix)] != prefix
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
        if (
            network
            and go_result.get("cleanup")
            and (
                rust_result.get("retained_routes")
                or rust_result.get("contexts") != 0
                or rust_result.get("services")
                or rust_result.get("unknown")
                or rust_result.get("receiver_consumed_closes") != 1
            )
        ):
            raise AssertionError(f"counterpart route custody mismatch: {done}")
        cleanup_barriers = (
            check_network_cleanup(trace) if network and go_result.get("cleanup") else 0
        )
        return {
            "classification": "PURE_STATEFUL_INTEROP",
            "case": case,
            "commands": commands,
            "codes": codes,
            "results": done,
            "cleanup_service_barriers": cleanup_barriers,
            "trace": trace,
        }
    except Exception as error:
        error.interop_trace = trace
        raise
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
            "network-positive",
            "network-wrong-question",
            "network-no-permit",
            "udp-hosts-positive",
            "system-udp-hosts-positive",
            "udp-hosts-foreign-member",
            "udp-hosts-parent-cancel",
            "udp-hosts-replay",
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
                    "trace": getattr(error, "interop_trace", []),
                },
                indent=2,
            )
            + "\n"
        )
        raise
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
