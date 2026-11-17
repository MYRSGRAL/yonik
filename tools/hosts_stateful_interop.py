#!/usr/bin/env python3
"""Bounded stdio relay двух named test binaries; не runtime acceptance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import subprocess
import time
from collections import deque
from pathlib import Path


def check_france_binding(trace: list[dict[str, object]]) -> dict[str, object]:
    """Read-only oracle общей session. Не создаёт frames/ACK/authority."""
    initial = [e["init"] for e in trace if "init" in e]
    if len(initial) != 1:
        raise AssertionError("France requires one init/launch")
    initial = initial[0]
    launch, config = bytes.fromhex(initial["launch"]), bytes.fromhex(initial["config"])
    if len(launch) != 192 or hashlib.sha256(config).digest() != launch[48:80]:
        raise AssertionError("France final config/launch mismatch")
    outbounds = [o for o in json.loads(config)["outbounds"] if o["tag"] == "proxy"]
    if (
        len(outbounds) != 1
        or outbounds[0]["protocol"] != "shadowsocks"
        or outbounds[0]["settings"]
        != {
            "servers": [
                {
                    "address": "fr.example.invalid",
                    "port": 443,
                    "method": "aes-128-gcm",
                    "password": "synthetic-password",
                }
            ]
        }
    ):
        raise AssertionError("full FranceSS settings changed")
    paths = {
        tuple(tuple(h) for h in initial[key]): carrier
        for key, carrier in [("tcp_path", 6), ("udp_path", 17)]
    }
    if len(paths) != 2:
        raise AssertionError("TCP/UDP checked paths aliased")
    pending: dict[int, tuple[int, bytes]] = {}
    contexts: dict[int, tuple[tuple[int, int], ...]] = {}
    queries: dict[int, tuple[tuple[int, int], ...]] = {}
    reservations: dict[int, int] = {}
    producers: dict[int, int] = {}
    waiters: dict[int, int] = {}
    permissions: dict[int, int] = {}
    parents: set[int] = set()
    closed_parents: set[int] = set()
    closed_permissions: set[int] = set()
    neighbor_events = 0
    descriptors, acks, admissions = 0, 0, 0
    descriptor = b""

    def n(b: bytes, at: int) -> int:
        if at + 8 > len(b):
            raise AssertionError("truncated France field")
        return int.from_bytes(b[at : at + 8], "big")

    for e in trace:
        if "event" in e:
            detail = e["event"]
            if (
                detail["name"] != "tcp_neighbor_after_udp_cleanup"
                or detail["grant"] != 2
                or detail["protocol"] != 6
                or not parents
                or parents - closed_parents
                or not any(
                    p == 6 and i not in closed_permissions
                    for i, p in permissions.items()
                )
            ):
                raise AssertionError(
                    "neighbor before UDP ACKs or without live TCP permission"
                )
            neighbor_events += 1
            continue
        if "physical" in e:
            raise AssertionError("HOSTS emitted DNS PhysicalBind")
        if "packet" not in e:
            continue
        raw = bytes.fromhex(e["packet"])
        if raw[:8] == b"DNSNEG02":
            descriptors += 1
            descriptor = raw
            if (
                e["side"] != "go"
                or len(raw) != 272
                or raw[16:208] != launch
                or raw[208:240] != hashlib.sha256(b"YONIK-DNS-V2-CODEC-5\0").digest()
            ):
                raise AssertionError("France descriptor downgrade/mixed launch")
            continue
        if raw[:8] == b"DNSACK02":
            acks += 1
            if (
                e["side"] != "rust"
                or raw != b"DNSACK02" + hashlib.sha256(descriptor).digest()
            ):
                raise AssertionError("France ACK binding")
            continue
        if (
            raw[:8] != b"YNKCAP01"
            or len(raw) < 128
            or int.from_bytes(raw[12:16], "big") != len(raw)
        ):
            raise AssertionError("France frame header")
        if (
            raw[32:48] != launch[80:96]
            or raw[48:64] != launch[96:112]
            or raw[64:96] != launch[48:80]
            or raw[96:112] != launch[112:128]
        ):
            raise AssertionError("mixed France frame binding")
        kind = int.from_bytes(raw[10:12], "big")
        b = raw[128:]
        if kind == 2:
            admissions += 1
            if e["side"] != "rust" or b[:32] != launch[152:184]:
                raise AssertionError("France manifest binding")
            # Независимое чтение DATA rows, не issuer decoder и не proof mint.
            at = 128
            rows = {}
            for table in range(1, 12):
                if at + 8 > len(b) or int.from_bytes(b[at : at + 2], "big") != table:
                    raise AssertionError("France capsule tables")
                count = int.from_bytes(b[at + 2 : at + 4], "big")
                size = int.from_bytes(b[at + 4 : at + 8], "big")
                at += 8
                end = at + size
                caps = (256, 512, 1024, 256, 64, 16, 4, 1, 512, 16, 1)
                if count > caps[table - 1] or end > len(b):
                    raise AssertionError("France capsule bounds")
                rows[table] = []
                for _ in range(count):
                    if at + 4 > end:
                        raise AssertionError("France row header")
                    length = int.from_bytes(b[at : at + 2], "big")
                    at += 4
                    if at + length > end:
                        raise AssertionError("France row bounds")
                    rows[table].append(b[at : at + length])
                    at += length
                if at != end or end > len(b):
                    raise AssertionError("France capsule bounds")
            expected = bytes.fromhex(
                "010000006eef7fffac9bb760fff69a2c41df43aaad73104657c75088f69e2168e967053a"
            )
            if at != len(b) or rows[4] != [expected] or len(rows[1]) != 1:
                raise AssertionError("France stream fingerprint/settings")
            for path, carrier in paths.items():
                if (
                    len(path) != 1
                    or path[0][1] != 0
                    or rows[9][path[0][0]][2] != carrier
                    or rows[9][path[0][0]][4] != carrier
                ):
                    raise AssertionError("France carrier projection")
            continue
        if e["side"] == "go":
            pending[n(raw, 16)] = (kind, b)
            continue
        req = pending.get(n(raw, 24))
        if req is None:
            continue
        sent_kind, sent = req
        if kind == 58 and b[2] == 1:
            parents.add(n(b, 8))
        elif kind == 48 and b[2] == 1 and sent[2] == 9:
            closed_parents.add(n(sent, 8))
        elif kind == 34 and b[:2] == b"\x03\x01":
            closed_permissions.add(n(b, 4))
        elif kind == 56 and b[2] == 1:
            count = int.from_bytes(sent[50:52], "big")
            if count != 1:
                raise AssertionError("France raw frontier count")
            path = ((int.from_bytes(sent[-4:-2], "big"), sent[-2]),)
            if path not in paths or n(b, 24) != n(sent, 16) or n(b, 8) in contexts:
                raise AssertionError("foreign context path/query")
            contexts[n(b, 8)] = path
            queries[n(sent, 16)] = path
        elif kind == 36 and b[2] == 1:
            reservations[n(b, 8)] = n(sent, 8)
        elif kind == 41 and b[2] == 1:
            query = n(sent, 12)
            if sent[136:138] != b"\x03\x02" or paths[queries[query]] != sent[142]:
                raise AssertionError("France Hosts DATA kind/carrier")
            producers[n(b, 8)] = query
        elif kind == 54 and b[2] == 1:
            if (
                n(b, 24) != n(sent, 8)
                or n(b, 16) != n(sent, 16)
                or n(b, 32) != n(sent, 32)
                or reservations[n(sent, 8)] != n(sent, 32)
                or producers[n(sent, 16)] == n(sent, 32)
                or queries[producers[n(sent, 16)]] != queries[n(sent, 32)]
            ):
                raise AssertionError("waiter borrowed producer/query authority")
            waiters[n(b, 8)] = n(sent, 32)
        elif kind == 19 and b[0] == 1 and sent_kind == 42:
            carrier = sent[25]
            if (
                n(sent, 4) not in waiters
                or carrier != paths[queries[waiters[n(sent, 4)]]]
                or sent[14:16] != b"\x02\x03"
                or n(b, 4) in (1, 2)
                or int.from_bytes(sent[26:28], "big") != 443
                or sent[31:] != bytes([203, 0, 113, 80])
            ):
                raise AssertionError("wrong waiter/member/USER namespace")
            permissions[n(b, 4)] = carrier
    if admissions != 1 or descriptors != 1 or acks > 1 or contexts and acks != 1:
        raise AssertionError("multiple France admission/setup")
    return {
        "admissions": admissions,
        "descriptors": descriptors,
        "acks": acks,
        "contexts": len(contexts),
        "producers": len(producers),
        "waiters": len(waiters),
        "permission_carriers": sorted(permissions.values()),
        "neighbor_events": neighbor_events,
    }


def check_network_cleanup(
    trace: list[dict[str, object]], user_grants: frozenset[int] = frozenset()
) -> int:
    """Проверяет ACK-барьеры по реальным кадрам, не создавая ответов actor'ам."""
    pending: dict[int, tuple[int, bytes]] = {}
    roots: dict[int, int] = {}
    required: dict[int, set[tuple[int, int]]] = {}
    acknowledged: set[tuple[int, int]] = set()
    closed = 0
    permissions: set[int] = set()
    query_parents: dict[int, int] = {}
    resource_contexts: dict[int, int] = {}
    proof_contexts: dict[int, int] = {}
    held: set[tuple[int, int]] = set()

    def number(body: bytes, offset: int) -> int:
        if len(body) < offset + 8:
            raise AssertionError("truncated cleanup field")
        return int.from_bytes(body[offset : offset + 8], "big")

    for event in trace:
        if "event" in event:
            detail = event["event"]
            key = (int(detail["target"]), int(detail["id"]))
            if detail["name"] == "ack_hold":
                if key not in acknowledged or key in held:
                    raise AssertionError("hold without actual ACK")
                acknowledged.remove(key)
                held.add(key)
            elif detail["name"] == "ack_release":
                if key not in held:
                    raise AssertionError("release without actual held ACK")
                held.remove(key)
                acknowledged.add(key)
            else:
                raise AssertionError("unknown ACK event")
            continue
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
            if kind == 45 and body[2] == 3:
                context = resource_contexts.get(number(body, 8))
                if context is None or any(
                    c == context and (4, proof) not in acknowledged
                    for proof, c in proof_contexts.items()
                ):
                    raise AssertionError("Resource retire before Proof ACK")
            if kind == 32 and body[:1] == b"\x03":
                root = number(body, 4)
                if root in permissions or root in user_grants:
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
        if kind == 58 and request_kind == 57:
            query_parents[number(sent, 8)] = number(body, 8)
        elif kind == 56 and request_kind == 55:
            context = number(body, 8)
            roots[context] = number(sent, 8)
            required[context] = {(8, context)}
            if number(sent, 16) in query_parents:
                required[context].add((9, query_parents[number(sent, 16)]))
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
            (resource_contexts if kind == 37 else proof_contexts)[number(body, 16)] = (
                context
            )
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
    if held:
        raise AssertionError("retained held ACK")
    if not closed:
        raise AssertionError("missing actual service Close32")
    return closed


def check_datagram_cleanup(
    trace: list[dict[str, object]], minimum_parents: int = 2
) -> int:
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
    if len(parents) < minimum_parents or required - acknowledged:
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
            "-test.run=^TestPureStatefulFranceSSStdioBridge$"
            if "france-" in case
            else "-test.run=^TestPureStatefulDatagramHostsSSStdioBridge$"
            if "udp-hosts-" in case or "udp-network-" in case
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
                    elif "event" in value:
                        trace.append({"side": side, "event": value["event"]})
                        continue
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
                        if side == "rust" and value.get("setup_denied"):
                            # Отказ SUT — test control, не fabricated wire ACK.
                            queue_write("go", line + b"\n")
                        if side == "go" and value.get("go_done") and "rust" not in done:
                            queue_write("rust", b'{"stop":true}\n')
                        continue
                    queue_write("go" if side == "rust" else "rust", line + b"\n")
        codes = {
            side: child.wait(timeout=max(0.01, deadline - time.monotonic()))
            for side, child in children.items()
        }
        if any(codes.values()) or not all(s in done for s in children):
            raise AssertionError(f"counterpart failed: {codes}; trace={trace[-12:]}")
        if "france-" in case:
            go_result, rust_result = done["go"], done["rust"]
            bindings = check_france_binding(trace)
            if case.endswith("missing-udp-scope"):
                if (
                    not (
                        go_result.get("setup_denied")
                        and rust_result.get("setup_denied")
                    )
                    or go_result.get("operations") != 0
                    or rust_result.get("routes") != 0
                ):
                    raise AssertionError(f"missing UDP scope became authority: {done}")
                if any(
                    "packet" in x and bytes.fromhex(x["packet"])[:8] == b"DNSACK02"
                    for x in trace
                ):
                    raise AssertionError("ACK without scope5")
                if bindings["acks"] != 0:
                    raise AssertionError("missing UDP scope ACK")
                return {
                    "classification": "PURE_STATEFUL_INTEROP",
                    "case": case,
                    "commands": commands,
                    "codes": codes,
                    "results": done,
                    "france_binding": bindings,
                    "trace": trace,
                }
            udp_expected = int(not case.endswith("parent-cancel"))
            tcp_expected = int(not case.endswith("missing-tcp-scope"))
            if bindings["acks"] != 1 or bindings["permission_carriers"] != (
                [6, 17] if tcp_expected else [17]
            ):
                raise AssertionError("missing separate France branch permissions")
            if bindings["neighbor_events"] != tcp_expected:
                raise AssertionError("missing live TCP after UDP cleanup")
            if (
                not go_result.get("france")
                or not go_result.get("cleanup")
                or go_result.get("tcp_opens") != tcp_expected
                or go_result.get("tcp_closes") != tcp_expected
                or go_result.get("tcp_neighbor_writes", 0) < tcp_expected
                or go_result.get("udp_opens") != udp_expected
                or go_result.get("udp_sends") != udp_expected
                or go_result.get("udp_closes") != udp_expected
                or go_result.get("udp_tasks_joined") != udp_expected * 2
                or go_result.get("operations") != 0
                or not rust_result.get("france")
                or rust_result.get("retained_routes")
                or rust_result.get("contexts") != 0
                or rust_result.get("flows") != 0
                or rust_result.get("services") != 0
                or rust_result.get("unknown")
            ):
                raise AssertionError(f"incomplete same-session FranceSS: {done}")
            return {
                "classification": "PURE_STATEFUL_INTEROP",
                "case": case,
                "commands": commands,
                "codes": codes,
                "results": done,
                "france_binding": bindings,
                "datagram_cleanup_barriers": check_datagram_cleanup(trace),
                "trace": trace,
            }
        network = case.startswith("network-")
        datagram = "udp-hosts-" in case or "udp-network-" in case
        if datagram:
            network = "udp-network-" in case
            bad = case.endswith("wrong-question")
            negative = case.endswith(
                ("foreign-member", "parent-cancel", "wrong-question")
            )
            expected = int(not negative)
            go_result, rust_result = done["go"], done["rust"]
            prefix = (
                (
                    [57, 20, 55, 35, 35, 52, 38]
                    if bad
                    else [57, 20, 55, 35, 35, 52, 38, 40, 57, 20, 55, 35, 53, 42]
                )
                if network
                else [57, 55, 35, 40, 57, 55, 35, 53, 42]
            )
            if (
                not go_result.get("cleanup")
                or not go_result.get("ss_consumer")
                or go_result.get("retained_operations")
                != go_result.get("preseed_operations")
                or go_result.get("attempts") != expected
                or go_result.get("sends") != expected
                or go_result.get("socket_closes") != expected
                or go_result.get("tasks_joined") != 2 * expected
                or go_result.get("kinds", [])[: len(prefix)] != prefix
                or not rust_result.get("rust_done")
                or rust_result.get("routes")
                != (
                    (3 if bad else 5 if case.endswith("foreign-member") else 6)
                    if network
                    else 1
                    if case.endswith("foreign-member")
                    else 2
                )
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
                or network
                and (
                    rust_result.get("receiver_consumed_closes") != 1
                    or go_result.get("resolver_protocol")
                    != (6 if "-tcp-" in case else 17)
                )
                or case.endswith("late-ack")
                and not go_result.get("late_ack")
            ):
                raise AssertionError(f"incomplete UDP actor roundtrip: {done}")
            return {
                "classification": "PURE_STATEFUL_INTEROP",
                "case": case,
                "commands": commands,
                "codes": codes,
                "results": done,
                "datagram_cleanup_barriers": check_datagram_cleanup(
                    trace, 1 if bad else 2
                ),
                "cleanup_service_barriers": check_network_cleanup(trace, frozenset({1}))
                if network
                else 0,
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
            "france-hosts-positive",
            "system-france-hosts-positive",
            "france-hosts-parent-cancel",
            "france-hosts-second-send",
            "france-hosts-missing-tcp-scope",
            "france-hosts-missing-udp-scope",
            "system-france-hosts-parent-cancel",
            "system-france-hosts-second-send",
            "system-france-hosts-missing-tcp-scope",
            "system-france-hosts-missing-udp-scope",
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
            "udp-network-udp-positive",
            "udp-network-tcp-positive",
            "system-udp-network-udp-positive",
            "system-udp-network-tcp-positive",
            "udp-network-udp-wrong-question",
            "udp-network-udp-foreign-member",
            "udp-network-udp-parent-cancel",
            "udp-network-udp-replay",
            "udp-network-tcp-late-ack",
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
