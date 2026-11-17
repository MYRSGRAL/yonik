"""Проверки deadline relay на собственных fake stdio peers."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import hosts_stateful_interop as interop


def cleanup_trace() -> list[dict[str, object]]:
    """Синтетические кадры только для проверки анализатора, не counterpart SUT."""
    trace: list[dict[str, object]] = []

    def frame(side: str, kind: int, seq: int, reply: int, body: bytearray) -> None:
        header = bytearray(128)
        header[:8] = b"YNKCAP01"
        header[10:12] = kind.to_bytes(2, "big")
        header[12:16] = (128 + len(body)).to_bytes(4, "big")
        header[16:24] = seq.to_bytes(8, "big")
        header[24:32] = reply.to_bytes(8, "big")
        trace.append({"side": side, "packet": (header + body).hex()})

    def body(size: int, fields: dict[int, int], status: int = 0) -> bytearray:
        value = bytearray(size)
        value[2] = status
        for offset, identifier in fields.items():
            value[offset : offset + 8] = identifier.to_bytes(8, "big")
        return value

    frame("go", 55, 1, 0, body(72, {8: 9}))
    frame("rust", 56, 1, 1, body(64, {8: 11}, 1))
    frame("go", 35, 2, 0, body(96, {}))
    reserved = body(64, {8: 12, 24: 11, 32: 13}, 1)
    reserved[60] = 1
    frame("rust", 36, 2, 2, reserved)
    frame("rust", 37, 3, 2, body(64, {16: 14, 32: 11}, 1))
    frame("rust", 39, 4, 3, body(64, {16: 15, 32: 11}, 1))
    for sequence, (target, identifier) in enumerate(
        [(4, 15), (3, 14), (7, 12), (2, 13), (8, 11)], 5
    ):
        kind = 45 if target in (3, 4) else 47
        request = body(24, {8: identifier}, target)
        frame("go", kind, sequence, 0, request)
        answer = body(40 if kind == 45 else 32, {8: identifier}, 1)
        if kind == 45:
            answer[3], answer[28] = target, 1
        frame("rust", kind + 1, sequence, sequence, answer)
    close = body(12, {4: 9})
    close[0] = 3
    frame("go", 32, 10, 0, close)
    return trace


class CleanupBarrierTests(unittest.TestCase):
    def test_joined_resource_and_all_namespaces_ack_before_service_close(self) -> None:
        self.assertEqual(interop.check_network_cleanup(cleanup_trace()), 1)

    def test_missing_resource_ack_cannot_hide_behind_final_cleanup(self) -> None:
        trace = cleanup_trace()
        del trace[9]
        with self.assertRaisesRegex(AssertionError, "Close32 before cleanup ACK"):
            interop.check_network_cleanup(trace)

    def test_service_close_before_context_ack_is_rejected(self) -> None:
        trace = cleanup_trace()
        trace[-1], trace[-2] = trace[-2], trace[-1]
        with self.assertRaisesRegex(AssertionError, "Close32 before cleanup ACK"):
            interop.check_network_cleanup(trace)


class RelayTests(unittest.TestCase):
    def test_nonreading_peer_cannot_bypass_absolute_deadline(self) -> None:
        original = subprocess.Popen
        children: list[subprocess.Popen[bytes]] = []

        def spawn(command: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
            program = "import time; time.sleep(0.8)"
            if command[0].endswith("rust"):
                program = (
                    "import json,time; "
                    "print(json.dumps({'packet':'00'*65536}),flush=True); "
                    "time.sleep(0.8)"
                )
            child = original([sys.executable, "-c", program], **kwargs)
            children.append(child)
            return child

        with patch.object(interop.subprocess, "Popen", side_effect=spawn):
            with self.assertRaises(TimeoutError):
                interop.run(Path("/fake/rust"), Path("/fake/go"), 0.15, "positive")
        self.assertEqual(len(children), 2)
        self.assertTrue(all(child.poll() is not None for child in children))

    def test_queued_stop_reaches_peer_and_both_children_are_joined(self) -> None:
        original = subprocess.Popen

        def spawn(command: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
            program = (
                "import json,sys; sys.stdin.readline(); "
                "print(json.dumps({'go_done':True,'cleanup':True,'attempts':1,"
                "'kinds':[55,35,40,55,35,53,42]}),flush=True)"
            )
            if command[0].endswith("rust"):
                program = (
                    "import json,sys; print(json.dumps({'init':{}}),flush=True); "
                    "assert json.loads(sys.stdin.readline())=={'stop':True}; "
                    "print(json.dumps({'rust_done':True,'routes':1,'owners':0}),flush=True)"
                )
            return original([sys.executable, "-c", program], **kwargs)

        with patch.object(interop.subprocess, "Popen", side_effect=spawn):
            result = interop.run(Path("/fake/rust"), Path("/fake/go"), 2, "positive")
        self.assertEqual(result["codes"], {"rust": 0, "go": 0})


if __name__ == "__main__":
    unittest.main()
