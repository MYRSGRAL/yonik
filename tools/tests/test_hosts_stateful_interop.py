"""Проверки deadline relay на собственных fake stdio peers."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import hosts_stateful_interop as interop


class FranceBindingTests(unittest.TestCase):
    def initial(self, method: str = "aes-128-gcm") -> dict[str, object]:
        config = json.dumps(
            {
                "outbounds": [
                    {
                        "tag": "proxy",
                        "protocol": "shadowsocks",
                        "settings": {
                            "servers": [
                                {
                                    "address": "fr.example.invalid",
                                    "port": 443,
                                    "method": method,
                                    "password": "synthetic-password",
                                }
                            ]
                        },
                    }
                ]
            }
        ).encode()
        launch = bytearray(192)
        launch[48:80] = hashlib.sha256(config).digest()
        return {
            "init": {
                "launch": launch.hex(),
                "config": config.hex(),
                "tcp_path": [[0, 0]],
                "udp_path": [[1, 0]],
            }
        }

    def test_two_sessions_cannot_substitute_one_full_profile(self) -> None:
        with self.assertRaisesRegex(AssertionError, "one init/launch"):
            interop.check_france_binding([self.initial(), self.initial()])

    def test_config_digest_and_full_ss_settings_are_independent(self) -> None:
        value = self.initial()
        value["init"]["config"] = "7b7d"
        with self.assertRaisesRegex(AssertionError, "config/launch mismatch"):
            interop.check_france_binding([value])
        with self.assertRaisesRegex(AssertionError, "settings changed"):
            interop.check_france_binding([self.initial("aes-256-gcm")])

    def test_aliased_paths_and_data_only_init_are_not_pair_evidence(self) -> None:
        value = self.initial()
        value["init"]["udp_path"] = [[0, 0]]
        with self.assertRaisesRegex(AssertionError, "paths aliased"):
            interop.check_france_binding([value])
        with self.assertRaisesRegex(AssertionError, "admission/setup"):
            interop.check_france_binding([self.initial()])


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
    frame("go", 38, 3, 0, body(72, {}))
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
    def test_resource_retire_requires_prior_actual_proof_ack(self) -> None:
        trace = cleanup_trace()
        del trace[8]
        with self.assertRaisesRegex(AssertionError, "Resource retire before Proof ACK"):
            interop.check_network_cleanup(trace)

    def test_held_actual_resource_ack_blocks_service_until_release(self) -> None:
        trace = cleanup_trace()
        hold = {"side": "go", "event": {"name": "ack_hold", "target": 3, "id": 14}}
        release = {
            "side": "go",
            "event": {"name": "ack_release", "target": 3, "id": 14},
        }
        trace.insert(11, hold)
        with self.assertRaisesRegex(AssertionError, "Close32 before cleanup ACK"):
            interop.check_network_cleanup(trace + [release])
        trace.insert(-1, release)
        self.assertEqual(interop.check_network_cleanup(trace), 1)

    def test_numeric_permission_close_is_distinct_from_service_root(self) -> None:
        trace = cleanup_trace()
        request = bytearray.fromhex(str(trace[0]["packet"]))
        request[10:12] = (42).to_bytes(2, "big")
        request[16:24] = (100).to_bytes(8, "big")
        answer = bytearray(184)
        answer[:128] = request[:128]
        answer[10:12] = (19).to_bytes(2, "big")
        answer[12:16] = len(answer).to_bytes(4, "big")
        answer[24:32] = (100).to_bytes(8, "big")
        answer[128] = 1
        answer[132:140] = (99).to_bytes(8, "big")
        close = bytearray.fromhex(str(trace[-1]["packet"]))
        close[132:140] = (99).to_bytes(8, "big")
        prefix = [
            {"side": "go", "packet": request.hex()},
            {"side": "rust", "packet": answer.hex()},
            {"side": "go", "packet": close.hex()},
        ]
        self.assertEqual(interop.check_network_cleanup(prefix + trace), 1)
        with self.assertRaisesRegex(AssertionError, "without acquired context"):
            interop.check_network_cleanup([prefix[0], prefix[2]] + trace)

    def test_joined_resource_and_all_namespaces_ack_before_service_close(self) -> None:
        self.assertEqual(interop.check_network_cleanup(cleanup_trace()), 1)

    def test_missing_resource_ack_cannot_hide_behind_final_cleanup(self) -> None:
        trace = cleanup_trace()
        del trace[10]
        with self.assertRaisesRegex(AssertionError, "Close32 before cleanup ACK"):
            interop.check_network_cleanup(trace)

    def test_service_close_before_context_ack_is_rejected(self) -> None:
        trace = cleanup_trace()
        trace[-1], trace[-2] = trace[-2], trace[-1]
        with self.assertRaisesRegex(AssertionError, "Close32 before cleanup ACK"):
            interop.check_network_cleanup(trace)


def datagram_cleanup_trace() -> list[dict[str, object]]:
    """Только unit corpus анализатора; эти кадры никогда не подаются SUT."""
    trace: list[dict[str, object]] = []

    def frame(
        side: str,
        kind: int,
        seq: int,
        reply: int,
        fields: dict[int, int],
        target: int = 0,
    ) -> None:
        body = bytearray(72)
        body[2] = target if side == "go" else 1
        for offset, value in fields.items():
            body[offset : offset + 8] = value.to_bytes(8, "big")
        header = bytearray(128)
        header[:8] = b"YNKCAP01"
        header[10:12] = kind.to_bytes(2, "big")
        header[12:16] = (128 + len(body)).to_bytes(4, "big")
        header[16:24] = seq.to_bytes(8, "big")
        header[24:32] = reply.to_bytes(8, "big")
        trace.append({"side": side, "packet": (header + body).hex()})

    for i in range(2):
        seq = 1 + i * 4
        frame("go", 57, seq, 0, {8: 9 + i})
        frame("rust", 58, seq, seq, {8: 1 + i})
        frame("go", 55, seq + 1, 0, {16: 9 + i})
        frame("rust", 56, seq + 1, seq + 1, {8: 11 + i})
        frame("go", 47, seq + 2, 0, {8: 11 + i}, 8)
        frame("rust", 48, seq + 2, seq + 2, {8: 11 + i})
        frame("go", 47, seq + 3, 0, {8: 1 + i}, 9)
        frame("rust", 48, seq + 3, seq + 3, {8: 1 + i})
    return trace


class DatagramBarrierTests(unittest.TestCase):
    def test_each_parent_and_own_context_have_actual_terminal_ack(self) -> None:
        self.assertEqual(interop.check_datagram_cleanup(datagram_cleanup_trace()), 4)

    def test_missing_parent_ack_cannot_hide_behind_terminal_counts(self) -> None:
        trace = datagram_cleanup_trace()
        del trace[-1]
        with self.assertRaisesRegex(AssertionError, "missing UDP cleanup ACK"):
            interop.check_datagram_cleanup(trace)

    def test_late_context_ack_does_not_authorize_earlier_parent_release(self) -> None:
        trace = datagram_cleanup_trace()
        trace[5], trace[6] = trace[6], trace[5]
        with self.assertRaisesRegex(AssertionError, "cancel9 before own context ACK"):
            interop.check_datagram_cleanup(trace)

    def test_original_user_close_waits_for_both_parent_acks(self) -> None:
        trace = datagram_cleanup_trace()
        close = bytearray.fromhex(str(trace[-2]["packet"]))[:140]
        close[10:12] = (32).to_bytes(2, "big")
        close[12:16] = len(close).to_bytes(4, "big")
        close[128:] = bytes(12)
        close[128] = 3
        close[132:140] = (1).to_bytes(8, "big")
        trace.insert(-1, {"side": "go", "packet": close.hex()})
        with self.assertRaisesRegex(
            AssertionError, "USER Close32 before owned parent ACK9"
        ):
            interop.check_datagram_cleanup(trace)


class RelayTests(unittest.TestCase):
    def test_setup_refusal_does_not_write_stop_to_already_exited_issuer(self) -> None:
        original = subprocess.Popen
        children: list[subprocess.Popen[bytes]] = []

        def spawn(command: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
            program = (
                "import json,sys,time; v=json.loads(sys.stdin.readline()); "
                "assert v['setup_denied']; time.sleep(0.05); "
                "print(json.dumps({'go_done':True,'setup_denied':True,'operations':0}),flush=True)"
            )
            if command[0].endswith("rust"):
                program = "import json; print(json.dumps({'rust_done':True,'setup_denied':True,'routes':0}),flush=True)"
            child = original([sys.executable, "-c", program], **kwargs)
            children.append(child)
            return child

        with (
            patch.object(interop.subprocess, "Popen", side_effect=spawn),
            patch.object(interop, "check_france_binding", return_value={"acks": 0}),
        ):
            result = interop.run(
                Path("/fake/rust"),
                Path("/fake/go"),
                2,
                "france-hosts-missing-udp-scope",
            )
        self.assertEqual(result["codes"], {"rust": 0, "go": 0})
        self.assertTrue(all(child.poll() is not None for child in children))

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
