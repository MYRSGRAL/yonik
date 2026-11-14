"""Канарейка FD и реальные counters внешнего sampler."""

import os
import select
import signal
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import connected_idle as driver
from connected_idle import sample


class SamplerTest(unittest.TestCase):
    def test_retained_descriptors_are_visible(self) -> None:
        """Sampler обязан видеть реальную прибавку удержанных FD."""
        before = sample(os.getpid())
        handles = [open("/dev/null", "rb") for _ in range(7)]
        try:
            during = sample(os.getpid())
            self.assertEqual(during["fd"] - before["fd"], 7)
            self.assertEqual(before["starttime"], during["starttime"])
            self.assertGreaterEqual(during["cpu_ticks"], before["cpu_ticks"])
            self.assertIsNone(during["wakeups"])
            self.assertTrue(during["wakeups_reason"])
        finally:
            for handle in handles:
                handle.close()
        self.assertEqual(sample(os.getpid())["fd"], before["fd"])


class ProtocolTests(unittest.TestCase):
    def test_engine_cleanup_escalates_and_reaps(self) -> None:
        engine = Mock()
        engine.wait.side_effect = [subprocess.TimeoutExpired("engine", 10), 0]
        engine.poll.return_value = None
        fake_compile = types.SimpleNamespace(wait_listener=lambda *_args: None)
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(driver.subprocess, "Popen", return_value=engine),
                patch.object(driver, "curl_probe", side_effect=RuntimeError("control")),
                patch.dict(sys.modules, {"engine_compile": fake_compile}),
                self.assertRaisesRegex(RuntimeError, "control"),
            ):
                driver.engine_only(
                    "xray",
                    Path("fixture"),
                    b"{}",
                    Path(tmp) / "out",
                    1,
                    2,
                    Path("ca"),
                    object(),
                    1,
                )
        engine.kill.assert_called_once()
        self.assertEqual(engine.wait.call_count, 2)

    def test_sampled_group_rejects_untracked_child_and_identity_drift(self) -> None:
        row = {
            "pid": 1,
            "starttime": "10",
            "namespaces": {"pid": "a"},
            "descendants": [],
        }
        driver.validate_group([row], [row])
        for mutated in (
            dict(row, starttime="11"),
            dict(row, namespaces={"pid": "b"}),
            dict(row, descendants=[2]),
        ):
            with self.subTest(mutated=mutated), self.assertRaises(RuntimeError):
                driver.validate_group([mutated], [row])

    def test_idle_enforces_identity_on_samples(self) -> None:
        row = sample(os.getpid())
        fixture = types.SimpleNamespace(requested=threading.Event())
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(
                driver, "sample", side_effect=[row, dict(row, starttime="wrong")]
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "identity"):
                driver.idle([os.getpid()], 0.01, Path(tmp), fixture)

    def test_real_unresponsive_owned_child_is_killed_and_reaped(self) -> None:
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('ready',flush=True);time.sleep(30)",
            ],
            stdout=subprocess.PIPE,
        )
        try:
            self.assertTrue(select.select([child.stdout], [], [], 5)[0])
            self.assertEqual(child.stdout.readline(), b"ready\n")
            descriptor = os.pidfd_open(child.pid)
            try:
                driver.terminate_pidfd(descriptor, timeout=0.05)
                self.assertTrue(select.select([descriptor], [], [], 0)[0])
            finally:
                os.close(descriptor)
            self.assertEqual(child.wait(timeout=1), -signal.SIGKILL)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=1)
            child.stdout.close()

    def test_gui_tls_refusal_is_not_curl_or_transport_failure(self) -> None:
        driver.require_gui_tls_refusal(
            {"status": "Limited", "probe_result": {"kind": "tls"}}, False
        )
        for state, requested in (
            ({"status": "Connected", "probe_result": {"kind": "http"}}, True),
            ({"status": "Limited", "probe_result": {"kind": "transport"}}, False),
            ({"status": "Limited", "probe_result": {"kind": "tls"}}, True),
        ):
            with (
                self.subTest(state=state, requested=requested),
                self.assertRaises(RuntimeError),
            ):
                driver.require_gui_tls_refusal(state, requested)


if __name__ == "__main__":
    unittest.main()
