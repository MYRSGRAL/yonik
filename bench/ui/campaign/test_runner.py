"""Реальные owned процессы проверяют KILL/reap и failed terminal."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "campaign_runner", Path(__file__).with_name("runner.py")
)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class OwnershipTests(unittest.TestCase):
    def setUp(self) -> None:
        runner.subreaper()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_term_ignored_requires_kill_and_reap(self) -> None:
        child = runner.TrackedChild(
            [
                sys.executable,
                "-u",
                "-c",
                "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('{}',flush=True);time.sleep(60)",
            ],
            self.root / "stderr",
        )
        try:
            child.ack(5)
            pid = child.process.pid
            token = child.guard.identity
            self.assertEqual(token["pid"], pid)
            self.assertEqual(token["sid"], pid)
            self.assertEqual(token["pgid"], pid)
            self.assertIsInstance(child.guard.pidfd, int)
            child.sample()
        finally:
            started = time.monotonic()
            child.close()
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(child.process.returncode, -9)
        self.assertFalse(Path(f"/proc/{pid}").exists())
        self.assertTrue(child.guard.cleanup["reaped"])

    def test_observed_descendant_fails_and_entire_owned_session_is_reaped(self) -> None:
        for escaped in (False, True):
            with self.subTest(escaped_session=escaped):
                code = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
                parent = f"import signal,subprocess,sys,time,json;signal.signal(signal.SIGTERM,signal.SIG_IGN);p=subprocess.Popen([sys.executable,'-c',{code!r}],start_new_session={escaped!r});print(json.dumps({{'child':p.pid}}),flush=True);time.sleep(60)"
                child = runner.TrackedChild(
                    [sys.executable, "-u", "-c", parent],
                    self.root / f"stderr-{escaped}",
                )
                descendant = None
                try:
                    report, _ = child.ack(5)
                    descendant = report["child"]
                    with self.assertRaises(runner.CoverageError):
                        child.sample()
                finally:
                    child.close()
                self.assertFalse(Path(f"/proc/{child.process.pid}").exists())
                self.assertFalse(Path(f"/proc/{descendant}").exists())
                self.assertTrue(child.guard.cleanup["reaped"])

    def test_census_error_still_kills_unpinned_owned_group(self) -> None:
        code = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
        parent = f"import signal,subprocess,sys,time,json;signal.signal(signal.SIGTERM,signal.SIG_IGN);p=subprocess.Popen([sys.executable,'-c',{code!r}]);print(json.dumps({{'child':p.pid}}),flush=True);time.sleep(60)"
        child = runner.TrackedChild(
            [sys.executable, "-u", "-c", parent], self.root / "census.stderr"
        )
        report, _ = child.ack(5)
        descendant = report["child"]
        try:
            with patch.object(child.guard, "discover", side_effect=OSError("census")):
                with self.assertRaises(runner.CoverageError):
                    child.close()
            self.assertFalse(Path(f"/proc/{child.process.pid}").exists())
            self.assertFalse(Path(f"/proc/{descendant}").exists())
        finally:
            # Изолированный RED не должен оставлять собственного потомка.
            try:
                os.kill(descendant, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(descendant, 0)
            except ChildProcessError:
                pass

    def test_malformed_metadata_after_spawn_cannot_skip_finally_or_emit_complete(
        self,
    ) -> None:
        out = self.root / "run"
        supervisor = runner.Supervisor(out, expected_cells=18)
        with self.assertRaises(json.JSONDecodeError):
            with supervisor:
                child = supervisor.own(
                    runner.TrackedChild(
                        [
                            sys.executable,
                            "-u",
                            "-c",
                            "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('{}',flush=True);time.sleep(60)",
                        ],
                        out / "stderr",
                    )
                )
                child.ack(5)
                pid = child.process.pid
                json.loads("{broken metadata")
        terminal = json.loads((out / "terminal.json").read_text())
        self.assertEqual(terminal["state"], "FAILED")
        self.assertFalse(Path(f"/proc/{pid}").exists())
        self.assertEqual(terminal["completed_cells"], 0)
        self.assertEqual(terminal["receipt_sha256"], runner.sha(out / "receipt.json"))

    def test_invalid_child_stdout_propagates_failed_terminal(self) -> None:
        out = self.root / "bad-stdout"
        supervisor = runner.Supervisor(out)
        with self.assertRaises(runner.legacy.BenchmarkError):
            with supervisor:
                child = supervisor.spawn(
                    lambda: runner.TrackedChild(
                        [
                            sys.executable,
                            "-u",
                            "-c",
                            "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('not-json',flush=True);time.sleep(60)",
                        ],
                        out / "stderr",
                    )
                )
                pid = child.process.pid
                child.ack(5)
        self.assertEqual(
            json.loads((out / "terminal.json").read_text())["state"], "FAILED"
        )
        self.assertFalse(Path(f"/proc/{pid}").exists())

    def test_cell_alarm_propagates_and_cleanup_survives_ignored_term(self) -> None:
        out = self.root / "alarm"
        supervisor = runner.Supervisor(out)
        with self.assertRaises(runner.Cancelled):
            with supervisor:
                child = supervisor.spawn(
                    lambda: runner.TrackedChild(
                        [
                            sys.executable,
                            "-u",
                            "-c",
                            "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('{}',flush=True);time.sleep(60)",
                        ],
                        out / "stderr",
                    )
                )
                child.ack(5)
                pid = child.process.pid
                signal.setitimer(signal.ITIMER_REAL, 0.1)
                child.pump(5)
        terminal = json.loads((out / "terminal.json").read_text())
        self.assertEqual(terminal["state"], "FAILED")
        self.assertFalse(Path(f"/proc/{pid}").exists())

    def test_cli_bad_manifest_has_nonzero_exit_and_failed_terminal(self) -> None:
        snapshot = self.root / "snapshot"
        for relative in (
            "bench/ui/campaign/runner.py",
            "tools/ui_benchmark.py",
            "tools/resource_counters.py",
            "bench/ui/private-x11-preflight.py",
        ):
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(runner.ROOT / relative, target)
        manifest = snapshot / "manifest.json"
        manifest.write_text("{broken")
        manifest.chmod(0o444)
        snapshot.chmod(0o555)
        output = self.root / "bad-manifest-output"
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(snapshot / "bench/ui/campaign/runner.py"),
                    "--manifest-sha256",
                    runner.sha(manifest),
                    "--output",
                    str(output),
                ],
                cwd=snapshot,
                start_new_session=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 1)
            terminal = json.loads((output / "terminal.json").read_text())
            self.assertEqual(terminal["state"], "FAILED")
            self.assertIn("JSONDecodeError", terminal["error"])
            receipt = json.loads((output / "receipt.json").read_text())
            self.assertEqual(receipt["identity"]["sid"], receipt["identity"]["pid"])
        finally:
            snapshot.chmod(0o755)

    def test_real_five_second_sampling_without_stdin_commands(self) -> None:
        code = "import signal,time,threading,sys;signal.signal(signal.SIGTERM,signal.SIG_IGN);threading.Thread(target=lambda:sys.stdout.write('unexpected:'+sys.stdin.readline()),daemon=True).start();print('{}',flush=True);time.sleep(60)"
        child = runner.TrackedChild(
            [sys.executable, "-u", "-c", code], self.root / "cadence.stderr"
        )
        samples = []
        try:
            child.ack(5)
            runner.sample_idle(child, None, 5.1, 5, samples)
            self.assertGreaterEqual(len(samples), 2)
            delta = (samples[1]["monotonic_ns"] - samples[0]["monotonic_ns"]) / 1e9
            self.assertGreaterEqual(delta, 4.9)
            self.assertLess(delta, 6)
            self.assertTrue(all(sample["wakeups"] is None for sample in samples))
            self.assertFalse(child.pending)
        finally:
            child.close()


if __name__ == "__main__":
    unittest.main()
