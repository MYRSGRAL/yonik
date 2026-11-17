"""Проверки deadline relay на собственных fake stdio peers."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import hosts_stateful_interop as interop


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
