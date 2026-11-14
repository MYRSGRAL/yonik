"""Отказ до запуска native runtime при нарушенной привязке ELF."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class IntegrityBoundary(unittest.TestCase):
    def test_corrupt_binary_never_starts_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "yonik-bench-qt").write_bytes(b"corrupted")
            (root / "manifest.json").write_text(
                json.dumps({"binary": {"yonik-bench-qt": {"sha256": "0" * 64}}})
            )
            output = root / "output"
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("private-x11-preflight.py")),
                    "--artifacts",
                    str(root),
                    "--xvfb",
                    str(root / "must-not-execute"),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("SHA-256: yonik-bench-qt", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
