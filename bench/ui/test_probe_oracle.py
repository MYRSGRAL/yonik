"""Отрицательные контроли наблюдения native frame counter."""

import runpy
import unittest
from pathlib import Path

MODULE = runpy.run_path(str(Path(__file__).with_name("private-x11-preflight.py")))


class ProbeValidation(unittest.TestCase):
    def test_nonce_counter_and_canary_fail_closed(self) -> None:
        validate = MODULE["validate_counter"]
        good = dict(nonce=7, rendered_frames=12)
        self.assertEqual(validate(good, 7, 11), 12)
        for bad in (
            dict(good, nonce=6),
            dict(good, nonce=True),
            dict(good, rendered_frames=True),
            dict(good, rendered_frames=10),
            dict(good, rendered_frames=2**64 - 1),
            dict(good, rendered_frames=2**64),
            dict(good, rendered_frames=-1),
            dict(good, nonce="7"),
        ):
            with self.assertRaises(MODULE["driver"].BenchmarkError):
                validate(bad, 7, 11)
        for after in (11, 0):
            with self.assertRaises(MODULE["driver"].BenchmarkError):
                MODULE["require_canary"](11, after)
        MODULE["require_canary"](11, 12)


if __name__ == "__main__":
    unittest.main()
