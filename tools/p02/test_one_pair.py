"""Selector/unit only: fake driver, никаких GUI/engine/fixture процессов."""

import contextlib
import io
import json
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import one_pair as selector


class SelectorTests(unittest.TestCase):
    def test_fixed_two_windows_and_dry_run_does_not_execute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "new"
            with (
                patch.object(selector, "OUTPUT", output),
                patch.object(selector, "PINS", {}),
                patch.object(selector, "execute") as execute,
                patch.object(
                    subprocess, "Popen", side_effect=AssertionError("runtime")
                ),
                contextlib.redirect_stdout(io.StringIO()) as stdout,
            ):
                selector.main([])
                result = json.loads(stdout.getvalue())
                self.assertEqual(result["mode"], "dry-run")
                self.assertEqual(
                    result["windows"],
                    [
                        {"group": "full", "seconds": 900},
                        {"group": "engine", "seconds": 900},
                    ],
                )
                execute.assert_not_called()
                self.assertFalse(output.exists())

    def test_explicit_execute_only_routes_to_mock(self) -> None:
        with (
            patch.object(selector, "plan", return_value={"mode": "execute"}) as plan,
            patch.object(selector, "execute") as execute,
        ):
            selector.main(["--execute"])
            self.assertTrue(plan.call_args.args[0].execute)
            execute.assert_called_once_with({"mode": "execute"})

    def test_wrong_scope_and_arbitrary_inputs_rejected(self) -> None:
        for argv in [
            ["--core", "xray"],
            ["--repeats", "2"],
            ["--seconds", "899"],
            ["--pair", "1"],
            ["--config", "foreign.json"],
            ["--shell", "true"],
        ]:
            with (
                self.subTest(argv=argv),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                selector.parser().parse_args(argv)

    def test_output_collision_and_foreign_output_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "new"
            with (
                patch.object(selector, "OUTPUT", output),
                patch.object(selector, "PINS", {}),
            ):
                args = selector.parser().parse_args([])
                args.output = Path(temporary) / "foreign"
                with self.assertRaises(ValueError):
                    selector.plan(args)
                args.output = output
                output.mkdir()
                with self.assertRaises(FileExistsError):
                    selector.plan(args)
                output.rmdir()
                output.symlink_to(Path(temporary) / "absent")
                with self.assertRaises(FileExistsError):
                    selector.plan(args)

    def test_wrong_artifact_binding_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "new"
            artifact = Path(temporary) / "artifact"
            artifact.write_bytes(b"different")
            with (
                patch.object(selector, "OUTPUT", output),
                patch.object(selector, "PINS", {artifact: "0" * 64}),
                self.assertRaisesRegex(ValueError, "binding"),
            ):
                selector.plan(selector.parser().parse_args([]))

    def test_pair_passes_same_captured_object_without_recomposition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            captured = b"opaque captured production bytes; never recompose"
            control = Mock()
            driver = Mock()
            driver.port.side_effect = [10001, 10002]
            driver.https_server.return_value = contextlib.nullcontext(
                types.SimpleNamespace(server_port=10003)
            )
            driver.peer.return_value = contextlib.nullcontext()
            driver.gui.return_value = contextlib.nullcontext(
                (types.SimpleNamespace(pid=101), control, [])
            )
            driver.capture.return_value = (102, captured)
            driver.idle.return_value = {"duration_s": 900}
            driver.descendants.return_value = set()

            def engine(*args: object) -> dict:
                self.assertIs(args[2], captured)
                self.assertEqual(args[0], "sing-box")
                self.assertEqual(args[-1], 900)
                path = args[3]
                path.mkdir()
                (path / "actual-config.json").write_bytes(captured)
                return {"duration_s": 900}

            driver.engine_only.side_effect = engine
            (output / "full").mkdir()
            (output / "full/actual-config.json").write_bytes(captured)
            with (
                patch.object(selector, "OUTPUT", output),
                patch.object(
                    subprocess, "Popen", side_effect=AssertionError("runtime")
                ),
            ):
                selector.run_pair(driver, {"unit": True})
            driver.idle.assert_called_once()
            self.assertEqual(driver.idle.call_args.args[:2], ([101, 102], 900))
            driver.engine_only.assert_called_once()
            driver.campaign.assert_not_called()
            driver.prepare.assert_called_once_with(control, "sing-box")
            self.assertEqual(control.send.call_args_list[0].args, ("connect",))
            self.assertEqual(control.send.call_args_list[1].args, ("hide",))
            self.assertEqual(
                json.loads((output / "result.json").read_text())["status"],
                "REPLACEMENT_PAIR_RECORDED_REVIEW_REQUIRED",
            )


if __name__ == "__main__":
    unittest.main()
