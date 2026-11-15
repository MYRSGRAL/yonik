"""Pins и граница source scope незамороженного full-profile follow-up."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

ADAPTER = Path(__file__).resolve().parents[2] / "adapters/xray/v26.10.31"


class FullProfilePatchTests(unittest.TestCase):
    def test_descriptor_binds_patch_without_claiming_runtime_acceptance(self) -> None:
        metadata = json.loads((ADAPTER / "native-full-profile.json").read_text())
        patch = (ADAPTER / "native-full-profile.patch").read_bytes()
        self.assertEqual(metadata["patch_sha256"], hashlib.sha256(patch).hexdigest())
        self.assertTrue(metadata["launch_admission_hook_connected"])
        self.assertFalse(metadata["builder_apply_enabled"])
        self.assertFalse(metadata["runtime_hooks_connected"])
        self.assertFalse(metadata["authority_issuer_connected"])
        self.assertIsNone(metadata["native_protocol"])

    def test_follow_up_preserves_frozen_wire_and_owned_source_scope(self) -> None:
        text = (ADAPTER / "native-full-profile.patch").read_text()
        paths = {
            line.removeprefix("+++ b/")
            for line in text.splitlines()
            if line.startswith("+++ b/")
        }
        self.assertIn("main/run.go", paths)
        for path in paths:
            self.assertTrue(
                path.startswith("common/yonikbroker/profile")
                or path
                in {
                    "main/run.go",
                    "main/yonik_profile_test.go",
                    "app/dns/nameserver_local.go",
                    "features/dns/localdns/client.go",
                    "features/dns/localdns/yonik_context_test.go",
                },
                path,
            )
        self.assertNotIn("common/yonikbroker/wire.go", paths)
        self.assertNotIn("common/yonikbroker/bootstrap_linux.go", paths)


if __name__ == "__main__":
    unittest.main()
