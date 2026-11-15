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
        self.assertTrue(metadata["original_flow_receipts_connected"])
        self.assertTrue(metadata["authorize_grant_consumer_connected"])
        self.assertTrue(metadata["dispatcher_chain_guards_connected"])
        self.assertFalse(metadata["physical_session_ownership_connected"])
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
                    "common/yonikbroker/routing.go",
                    "app/proxyman/inbound/worker.go",
                    "proxy/socks/server.go",
                    "proxy/http/server.go",
                    "proxy/tun/handler.go",
                    "app/dispatcher/default.go",
                    "app/proxyman/outbound/handler.go",
                    "app/proxyman/outbound/yonik_profile_test.go",
                    "transport/internet/dialer.go",
                    "transport/internet/udp/dispatcher.go",
                },
                path,
            )
        self.assertNotIn("common/yonikbroker/wire.go", paths)
        self.assertNotIn("common/yonikbroker/bootstrap_linux.go", paths)

    def test_independent_rust_vectors_are_embedded_byte_exact(self) -> None:
        patch = (ADAPTER / "native-full-profile.patch").read_text()
        for name in (
            "local-minimal.json",
            "system-chain-default-reject.json",
            "system-chain-probe.json",
            "resolver-snapshot-v1.json",
        ):
            marker = f"+++ b/common/yonikbroker/profile-rust-{name}\n"
            added = patch.split(marker, 1)[1].split("diff --git ", 1)[0]
            embedded = (
                "\n".join(
                    line[1:] for line in added.splitlines() if line.startswith("+")
                )
                + "\n"
            )
            self.assertEqual(
                embedded.encode(),
                (ADAPTER / "full-profile-fixtures" / name).read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
