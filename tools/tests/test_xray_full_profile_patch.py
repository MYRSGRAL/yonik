"""Pins и граница source scope незамороженного full-profile follow-up."""

from __future__ import annotations

import hashlib
import json
import struct
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
        self.assertTrue(metadata["physical_session_ownership_connected"])
        self.assertTrue(metadata["transport_guards_connected"])
        self.assertFalse(metadata["pooled_chain_reuse_connected"])
        self.assertFalse(metadata["probe_grants_connected"])
        self.assertFalse(metadata["builder_apply_enabled"])
        self.assertFalse(metadata["runtime_hooks_connected"])
        self.assertFalse(metadata["authority_issuer_connected"])
        self.assertTrue(metadata["dns_service_consumer_connected"])
        self.assertTrue(metadata["probe_service_consumer_connected"])
        self.assertTrue(metadata["snapshot_query_engine_connected"])
        self.assertTrue(metadata["observatory_probe_hook_connected"])
        self.assertFalse(metadata["exact_dns_outer_caller_connected"])
        self.assertFalse(metadata["physical_resolver_proof_connected"])
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
                    "app/observatory/observer.go",
                    "app/observatory/yonik_profile_service_test.go",
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
                    "common/mux/client.go",
                    "common/mux/yonik_profile_transport_test.go",
                    "common/mux/yonik_r9_lifecycle_test.go",
                    "transport/internet/system_dialer.go",
                    "transport/internet/memory_settings.go",
                    "transport/internet/yonik_profile_transport_test.go",
                    "transport/internet/grpc/dial.go",
                    "transport/internet/grpc/yonik_profile_transport_test.go",
                    "transport/internet/hysteria/dialer.go",
                    "transport/internet/hysteria/yonik_profile_transport_test.go",
                    "transport/internet/splithttp/dialer.go",
                    "transport/internet/splithttp/client.go",
                    "transport/internet/splithttp/mux.go",
                    "transport/internet/splithttp/yonik_profile_transport_test.go",
                    "transport/internet/splithttp/yonik_r9_test.go",
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

    def test_original_flow_fixture_keeps_initiator_and_actual_udp_ports(self) -> None:
        fixture = ADAPTER / "full-profile-fixtures/original-flow-v3.json"
        rows = json.loads(fixture.read_text())["rows"]
        self.assertEqual(len(rows), 2)
        for row in rows:
            wire = bytes.fromhex(row["tupleHex"])
            self.assertEqual(len(wire), 40)
            network, family, reserved, local, remote = struct.unpack("!BBHHH", wire[:8])
            self.assertIn(network, (6, 17))
            self.assertEqual((family, reserved), (4, 0))
            self.assertEqual(local, row["initiatorPort"])
            self.assertEqual(remote, row["actualIngressPort"])
            self.assertNotEqual(local, remote)
        self.assertEqual(rows[0]["actualIngressPort"], rows[0]["ownedIngressPort"])
        self.assertNotEqual(rows[1]["actualIngressPort"], rows[1]["ownedIngressPort"])
        patch = (ADAPTER / "native-full-profile.patch").read_text()
        added = patch.split(
            "+++ b/common/yonikbroker/profile-original-flow-v3.json\n", 1
        )[1]
        added = added.split("diff --git ", 1)[0]
        embedded = "\n".join(
            line[1:] for line in added.splitlines() if line.startswith("+")
        )
        self.assertEqual((embedded + "\n").encode(), fixture.read_bytes())

    def test_service_vectors_are_embedded_without_claiming_authority(self) -> None:
        fixture = ADAPTER / "full-profile-fixtures/service-grants-v3.json"
        vectors = json.loads(fixture.read_text())
        self.assertEqual((vectors["mappingVersion"], vectors["tableCount"]), (3, 11))
        self.assertFalse(vectors["authority"])
        self.assertEqual(
            bytes.fromhex(vectors["probeBodyHex"]), struct.pack("!HHHH", 1, 0, 0, 65535)
        )
        self.assertEqual(
            bytes.fromhex(vectors["bootstrapBodyHex"]), struct.pack("!HHHH", 2, 0, 0, 0)
        )
        for name, grant_class, flow in (
            ("probeGrantBodyHex", 2, 0),
            ("dnsGrantBodyHex", 3, 1),
        ):
            grant = bytes.fromhex(vectors[name])
            self.assertEqual(len(grant), 56)
            self.assertEqual(grant[:4], bytes((1, grant_class, 0, 0)))
            self.assertEqual(struct.unpack_from("!Q", grant, 12)[0], flow)
            self.assertEqual(grant[32:], bytes(24))
        self.assertEqual(
            vectors["systemUserDNSRustHead"],
            "abf5c2435dd71b272c8f064b155267c52fde9809",
        )
        system = bytes.fromhex(vectors["systemUserDNSGrantFrameHex"])
        self.assertEqual(len(system), 184)
        self.assertEqual(system[:8], b"YNKCAP01")
        self.assertEqual(struct.unpack_from("!HHIQQ", system, 8), (1, 19, 184, 9, 4))
        self.assertEqual(struct.unpack_from("!Q", system, 112)[0], 11)
        self.assertEqual(system[128:132], bytes((1, 3, 1, 0)))
        self.assertEqual(struct.unpack_from("!QQIQ", system, 132), (11, 1, 1000, 1))
        self.assertEqual(struct.unpack_from("!Q", system, 160)[0], 20_000_000)
        self.assertEqual(system[168:176], bytes((2, 0, 0, 0, 0, 0, 0, 0)))
        self.assertEqual(struct.unpack_from("!Q", system, 176)[0], 42)
        patch = (ADAPTER / "native-full-profile.patch").read_text()
        added = patch.split(
            "+++ b/common/yonikbroker/profile-service-vectors.json\n", 1
        )[1].split("diff --git ", 1)[0]
        embedded = (
            "\n".join(line[1:] for line in added.splitlines() if line.startswith("+"))
            + "\n"
        )
        self.assertEqual(embedded.encode(), fixture.read_bytes())


if __name__ == "__main__":
    unittest.main()
