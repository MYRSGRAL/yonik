"""Pins и граница source scope незамороженного full-profile follow-up."""

from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path

ADAPTER = Path(__file__).resolve().parents[2] / "adapters/xray/v26.10.31"


class FullProfilePatchTests(unittest.TestCase):
    def test_rx_scratch_is_permanent_and_shared_readers_use_exclusive_lease(
        self,
    ) -> None:
        patch = (ADAPTER / "native-full-profile.patch").read_text()
        for anchor in (
            "c.initRXBudget()",
            "const profileRXFD = 16",
            "const profileRXMemory = 66048",
            "return p.leaseProfileRX()",
            "a.runtime.leaseProfileRX()",
            "c.profilePendingUsed()",
            "c.rxReserved && !c.dnsScratchUnknown",
        ):
            self.assertIn(anchor, patch)
        actor = patch.split("+++ b/common/yonikbroker/profile_udp_actor_linux.go\n", 1)[
            1
        ].split("diff --git ", 1)[0]
        self.assertNotIn("fdSlots += 16", actor)
        self.assertNotIn("proofPending++", actor.split("receive(read", 1)[1])

    def test_dns_direct_transport_uses_private_actor_and_keeps_public_gates_closed(
        self,
    ) -> None:
        patch = (ADAPTER / "native-full-profile.patch").read_text()
        for caller in (
            "return profileDNSDialDirect(ctx, dest, runner)",
            "return c.dnsDirectDispatch(op)",
            "c.dnsDirectAccept(f)",
            "p.reserveDNSInput()",
            "hooks.ProfileDNSDirectFactory(ctx)",
            "profileKernelSocketNamespace(source.proof, fd)",
            "op.sequence = op.dnsDirect.request.sequence",
            "op.sent = op.dnsDirect.request.sent",
            "s.tasks.Wait()",
        ):
            self.assertIn(caller, patch)
        metadata = json.loads((ADAPTER / "native-full-profile.json").read_text())
        for gate in (
            "builder_apply_enabled",
            "runtime_hooks_connected",
            "authority_issuer_connected",
            "physical_resolver_proof_connected",
        ):
            self.assertFalse(metadata[gate])

    def test_dns_v2_canonical_pin_is_data_only_and_embedded_exactly(self) -> None:
        raw = (ADAPTER / "full-profile-fixtures/dns-v2-canonical.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "10d798ffd45f7d250e4c3f38c02b9f394671d1f9ee4871cdcd39b9d042e59359",
        )
        patch = (ADAPTER / "native-full-profile.patch").read_text()
        added = patch.split(
            "+++ b/common/yonikbroker/profile-dns-v2-canonical.json\n", 1
        )[1].split("diff --git ", 1)[0]
        embedded = (
            "\n".join(line[1:] for line in added.splitlines() if line.startswith("+"))
            + "\n"
        ).encode()
        self.assertEqual(raw, embedded)
        corpus = json.loads(raw)
        self.assertEqual(len(corpus["vectors"]), 86)
        self.assertEqual(len(corpus["rejectedBodies"]), 218)
        self.assertEqual(len(corpus["rejectedFrames"]), 17)
        self.assertIn("YONIK-DNS-V2-CODEC-2", patch)
        self.assertIn("ProfileDNSPrepareHandler(ctx, h.tag", patch)
        self.assertIn("c.dnsAccept(f)", patch)
        self.assertIn("c.dnsTick()", patch)
        self.assertIn("p.negotiateDNSV2(record, initialDeadline)", patch)
        self.assertIn("task.OwnContext(dnsCtx, conn)", patch)
        metadata = json.loads((ADAPTER / "native-full-profile.json").read_text())
        self.assertFalse(metadata["builder_apply_enabled"])
        self.assertFalse(metadata["authority_issuer_connected"])

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
        self.assertTrue(metadata["pooled_chain_reuse_connected"])
        self.assertTrue(metadata["pooled_chain_numeric_only"])
        self.assertFalse(metadata["probe_grants_connected"])
        self.assertFalse(metadata["builder_apply_enabled"])
        self.assertFalse(metadata["runtime_hooks_connected"])
        self.assertFalse(metadata["authority_issuer_connected"])
        self.assertTrue(metadata["system_tcp_proof_consumer_connected"])
        self.assertFalse(metadata["system_udp_association_proof_connected"])
        self.assertTrue(metadata["udp_v2_codec_source"])
        self.assertTrue(metadata["udp_v2_private_state_source"])
        self.assertTrue(metadata["udp_v2_socks_guard_connected"])
        self.assertTrue(metadata["udp_v2_actor_delivery_connected"])
        self.assertFalse(metadata["udp_v2_consumer_ready"])
        self.assertTrue(metadata["udp_v2_name_policy_parity"])
        self.assertTrue(metadata["udp_v2_receive_os_source"])
        self.assertTrue(metadata["udp_v2_namespace_binding_source"])
        self.assertTrue(metadata["udp_v2_runtime_flow_handoff_connected"])
        self.assertTrue(metadata["udp_v2_close_receipt_connected"])
        self.assertTrue(metadata["udp_v2_response_sink_source"])
        self.assertTrue(metadata["dns_service_consumer_connected"])
        self.assertTrue(metadata["probe_service_consumer_connected"])
        self.assertTrue(metadata["snapshot_query_engine_connected"])
        self.assertTrue(metadata["observatory_probe_hook_connected"])
        self.assertTrue(metadata["exact_dns_outer_caller_connected"])
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
                    "app/dns/dns.go",
                    "app/dns/nameserver.go",
                    "app/dns/yonik_outer_test.go",
                    "app/dns/dnscommon.go",
                    "app/dns/dnscommon_test.go",
                    "app/dns/cache_controller.go",
                    "app/dns/nameserver_cached.go",
                    "app/dns/yonik_exchange.go",
                    "app/dns/nameserver_udp.go",
                    "app/dns/nameserver_tcp.go",
                    "app/dns/yonik_lineage_test.go",
                    "features/dns/localdns/client.go",
                    "features/dns/localdns/yonik_context_test.go",
                    "common/yonikbroker/routing.go",
                    "app/proxyman/inbound/worker.go",
                    "proxy/socks/server.go",
                    "proxy/socks/yonik_udp_v2_test.go",
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

    def test_numeric_chain_preflight_is_connected_before_transport_effects(
        self,
    ) -> None:
        patch = (ADAPTER / "native-full-profile.patch").read_text()
        handler = patch.split("+++ b/app/proxyman/outbound/handler.go\n", 1)[1]
        handler = handler.split("diff --git ", 1)[0]
        self.assertIn("nativehooks.ProfilePrepareChain(next, h.profileBranch)", handler)
        self.assertIn("next.profileMuxDecision(target)", handler)
        self.assertLess(
            handler.index("nativehooks.ProfilePrepareChain(next, h.profileBranch)"),
            handler.index("nativehooks.ProfileGuardLink(ctx, link)"),
        )
        self.assertIn("+++ b/app/dns/dns.go", patch)
        self.assertIn("+++ b/app/dns/nameserver.go", patch)

    def test_udp_v2_source_and_rust_vectors_stay_closed_and_byte_exact(self) -> None:
        metadata = json.loads((ADAPTER / "native-full-profile.json").read_text())
        self.assertEqual(
            metadata["udp_v2_rust_fixture_head"],
            "d79a26fc0979b6fadb7aa01cf1f4d362565ada26",
        )
        patch = (ADAPTER / "native-full-profile.patch").read_text()
        for fixture, member in (
            ("udp-proof-v2-source-vectors.json", "profile-udp-proof-v2-source.json"),
            ("udp-proof-v2-rust-d79a26f.json", "profile-udp-proof-v2-rust.json"),
            (
                "udp-original-destination-v1.json",
                "profile-udp-original-destination-v1.json",
            ),
        ):
            raw = (ADAPTER / "full-profile-fixtures" / fixture).read_bytes()
            added = patch.split(f"+++ b/common/yonikbroker/{member}\n", 1)[1]
            added = added.split("diff --git ", 1)[0]
            embedded = (
                "\n".join(
                    line[1:] for line in added.splitlines() if line.startswith("+")
                )
                + "\n"
            ).encode()
            self.assertEqual(embedded, raw)
        rust = json.loads(
            (
                ADAPTER / "full-profile-fixtures/udp-proof-v2-rust-d79a26f.json"
            ).read_text()
        )
        bootstrap = bytes.fromhex(rust["bootstrap_hex"])
        self.assertEqual(bootstrap[:8], b"YNKPF002")
        self.assertEqual(struct.unpack_from("!HHH", bootstrap, 8), (2, 128, 1))
        self.assertEqual(
            bytes.fromhex(rust["ack_hex"]),
            b"YNKPFA02" + hashlib.sha256(bootstrap).digest(),
        )
        self.assertEqual(len(rust["vectors"]), 10)
        self.assertIn("profileHandshakeWithUDPDelivery(svrSession, reader, conn", patch)
        self.assertIn('string(body[:8]) == "YNKPF002"', patch)
        self.assertIn("p.udpActor.receive(func() (profileProofPacket, error)", patch)
        self.assertIn("privateUDP.Endpoint()", patch)
        self.assertIn("p.udpActor.tick()", patch)
        self.assertIn("namespace: profileKernelSocketNamespace", patch)
        self.assertEqual(
            metadata["udp_v2_original_grammar_head"],
            "7f1f5a8139ecd7f06e64b483b44c627ae2f99654",
        )

    def test_udp_producer_uses_private_flow_and_duplex_reply_without_wire_extension(
        self,
    ) -> None:
        patch = (ADAPTER / "native-full-profile.patch").read_text()
        self.assertIn("privateUDP.Serve(dispatcher.DispatchLink", patch)
        self.assertIn("p.udpActor.producerTick()", patch)
        self.assertIn("p.openConsumed()", patch)
        self.assertIn("p.association.CloseAndJoin()", patch)
        self.assertIn("profileReceiptFrom(u.grantContext) != u.receipt", patch)
        self.assertIn("profileUDPDownstreamCredit", patch)
        self.assertIn("hooks.ProfileBeginLogicalTask(ctx)", patch)
        self.assertIn("errProfileUDPResponseUncertain", patch)
        self.assertIn(
            "TestProfileUDPProducerDelayedSendBlocksKnownCloseAndUncertainIsSticky",
            patch,
        )
        self.assertIn(
            "hooks.ProfileDNSQueryContext, hooks.ProfileCheckDNSAnswer", patch
        )
        self.assertIn("if !owned", patch)

    def test_system_proof_fixture_is_embedded_byte_exact(self) -> None:
        fixture = ADAPTER / "full-profile-fixtures/system-proof-extension-v1.json"
        vectors = json.loads(fixture.read_text())
        bootstrap = bytes.fromhex(vectors["bootstrap_hex"])
        ack = bytes.fromhex(vectors["bootstrap_ack_hex"])
        socket = bytes.fromhex(vectors["socket_hex"])
        self.assertEqual(len(bootstrap), 128)
        self.assertEqual(bootstrap[:8], b"YNKPF001")
        self.assertEqual(ack, b"YNKPFA01" + hashlib.sha256(bootstrap).digest())
        self.assertEqual(len(socket), 192)
        self.assertEqual(socket[:8], b"YNKSPF01")
        self.assertEqual(struct.unpack_from("!HHH", socket, 8), (1, 192, 1))
        self.assertEqual(socket[146:148], bytes((2, 0)))
        local, remote = struct.unpack_from("!HH", socket, 152)
        self.assertNotEqual(local, remote)
        patch = (ADAPTER / "native-full-profile.patch").read_text()
        added = patch.split(
            "+++ b/common/yonikbroker/profile-system-proof-v1.json\n", 1
        )[1].split("diff --git ", 1)[0]
        embedded = (
            "\n".join(line[1:] for line in added.splitlines() if line.startswith("+"))
            + "\n"
        )
        self.assertEqual(embedded.encode(), fixture.read_bytes())

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
