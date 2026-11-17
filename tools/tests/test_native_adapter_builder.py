"""Проверки закреплённой сборки без сети и настоящего Go toolchain."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_native_adapter as builder  # noqa: E402


class BuilderTests(unittest.TestCase):
    def test_france_projection_all_scopes_fit_protected_manifest_without_authority(
        self,
    ) -> None:
        record = {
            "contract": "yonik-xray-profile-udp-v2",
            "version": 1,
            "source_commit": builder.XRAY_COMMIT,
            "patch_sha256": builder.PROFILE_PATCH,
            **{
                key: "12" * 32
                for key in (
                    "source_sha256",
                    "builder_sha256",
                    "toolchain_sha256",
                    "build_inputs_sha256",
                    "elf_sha256",
                )
            },
        }
        candidate = builder.france_candidate(record)
        self.assertFalse(candidate["install_authority"])
        raw = candidate["registry_projection"]
        self.assertLessEqual(len(raw.encode()), 4096)

        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                self.assertNotIn(key, result)
                result[key] = value
            return result

        projection = json.loads(raw, object_pairs_hook=unique)
        self.assertEqual(projection["schema"], 2)
        entry = projection["engines"][0]
        self.assertEqual(entry["sha256"], record["elf_sha256"])
        producer = entry["native_profile_producer"]
        self.assertEqual(len(set(producer) - set(record)), 9)
        self.assertNotIn("dns_wire", producer)
        self.assertNotIn("dns_release", producer)
        self.assertNotIn("path", entry)
        self.assertEqual(set(record), set(producer) & set(record))
        with self.assertRaises(builder.BuildError):
            builder.france_candidate(record | {"oversize": "x" * 4096})

    def test_tcp5_candidate_keeps_tcp_udp_source_reviews_separate(self) -> None:
        original = {"elf_sha256": "11" * 32, "patch_sha256": "44" * 32}
        candidate = builder.tcp5_candidate(original)
        self.assertFalse(candidate["install_authority"])
        self.assertFalse(candidate["source_eligibility"])
        record = candidate["candidate_record"]
        self.assertEqual(record["elf_sha256"], original["elf_sha256"])
        self.assertEqual(record["patch_sha256"], original["patch_sha256"])
        self.assertNotIn("bootstrap_source", record)
        self.assertNotIn("bootstrap_datagram", record)
        self.assertEqual(set(original), {"elf_sha256", "patch_sha256"})
        for slot, contract in (
            ("bootstrap_tcp5_source", "tcp-codec5-bootstrap-parent-member-v1"),
            ("bootstrap_tcp5_dns_wire", "tcp-codec5-bootstrap-bound-dns-transcript-v1"),
            (
                "bootstrap_tcp5_dns_release",
                "tcp-codec5-bootstrap-dns-consuming-close-join-v1",
            ),
        ):
            self.assertEqual(
                record[slot]["schema_sha256"],
                hashlib.sha256(b"YONIK-DNS-V2-CODEC-5\0").hexdigest(),
            )
            self.assertEqual(
                record[slot]["contract_sha256"],
                hashlib.sha256(contract.encode() + b"\0").hexdigest(),
            )

    def test_datagram_candidate_is_scope5_request_not_source_or_install_authority(
        self,
    ) -> None:
        record = {"elf_sha256": "11" * 32, "patch_sha256": "44" * 32}
        projected = builder.datagram_candidate(record)
        self.assertFalse(projected["install_authority"])
        self.assertFalse(projected["source_eligibility"])
        candidate = projected["candidate_record"]
        self.assertEqual(candidate["elf_sha256"], record["elf_sha256"])
        self.assertEqual(candidate["patch_sha256"], record["patch_sha256"])
        for slot in (
            "bootstrap_datagram",
            "bootstrap_datagram_dns_wire",
            "bootstrap_datagram_dns_release",
        ):
            self.assertNotIn(slot, record)
            self.assertEqual(
                candidate[slot]["schema_sha256"],
                hashlib.sha256(b"YONIK-DNS-V2-CODEC-5\0").hexdigest(),
            )
        self.assertNotIn("bootstrap_source", candidate)

    def test_bootstrap_candidate_is_independent_compile_only_metadata(self) -> None:
        original = {"elf_sha256": "11" * 32, "patch_sha256": "44" * 32}
        candidate = builder.bootstrap_candidate(original)
        self.assertFalse(candidate["install_authority"])
        self.assertTrue(candidate["requires_independent_scope_review"])
        self.assertEqual(candidate["validation"], "COMPILE_ONLY_CANDIDATE")
        record = candidate["candidate_record"]
        self.assertEqual(record["elf_sha256"], original["elf_sha256"])
        self.assertEqual(record["patch_sha256"], original["patch_sha256"])
        for slot, contract in (
            ("bootstrap_source", "captured-netgo-bootstrap-parent-member-v1"),
            ("bootstrap_dns_wire", "bootstrap-direct-dns-bound-request-response-v1"),
            ("bootstrap_dns_release", "bootstrap-direct-dns-consuming-close-join-v1"),
        ):
            self.assertNotIn(slot, original)
            self.assertEqual(record[slot]["contract"], contract)
            self.assertEqual(record[slot]["version"], 1)
            self.assertEqual(
                record[slot]["contract_sha256"],
                hashlib.sha256(contract.encode() + b"\0").hexdigest(),
            )
            self.assertEqual(
                record[slot]["schema_sha256"],
                hashlib.sha256(b"YONIK-DNS-V2-CODEC-4\0").hexdigest(),
            )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="yonik-builder-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "build"
        self.source = self.root / "build-source-sing-box"
        (self.source / "release").mkdir(parents=True)
        (self.source / "release/DEFAULT_BUILD_TAGS_OTHERS").write_text(
            "with_quic,with_utls\n"
        )
        (self.source / "go.mod").write_text("module example\n")
        (self.source / "go.sum").write_text("fixture\n")
        self.patch_file = self.base / "adapter.patch"
        self.patch_file.write_bytes(builder.DEFAULT_PATCH.read_bytes())
        self.extra_patches = []
        for name in (
            "dns_provenance",
            "pin_resolution",
            "external_tun_configuration",
        ):
            path = self.base / f"{name}.patch"
            path.write_text(f"synthetic canonical {name} patch")
            self.extra_patches.append((path, name))
        self.output = self.base / "output"
        self.head = builder.SOURCE_COMMIT
        self.dirty = ""
        self.fail_go = False
        self.modify_module = False
        self.binary_version = builder.SOURCE_VERSION
        self.commands: list[list[str]] = []

    def fake_run(self, runner: builder.Runner, argv: list[str], cwd: Path) -> str:
        self.commands.append(argv)
        # Эксклюзивная блокировка не должна проходить, пока запущена команда.
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        for name in ("GOCACHE", "GOMODCACHE", "GOPATH", "GOTMPDIR", "TMPDIR"):
            self.assertTrue(Path(runner.env[name]).is_relative_to(self.root))
        self.assertEqual(runner.env["GOTOOLCHAIN"], "local")
        self.assertEqual(runner.env["GOENV"], "off")
        self.assertNotIn("GOFLAGS", runner.env)
        self.assertEqual(runner.env.get("HOME"), os.environ.get("HOME"))
        if argv[:3] == ["git", "rev-parse", "HEAD"]:
            return self.head + "\n"
        if argv[:2] == ["git", "rev-parse"]:
            return builder.SOURCE_COMMIT + "\n"
        if argv[:2] == ["git", "status"]:
            return self.dirty
        if argv[:2] == ["go", "version"]:
            return "go version go1.25.0 linux/amd64\n"
        if argv[:2] == ["go", "env"]:
            return json.dumps({"GOOS": "linux", "GOARCH": "amd64", "GOEXPERIMENT": ""})
        if argv[:2] == ["go", "build"]:
            prebuild = json.loads((runner.logs / "prebuild.json").read_text())
            self.assertEqual(prebuild["build_args"], argv)
            self.assertEqual(prebuild["build_environment"]["GOMAXPROCS"], "1")
            self.assertIsNone(prebuild["native_protocol"])
            if self.fail_go:
                raise builder.BuildError("Go завершился с ошибкой")
            if self.modify_module:
                (self.source / "go.sum").write_text("unexpected change")
            Path(argv[argv.index("-o") + 1]).write_bytes(b"fixture binary")
        if len(argv) == 2 and argv[1] == "version":
            return f"sing-box version {self.binary_version}\n"
        return ""

    def build(self) -> Path:
        with (
            patch.object(
                builder.Runner, "run", autospec=True, side_effect=self.fake_run
            ),
            patch.object(
                builder, "EXTRA_PATCHES", tuple(self.extra_patches), create=True
            ),
        ):
            return builder.build(self.root, self.output, self.patch_file)

    def test_xray_build_is_pinned_and_claims_no_unimplemented_features(self) -> None:
        self.source = self.root / "build-source-xray"
        self.source.mkdir()
        (self.source / "go.mod").write_text("module github.com/xtls/xray-core\n")
        (self.source / "go.sum").write_text("fixture\n")
        self.head = builder.XRAY_COMMIT
        original = self.fake_run

        def run(runner: builder.Runner, argv: list[str], cwd: Path) -> str:
            if argv[:2] == ["git", "rev-parse"]:
                original(runner, ["git", "status"], cwd)
                return builder.XRAY_COMMIT + "\n"
            if len(argv) == 2 and argv[1] == "version":
                return "Xray 26.10.31 (Xray, Penetrates Everything.) fixture\n"
            return original(runner, argv, cwd)

        with patch.object(builder.Runner, "run", autospec=True, side_effect=run):
            result = builder.build(
                self.root, self.output, self.patch_file, "xray", compile_only=True
            )
        manifest = json.loads(result.read_text())
        self.assertEqual(manifest["source_commit"], builder.XRAY_COMMIT)
        self.assertEqual(
            manifest["prebuild_sha256"], builder.sha256(self.output / "prebuild.json")
        )
        self.assertEqual(manifest["adapter_features"], {})
        self.assertEqual(manifest["patches"], [])
        self.assertIsNone(manifest["patch_sha256"])
        self.assertTrue((self.output / "xray").is_file())
        command = next(argv for argv in self.commands if argv[:2] == ["go", "build"])
        self.assertIn("-p=1", command)
        self.assertEqual(command[-1], "./main")
        self.assertFalse(any(argv[:2] == ["git", "apply"] for argv in self.commands))
        self.assertFalse(
            any(
                argv and argv[0] == str(self.root / "build-native-adapter-xray")
                for argv in self.commands
            )
        )
        self.assertEqual(manifest["validation"], "COMPILE_ONLY")
        self.assertFalse(manifest["binary_version_executed"])

    def test_codec_component_is_verified_without_feature_ack(self) -> None:
        self.check_codec_component(compile_only=False)

    def test_compile_only_codec_never_executes_tests_or_core(self) -> None:
        self.check_codec_component(compile_only=True)

    def check_codec_component(self, *, compile_only: bool) -> None:
        original = self.fake_run

        def run(runner: builder.Runner, argv: list[str], cwd: Path) -> str:
            if argv[:2] == ["git", "apply"] and "native-broker-codec.patch" in argv[-1]:
                subprocess.run(
                    [
                        *argv[:-1],
                        *(
                            f"--exclude={name}"
                            for name in metadata["callsite_files_sha256"]
                        ),
                        argv[-1],
                    ],
                    cwd=cwd,
                    check=True,
                    capture_output=True,
                )
            return original(runner, argv, cwd)

        metadata = json.loads(
            builder.DEFAULT_PATCH.with_name("native-broker-codec.json").read_text()
        )
        real_sha256 = builder.sha256

        def sha256(path: Path) -> str:
            if path in {
                self.source / name for name in metadata["callsite_files_sha256"]
            }:
                return metadata["callsite_files_sha256"][
                    str(path.relative_to(self.source))
                ]
            return real_sha256(path)

        with (
            patch.object(builder, "sha256", side_effect=sha256),
            patch.object(builder.Runner, "run", autospec=True, side_effect=run),
            patch.object(builder, "EXTRA_PATCHES", tuple(self.extra_patches)),
        ):
            result = builder.build(
                self.root,
                self.output,
                self.patch_file,
                native_codec=True,
                compile_only=compile_only,
            )
        manifest = json.loads(result.read_text())
        self.assertFalse(manifest["native_codec_component"]["runtime_hooks_connected"])
        self.assertTrue(
            manifest["native_codec_component"]["routing_entry_guard_connected"]
        )
        if compile_only:
            tests = [argv for argv in self.commands if argv[:2] == ["go", "test"]]
            self.assertEqual(len(tests), 3)
            self.assertTrue(all("-c" in argv for argv in tests))
            self.assertFalse(
                any(
                    argv and argv[0].startswith(str(self.root))
                    for argv in self.commands
                )
            )
            self.assertEqual(manifest["validation"], "COMPILE_ONLY")
            return
        self.assertIn(["go", "test", "-p=1", "-mod=readonly", "./route"], self.commands)
        self.assertIn(
            ["go", "test", "-p=1", "-mod=readonly", "./protocol/tun"], self.commands
        )
        self.assertTrue(
            manifest["native_codec_component"]["owned_tun_constructor_connected"]
        )
        self.assertIsNone(manifest["native_protocol"])
        self.assertNotIn("native_broker", manifest["adapter_features"])
        self.assertIn(
            ["go", "test", "-p=1", "-mod=readonly", "./common/yonikbroker"],
            self.commands,
        )

    def test_unknown_engine_is_rejected_before_commands(self) -> None:
        with self.assertRaises(builder.BuildError):
            builder.build(self.root, self.output, self.patch_file, "other")
        self.assertFalse(self.commands)

    def test_profile_evidence_refuses_non_compile_only_or_wrong_engine(self) -> None:
        for engine, compile_only in (("xray", False), ("sing-box", True)):
            with self.assertRaises(builder.BuildError):
                builder.build(
                    self.root,
                    self.output,
                    self.patch_file,
                    engine,
                    compile_only=compile_only,
                    experimental_profile=True,
                )
        self.assertFalse(self.commands)

    def test_profile_compile_only_emits_record_without_execution_or_install(
        self,
    ) -> None:
        self.source = self.root / "build-source-xray"
        self.source.mkdir()
        (self.source / "go.mod").write_text("module fixture\n")
        (self.source / "go.sum").write_text("fixture\n")
        self.head = builder.XRAY_COMMIT
        adapter = builder.DEFAULT_PATCH.parents[2] / "xray" / builder.XRAY_TAG
        codec = json.loads((adapter / "native-broker-codec.json").read_text())
        full = json.loads((adapter / "native-full-profile.json").read_text())
        accepted_fixture_pin = full["patch_sha256"]
        phase = False
        original_hash = builder.sha256

        def digest(path: Path) -> str:
            metadata = full if phase else codec
            pins = {
                **{
                    f"common/yonikbroker/{name}": value
                    for name, value in metadata["package_files_sha256"].items()
                },
                **metadata.get("callsite_files_sha256", {}),
            }
            if (
                path.is_relative_to(self.source)
                and str(path.relative_to(self.source)) in pins
            ):
                return pins[str(path.relative_to(self.source))]
            return original_hash(path)

        def run(runner: builder.Runner, argv: list[str], cwd: Path) -> str:
            nonlocal phase
            if argv[:2] == ["git", "rev-parse"]:
                self.commands.append(argv)
                return builder.XRAY_COMMIT + "\n"
            if argv[:2] == ["git", "apply"] and argv[-1].endswith(
                "native-full-profile.patch"
            ):
                phase = True
            result = self.fake_run(runner, argv, cwd)
            if argv[:2] == ["go", "build"]:
                Path(argv[argv.index("-o") + 1]).write_bytes(
                    b"\x7fELFsynthetic: never execute"
                )
            return result

        with (
            patch.object(builder, "sha256", side_effect=digest),
            patch.object(builder.Runner, "run", autospec=True, side_effect=run),
            patch.object(builder, "toolchain_digest", return_value="15" * 32),
            # Только fake reviewed pin; production allowlist не следует metadata.
            patch.object(builder, "PROFILE_PATCH", accepted_fixture_pin),
        ):
            builder.build(
                self.root,
                self.output,
                self.patch_file,
                "xray",
                compile_only=True,
                experimental_profile=True,
            )
        record = json.loads((self.output / "native-profile-producer.json").read_text())
        self.assertEqual(record["elf_sha256"], original_hash(self.output / "xray"))
        self.assertEqual(record["patch_sha256"], accepted_fixture_pin)
        candidate = json.loads(
            (self.output / "native-profile-dns-release-candidate.json").read_text()
        )
        self.assertFalse(candidate["install_authority"])
        self.assertTrue(candidate["requires_factory_ownership_review"])
        self.assertEqual(
            candidate["candidate_record"]["elf_sha256"], record["elf_sha256"]
        )
        self.assertEqual(
            candidate["candidate_record"]["dns_release"]["schema_sha256"],
            hashlib.sha256(b"YONIK-DNS-V2-CODEC-3\0").hexdigest(),
        )
        self.assertNotIn("dns_release", record)
        self.assertEqual(
            candidate["candidate_record"]["dns_wire"]["contract"],
            "direct-dns-bound-request-response-v1",
        )
        self.assertEqual(
            candidate["candidate_record"]["dns_wire"]["schema_sha256"],
            hashlib.sha256(b"YONIK-DNS-V2-CODEC-3\0").hexdigest(),
        )
        self.assertNotIn("dns_wire", record)
        bootstrap = json.loads(
            (self.output / "native-profile-bootstrap-candidate.json").read_text()
        )
        self.assertFalse(bootstrap["install_authority"])
        self.assertTrue(bootstrap["requires_independent_scope_review"])
        for slot in ("bootstrap_source", "bootstrap_dns_wire", "bootstrap_dns_release"):
            self.assertNotIn(slot, record)
            self.assertEqual(
                bootstrap["candidate_record"][slot]["schema_sha256"],
                hashlib.sha256(b"YONIK-DNS-V2-CODEC-4\0").hexdigest(),
            )
        self.assertEqual(
            bootstrap["candidate_record"]["elf_sha256"], record["elf_sha256"]
        )
        self.assertEqual(
            record["builder_sha256"], original_hash(Path(builder.__file__))
        )
        self.assertFalse(
            any(argv and argv[0].startswith(str(self.root)) for argv in self.commands)
        )

    def test_unknown_patch_cannot_claim_strict_complete_feature(self) -> None:
        self.patch_file.write_text("unrelated README-only patch")
        with self.assertRaisesRegex(builder.BuildError, "каноническ"):
            self.build()
        self.assertFalse(self.commands)
        self.assertFalse((self.output / "manifest.json").exists())

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Требуется Linux pidfd")
    def test_timeout_stops_descendants_before_return(self) -> None:
        runner = builder.Runner(self.root)
        pid_file = self.base / "child.pid"
        script = (
            "import subprocess,sys,time; from pathlib import Path; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
            "Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)"
        )
        original_run = subprocess.run

        def short_run(
            *args: object, **kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            kwargs["timeout"] = 0.3
            return original_run(*args, **kwargs)

        child_pid = None
        try:
            with (
                patch.object(builder, "COMMAND_TIMEOUT", 0.3, create=True),
                patch.object(builder.subprocess, "run", side_effect=short_run),
            ):
                with self.assertRaisesRegex(builder.BuildError, "лимит времени"):
                    runner.run([sys.executable, "-c", script, str(pid_file)], self.root)
            child_pid = int(pid_file.read_text())
            try:
                descriptor = os.pidfd_open(child_pid)
            except ProcessLookupError:
                return  # Потомок уже завершён и reaped.
            try:
                self.assertTrue(
                    select.select([descriptor], [], [], 0.5)[0],
                    "Потомок пережил timeout builder",
                )
            finally:
                os.close(descriptor)
        finally:
            if child_pid is None and pid_file.exists():
                child_pid = int(pid_file.read_text())
            if child_pid is not None:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_signal_during_handler_restore_still_stops_process_group(self) -> None:
        runner = builder.Runner(self.root)
        events = (signal.SIGINT, signal.SIGTERM)
        previous = {event: signal.getsignal(event) for event in events}
        original_signal = signal.signal
        interrupted = False

        def restore_with_interrupt(event: int, handler: object) -> object:
            nonlocal interrupted
            result = original_signal(event, handler)
            if (
                event == signal.SIGINT
                and handler is previous[event]
                and not interrupted
            ):
                interrupted = True
                signal.raise_signal(signal.SIGINT)
            return result

        try:
            with (
                patch.object(builder.subprocess, "Popen") as popen,
                patch.object(builder.os, "killpg") as kill_group,
                patch.object(
                    builder.signal, "signal", side_effect=restore_with_interrupt
                ),
            ):
                popen.return_value.pid = 12345
                with self.assertRaises(KeyboardInterrupt):
                    runner.run(["git", "status"], self.root)
                kill_group.assert_called_once_with(12345, signal.SIGKILL)
        finally:
            for event, handler in previous.items():
                original_signal(event, handler)

    def test_wrong_head_refused_before_patch(self) -> None:
        self.head = "0" * 40
        with self.assertRaisesRegex(builder.BuildError, "HEAD"):
            self.build()
        self.assertFalse(any("apply" in command for command in self.commands))

    def test_dirty_source_refused(self) -> None:
        self.dirty = " M go.mod\n"
        with self.assertRaisesRegex(builder.BuildError, "чист"):
            self.build()

    def test_success_records_patch_binary_and_exact_build_settings(self) -> None:
        manifest = json.loads(self.build().read_text())
        self.assertEqual(
            manifest["patch_sha256"],
            hashlib.sha256(self.patch_file.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            manifest["binary_sha256"], hashlib.sha256(b"fixture binary").hexdigest()
        )
        self.assertEqual(manifest["source_commit"], builder.SOURCE_COMMIT)
        self.assertEqual(manifest["source_tag"], "v1.14.4")
        self.assertEqual(manifest["engine"], "sing-box")
        self.assertEqual(manifest["engine_version"], "1.14.4")
        self.assertEqual(manifest["build_tags"], ["with_quic", "with_utls"])
        self.assertTrue(manifest["adapter_features"]["strict_complete_dns"])
        self.assertTrue(manifest["adapter_features"]["external_tun_configuration"])
        self.assertFalse(manifest["strictDNSGate"])
        self.assertFalse(manifest["strict_dns_gate"])
        self.assertIn("-mod=readonly", manifest["build_args"])
        self.assertEqual(
            manifest["build_args"][manifest["build_args"].index("-ldflags") + 1],
            "-X github.com/sagernet/sing-box/constant.Version=1.14.4",
        )
        self.assertEqual(manifest["build_args"][-1], "./cmd/sing-box")

    def test_unknown_binary_version_is_refused_before_publication(self) -> None:
        self.binary_version = "unknown"
        with self.assertRaisesRegex(builder.BuildError, "закреплённую версию"):
            self.build()
        self.assertFalse((self.output / "manifest.json").exists())

    def test_default_chain_binds_the_external_tun_patch(self) -> None:
        entries = [
            path
            for path, feature in builder.EXTRA_PATCHES
            if feature == "external_tun_configuration"
        ]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, "external-tun-configuration.patch")
        self.assertTrue(entries[0].is_file())

    def test_manifest_binds_complete_ordered_patch_chain(self) -> None:
        manifest = json.loads(self.build().read_text())
        expected = [self.patch_file, *(path for path, _ in self.extra_patches)]
        self.assertEqual(
            [entry["sha256"] for entry in manifest["patches"]],
            [builder.sha256(path) for path in expected],
        )
        self.assertEqual(
            [
                command[-1]
                for command in self.commands
                if command[:3] == ["git", "apply", "--check"]
            ],
            [str(path) for path in expected],
        )
        self.assertTrue(manifest["adapter_features"]["dns_provenance"])
        self.assertTrue(manifest["adapter_features"]["pin_resolution"])
        self.assertFalse(manifest["strict_dns_gate"])

    def test_failed_go_does_not_publish_manifest(self) -> None:
        self.fail_go = True
        with self.assertRaises(builder.BuildError):
            self.build()
        self.assertFalse((self.output / "manifest.json").exists())
        self.assertFalse((self.output / "sing-box").exists())

    def test_modified_module_does_not_publish(self) -> None:
        self.modify_module = True
        with self.assertRaisesRegex(builder.BuildError, "go.mod/go.sum"):
            self.build()
        self.assertFalse((self.output / "manifest.json").exists())

    def test_partial_prior_build_is_not_restarted(self) -> None:
        self.fail_go = True
        with self.assertRaises(builder.BuildError):
            self.build()
        self.fail_go = False
        with self.assertRaisesRegex(builder.BuildError, "предыдущ"):
            self.build()

    def test_output_inside_build_root_refused(self) -> None:
        self.output = self.root / "output"
        with self.assertRaisesRegex(builder.BuildError, "output"):
            self.build()

    def test_runner_keeps_failed_process_stdout_stderr(self) -> None:
        runner = builder.Runner(self.root)
        with self.assertRaisesRegex(builder.BuildError, "кодом 7"):
            runner.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('out'); sys.stderr.write('err'); sys.exit(7)",
                ],
                self.root,
            )
        self.assertEqual(next(runner.logs.glob("*.stdout.log")).read_text(), "out")
        self.assertEqual(next(runner.logs.glob("*.stderr.log")).read_text(), "err")

    def test_runner_limits_git_and_go_build_duration(self) -> None:
        runner = builder.Runner(self.root)
        for argv, timeout in ((["git", "clone"], 180), (["go", "build"], 900)):
            with (
                self.subTest(argv=argv),
                patch.object(builder.subprocess, "Popen") as popen,
                patch.object(builder.os, "killpg") as kill_group,
            ):
                process = popen.return_value
                process.pid = 12345
                process.wait.side_effect = [subprocess.TimeoutExpired(argv, timeout), 0]
                with self.assertRaisesRegex(builder.BuildError, "лимит времени"):
                    runner.run(argv, self.root)
                self.assertEqual(
                    process.wait.call_args_list[0].kwargs["timeout"], timeout
                )
                self.assertTrue(popen.call_args.kwargs["start_new_session"])
                kill_group.assert_called_once_with(12345, signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
