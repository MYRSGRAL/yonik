"""Синтетические offline capture; никаких compiler/ELF execution."""

import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import n5_capture_receipts as seam
from _p25_capture_producer import retain


class CaptureReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.retained = self.root / "retained"
        self.retained.mkdir()
        source = self.root / "source"
        source.mkdir()
        build = self.root / "task" / "target"
        (build / "release").mkdir(parents=True)
        self.commit = "a" * 40
        archive = b"synthetic frozen archive bytes"
        (self.retained / "source.tar").write_bytes(archive)
        frozen = {
            "schema": 2,
            "release_id": "synthetic",
            "state": "FROZEN",
            "source": {"commit": self.commit, "tree": "b" * 40},
            "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "recipe": seam.RECIPE,
            "tooling_sha256": {"controller": "c" * 64},
        }
        self.write("frozen.json", frozen)
        elf = struct.pack(
            "<16sHHIQQQIHHHHHH",
            b"\x7fELF\x02\x01\x01",
            3,
            62,
            1,
            0,
            64,
            0,
            0,
            64,
            56,
            1,
            0,
            0,
            0,
        ) + bytes(56)
        for name in seam.RUST:
            (build / "release" / name).write_bytes(elf)
            (self.retained / name).write_bytes(elf)
        commands = [
            {
                "argv": [seam.SLOT, *cmd],
                "cwd": str(source),
                "exit": 0,
                "controlled_env": {},
            }
            for cmd in seam.RECIPE["rust_commands"]
        ]
        manifest = retain(
            source,
            build,
            self.retained,
            frozen,
            commands,
            list(seam.RUST),
            seam.RECIPE["target"],
        )
        marker = {
            **frozen,
            "state": "RUST_CAPTURED_ONLY",
            "producer": "local-release-controller-v1",
            "toolchains": {"rustc": "synthetic", "cargo": "synthetic"},
            "controlled_env": {},
            "commands": commands,
            "elf": {name: seam.elf_header(elf) for name in seam.RUST},
            "build_capture": manifest,
            "rust_lineage": None,
            "final_linux_acceptance": False,
        }
        self.write("rust-captured-only.json", marker)
        self.pins = {name: self.digest(name) for name in (*seam.METADATA, "source.tar")}

    def write(self, name: str, value: dict) -> None:
        (self.retained / name).write_text(json.dumps(value))

    def digest(self, name: str) -> str:
        return hashlib.sha256((self.retained / name).read_bytes()).hexdigest()

    def produce(self) -> tuple[dict, dict]:
        return seam.produce(self.retained, self.pins, self.commit)

    def final_profile_fixture(
        self, registry: bool = False, probe_only: bool = False, alias: bool = False
    ) -> None:
        """Форма enrich/retain: generated, source, staged SDK, normalized deps, observed."""
        from _p25_final_profile import PROFILE

        roots = {
            "source": "/captured/source",
            "build": "/captured/task/target",
            "sdk": "/captured/task/capture-sdk",
        }
        frozen = json.loads((self.retained / "frozen.json").read_bytes())
        body = {
            "spec": dict(PROFILE),
            "tooling_sha256": {
                name: "c" * 64
                for name in (
                    "_p25_final_profile.py",
                    "p25_cxx_capture_wrapper.py",
                    "_p25_capture_producer.py",
                    "p25_capture_build_closure.py",
                )
            },
        }
        frozen["final_profile"] = {
            **body,
            "sha256": hashlib.sha256(
                json.dumps(body, sort_keys=True).encode()
            ).hexdigest(),
        }
        self.write("frozen.json", frozen)
        registry_cwd = None
        if registry:
            import tarfile

            registry_root = self.root / "registry"
            self.enterContext(
                patch.dict(
                    PROFILE, {"registry_source_root": str(registry_root / "src")}
                )
            )
            body["spec"] = dict(PROFILE)
            frozen["final_profile"] = {
                **body,
                "sha256": hashlib.sha256(
                    json.dumps(body, sort_keys=True).encode()
                ).hexdigest(),
            }
            registry_cwd = str(
                registry_root
                / "src/index.crates.io-1949cf8c6b5b557f/link-cplusplus-1.0.12"
            )
            unit_bytes = b"// SPDX-License-Identifier: MIT\n// registry fixture\n"
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz") as tar:
                member = tarfile.TarInfo("link-cplusplus-1.0.12/src/dummy.cc")
                member.size = len(unit_bytes)
                tar.addfile(member, io.BytesIO(unit_bytes))
                header_bytes = b"// SPDX-License-Identifier: LGPL-3.0-only\n"
                member = tarfile.TarInfo("link-cplusplus-1.0.12/include/synthetic.h")
                member.size = len(header_bytes)
                tar.addfile(member, io.BytesIO(header_bytes))
            checksum = hashlib.sha256(archive.getvalue()).hexdigest()
            cache = registry_root / "cache/index.crates.io-1949cf8c6b5b557f"
            cache.mkdir(parents=True)
            (cache / "link-cplusplus-1.0.12.crate").write_bytes(archive.getvalue())
            lock = (
                'version = 4\n[[package]]\nname = "link-cplusplus"\nversion = "1.0.12"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                f'checksum = "{checksum}"\n'
            ).encode()
            source_tar = io.BytesIO()
            with tarfile.open(fileobj=source_tar, mode="w") as tar:
                member = tarfile.TarInfo("src/Cargo.lock")
                member.size = len(lock)
                tar.addfile(member, io.BytesIO(lock))
            (self.retained / "source.tar").write_bytes(source_tar.getvalue())
            frozen["archive_sha256"] = self.digest("source.tar")
            self.write("frozen.json", frozen)
        record = json.loads((self.retained / "build-capture-record.json").read_bytes())
        if registry:
            record["source"]["archive_sha256"] = frozen["archive_sha256"]
        data = {}
        origins = {}

        def add(root: str, path: str, kind: str, raw: bytes) -> str:
            key = "input-" + str(len(record["files"]))
            record["files"].append(
                {
                    "id": key,
                    "root": root,
                    "path": path,
                    "kind": kind,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
            data[root, path] = raw
            return key

        def staged(origin: str, kind: str, raw: bytes) -> str:
            name = hashlib.sha256(origin.encode()).hexdigest()
            origins[origin] = name
            return add("sdk", name, kind, raw)

        compiler = {
            "path": "/usr/bin/synthetic-g++",
            "sha256": hashlib.sha256(b"compiler bytes").hexdigest(),
        }
        compiler_id = staged(compiler["path"], "tool", b"compiler bytes")
        unit = add(
            "build",
            "generated.cpp",
            "generated",
            b"// SPDX-License-Identifier: MIT\n// generated retained bytes\n",
        )
        if registry and not probe_only:
            removed = record["files"].pop()
            del data["build", removed["path"]]
            unit = staged(registry_cwd + "/src/dummy.cc", "sdk-unit", unit_bytes)
        source = add("source", "input.cpp", "source", b"// source input\n")
        header = staged(
            registry_cwd + "/include/synthetic.h"
            if registry
            else "/usr/include/synthetic.h",
            "header",
            b"// SPDX-License-Identifier: LGPL-3.0-only\n",
        )
        alias_id = None
        alias_map = {}
        if alias:
            forest = (
                "release/build/cxx-qt-aaaaaaaaaaaaaaaa/out/cxxqtbuild/include/cxx-qt"
            )
            canonical = roots["build"] + "/" + forest + "/alias.h"
            origin_dir = (
                roots["build"]
                + "/release/build/yonik-desktop-bbbbbbbbbbbbbbbb/out/cxxqtbuild/include/cxx-qt"
            )
            alias_id = add(
                "build",
                forest + "/alias.h",
                "generated",
                b"// synthetic retained header\n",
            )
            alias_map[origin_dir + "/alias.h"] = {
                "canonical": canonical,
                "links": [{"path": origin_dir, "target": str(Path(canonical).parent)}],
                "sha256": record["files"][-1]["sha256"],
            }
        dep = {
            "schema": 1,
            "unit": unit,
            "dependencies": [unit, source, header] + ([alias_id] if alias_id else []),
        }
        dep_id = add(
            "build", "p25capture/0-normalized.json", "depfile", seam.retained_json(dep)
        )
        query_tool = {
            "path": "/usr/bin/synthetic-qtpaths",
            "sha256": hashlib.sha256(b"query bytes").hexdigest(),
        }
        query_id = staged(query_tool["path"], "tool", b"query bytes")
        qt = {
            "schema": 1,
            "version": "6.11.2",
            "sdk_files": [row["id"] for row in record["files"] if row["root"] == "sdk"],
            "query_argv": PROFILE["qt_query"],
            "query_tool": query_id,
            "exit": 0,
        }
        record["qt_version"] = add(
            "build",
            "p25capture/qt-normalized.json",
            "qt-version",
            seam.retained_json(qt),
        )
        argv = [
            PROFILE["compiler"],
            "-c",
            registry_cwd + "/src/dummy.cc"
            if registry and not probe_only
            else roots["build"] + "/generated.cpp",
            "-o",
            "out.o",
            "-MD",
            "-MF",
            roots["build"] + "/p25capture/0.d",
        ]
        record["units"] = [{"file": unit, "depfile": dep_id, "argv": argv}]
        record["source"]["tracked_inputs"] = [source]
        self.write("build-capture-record.json", record)
        config = {
            "schema": 1,
            "source": roots["source"],
            "build": roots["build"],
            "sdk": PROFILE["sdk_root"],
        }
        config_hash = hashlib.sha256(seam.retained_json(config)).hexdigest()
        observed = {
            "schema": 1,
            "config": config,
            "config_sha256": config_hash,
            "input_origins": origins,
            "records": [
                {
                    "schema": 1,
                    "config_sha256": config_hash,
                    "argv": argv,
                    "original_argv": argv[1:-3],
                    "cwd": registry_cwd
                    if registry and not probe_only
                    else roots["source"],
                    "compiler": compiler,
                    "exit": 0,
                    "stdout_sha256": "d" * 64,
                    "stderr_sha256": "e" * 64,
                    "depfile": "p25capture/0.d",
                    "unit": registry_cwd + "/src/dummy.cc"
                    if registry and not probe_only
                    else roots["build"] + "/generated.cpp",
                    "compiler_id": compiler_id,
                    "raw_depfile_sha256": "f" * 64,
                    "normalized_depfile": dep,
                }
            ],
            "qt": {
                "schema": 1,
                "query_argv": PROFILE["qt_query"],
                "version": "6.11.2",
                "exit": 0,
                "tool": query_tool,
                "stdout": "6.11.2\n",
                "stderr_sha256": "e" * 64,
            },
        }
        if alias:
            observed.update(schema=2, aliases=alias_map)
        if registry:
            probe = {
                key: value
                for key, value in observed["records"][0].items()
                if key not in {"raw_depfile_sha256", "normalized_depfile"}
            }
            probe.update(
                original_argv=["-E", roots["build"] + "/generated-probe.cc"],
                argv=[
                    PROFILE["compiler"],
                    "-E",
                    roots["build"] + "/generated-probe.cc",
                ],
                unit=None,
                depfile=None,
                cwd=registry_cwd,
            )
            observed["records"].append(probe)
        self.write("build-cxx-observed.json", observed)
        reader = seam.RetainedReader(self.retained)
        reader.virtual = data
        report = seam._capture(
            reader, "capture-record.json", self.digest("build-capture-record.json")
        )
        report.update(roots=roots, record_path="capture-record.json")
        self.write("build-capture-report.json", report)
        manifest = json.loads(
            (self.retained / "build-capture-manifest.json").read_bytes()
        )
        missing = [
            "qt:query-to-header-version-join",
            f"source-offer-primary-join:{unit}"
            if registry and not probe_only
            else f"generation-provenance:{unit}",
            f"source-offer-primary-join:{header}",
        ]
        if alias_id:
            missing.append(f"generation-provenance:{alias_id}")
        manifest.update(
            source=record["source"],
            missing=report["missing"],
            record_sha256=self.digest("build-capture-record.json"),
            report_sha256=self.digest("build-capture-report.json"),
            final_profile=frozen["final_profile"],
            producer_missing=missing,
            positive_metadata={
                "producer_missing": missing,
                "compiled_units": 1,
                "observed_invocations": len(observed["records"]),
                "qt_version": "6.11.2",
                "observed_sha256": self.digest("build-cxx-observed.json"),
            },
        )
        for row in manifest["observed_commands"]:
            row["cwd"] = roots["source"]
        manifest["invocation"] = [
            "python3",
            "tools/p25_capture_build_closure.py",
            "--source-root",
            roots["source"],
            "--build-root",
            roots["build"],
            "--sdk-root",
            roots["sdk"],
            "--record",
            "capture-record.json",
            "--record-sha256",
            manifest["record_sha256"],
        ]
        self.write("build-capture-manifest.json", manifest)
        marker = json.loads((self.retained / "rust-captured-only.json").read_bytes())
        marker.update(
            archive_sha256=frozen["archive_sha256"],
            final_profile=frozen["final_profile"],
            build_capture=manifest,
            commands=manifest["observed_commands"],
        )
        self.write("rust-captured-only.json", marker)
        self.pins = {
            name: self.digest(name)
            for name in (*seam.METADATA, "source.tar", "build-cxx-observed.json")
        }

    def test_registry_cwd_requires_independent_sidecar(self) -> None:
        self.final_profile_fixture(registry=True)
        with self.assertRaisesRegex(ValueError, "MISSING.*registry proof"):
            self.produce()

    def test_no_registry_context_rejects_extra_proof(self) -> None:
        self.final_profile_fixture()
        with self.assertRaisesRegex(ValueError, "Unexpected registry proof"):
            seam.produce(
                self.retained,
                self.pins,
                self.commit,
                registry_proof="registry-proof.json",
                registry_proof_sha256="0" * 64,
            )

    def test_final_profile_positive_actual_controller_shape(self) -> None:
        self.final_profile_fixture()
        receipts, report = self.produce()
        self.assertEqual(
            receipts["worker.receipt.json"]["elf_sha256"], self.digest("yonik-worker")
        )
        self.assertEqual(report["closure_status"], "MISSING")
        self.assertIn("retained:raw-depfiles-unavailable", report["closure_missing"])
        self.assertEqual(report["admission"], "NOT_ADMISSION")
        import n5_build_manifest as consumer

        receipt = self.retained / "derived-worker.json"
        receipt.write_bytes(seam.encode(receipts["worker-build-receipt.json"]))
        provenance = self.retained / "kernel-provenance.json"
        provenance.write_bytes(
            seam.encode(
                {
                    "schema": 1,
                    "policy_id": consumer.POLICY,
                    "policy_sha256": "a" * 64,
                    "kernel_release": "synthetic-1",
                    "kernel_machine": "x86_64",
                    "kernel_abi": consumer.ABI,
                    "kernel_build_id": "b" * 40,
                }
            )
        )
        candidate, consumer_report = consumer.produce(
            self.retained / "yonik-worker",
            self.retained / "source.tar",
            receipt,
            provenance,
        )
        self.assertEqual(
            candidate["worker_sha256"], list(bytes.fromhex(self.digest("yonik-worker")))
        )
        self.assertEqual(consumer_report["admission"], "NOT_ADMISSION")

    def test_schema2_probe_offline_without_host_sources(self) -> None:
        self.final_profile_fixture()
        observed = json.loads((self.retained / "build-cxx-observed.json").read_bytes())
        observed.update(schema=2, aliases={})
        original = observed["records"][0]
        probe = {
            key: value
            for key, value in original.items()
            if key not in {"raw_depfile_sha256", "normalized_depfile"}
        }
        probe.update(
            schema=2,
            purpose="family-query",
            probe=None,
            original_argv=["-?"],
            argv=["/usr/bin/g++", "-?"],
            exit=1,
            unit=None,
            depfile=None,
        )
        observed["records"].append(probe)
        self.write("build-cxx-observed.json", observed)
        self.pins["build-cxx-observed.json"] = self.digest("build-cxx-observed.json")
        manifest = json.loads(
            (self.retained / "build-capture-manifest.json").read_bytes()
        )
        manifest["positive_metadata"].update(
            observed_invocations=2, observed_sha256=self.pins["build-cxx-observed.json"]
        )
        self.write("build-capture-manifest.json", manifest)
        self.pins["build-capture-manifest.json"] = self.digest(
            "build-capture-manifest.json"
        )
        marker = json.loads((self.retained / "rust-captured-only.json").read_bytes())
        marker["build_capture"] = manifest
        self.write("rust-captured-only.json", marker)
        self.pins["rust-captured-only.json"] = self.digest("rust-captured-only.json")
        _, report = self.produce()
        self.assertEqual(report["admission"], "NOT_ADMISSION")

    def test_schema2_alias_offline_retained_whitelist(self) -> None:
        self.final_profile_fixture(alias=True)
        _, report = self.produce()
        self.assertEqual(report["admission"], "NOT_ADMISSION")

    def final_negative(self, name: str, mutate) -> None:
        self.final_profile_fixture()
        value = json.loads((self.retained / name).read_bytes())
        mutate(value)
        self.write(name, value)
        self.pins[name] = self.digest(name)
        # Обновить внешние hash joins, чтобы тест достиг semantic validator.
        manifest = json.loads(
            (self.retained / "build-capture-manifest.json").read_bytes()
        )
        if name == "build-cxx-observed.json":
            manifest["positive_metadata"]["observed_sha256"] = self.pins[name]
        if name == "build-capture-report.json":
            manifest["report_sha256"] = self.pins[name]
            manifest["missing"] = value["missing"]
        self.write("build-capture-manifest.json", manifest)
        self.pins["build-capture-manifest.json"] = self.digest(
            "build-capture-manifest.json"
        )
        marker = json.loads((self.retained / "rust-captured-only.json").read_bytes())
        marker["build_capture"] = manifest
        self.write("rust-captured-only.json", marker)
        self.pins["rust-captured-only.json"] = self.digest("rust-captured-only.json")
        with self.assertRaises(ValueError):
            self.produce()

    def test_final_profile_tampered_observed_negative(self) -> None:
        self.final_negative(
            "build-cxx-observed.json",
            lambda value: value["records"][0]["argv"].append("-DOTHER"),
        )

    def test_final_profile_scalar_record_uses_cli_validation_error(self) -> None:
        original = {
            path: path.read_bytes()
            for path in self.retained.iterdir()
            if path.is_file()
        }
        pins = dict(self.pins)
        for invalid in (None, 0, False, "scalar", []):
            with self.subTest(invalid=invalid):
                for path, raw in original.items():
                    path.write_bytes(raw)
                self.pins = dict(pins)
                self.final_negative(
                    "build-cxx-observed.json",
                    lambda value: value["records"].__setitem__(0, invalid),
                )
                argv = [
                    "n5_capture_receipts.py",
                    "--retained",
                    str(self.retained),
                    "--source-commit",
                    self.commit,
                    "--output",
                    str(self.root / "must-not-exist"),
                ]
                for name, checksum in self.pins.items():
                    argv.extend(["--" + name.replace(".", "-") + "-sha256", checksum])
                with (
                    patch.object(sys, "argv", argv),
                    patch.object(sys, "stderr", io.StringIO()) as stderr,
                ):
                    with self.assertRaises(SystemExit) as failure:
                        seam.main()
                self.assertEqual(failure.exception.code, 2)
                self.assertNotIn("Traceback", stderr.getvalue())
                self.assertFalse((self.root / "must-not-exist").exists())

    def test_final_profile_tampered_deps_negative(self) -> None:
        self.final_negative(
            "build-cxx-observed.json",
            lambda value: value["records"][0]["normalized_depfile"][
                "dependencies"
            ].pop(),
        )

    def test_final_profile_tampered_generated_negative(self) -> None:
        self.final_negative(
            "build-capture-report.json",
            lambda value: value["unbound_generated_sources"][0].update(text="changed"),
        )

    def test_final_profile_tampered_inputbindings_negative(self) -> None:
        self.final_negative(
            "build-cxx-observed.json",
            lambda value: value["input_origins"].update({"/etc/untrusted": "a" * 64}),
        )

    def test_final_profile_tampered_profilebindings_negative(self) -> None:
        self.final_negative(
            "build-cxx-observed.json",
            lambda value: value["config"].update(sdk="/other"),
        )

    def test_final_profile_verified_boolean_schema_negative(self) -> None:
        self.final_negative(
            "build-capture-report.json",
            lambda value: value["files"][0].update(verified=1),
        )

    def test_final_profile_observed_unpinned_negative(self) -> None:
        self.final_profile_fixture()
        self.pins.pop("build-cxx-observed.json")
        with self.assertRaises(ValueError):
            self.produce()

    def test_final_profile_observed_duplicate_unknown_schema_negative(self) -> None:
        self.final_profile_fixture()
        path = self.retained / "build-cxx-observed.json"
        original = path.read_text()
        for raw in (
            '{"schema":1,' + original[1:],
            original[:-1] + ',"unknown":0}',
            original.replace('"schema": 1', '"schema": true', 1),
        ):
            path.write_text(raw)
            self.pins["build-cxx-observed.json"] = self.digest(
                "build-cxx-observed.json"
            )
            with self.assertRaises(ValueError):
                self.produce()

    def test_final_profile_observed_nofollow_negative(self) -> None:
        self.final_profile_fixture()
        path = self.retained / "build-cxx-observed.json"
        saved = self.root / "observed"
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaises(OSError):
            self.produce()

    def test_final_profile_observed_missing_negative(self) -> None:
        self.final_profile_fixture()
        (self.retained / "build-cxx-observed.json").unlink()
        with self.assertRaises(FileNotFoundError):
            self.produce()

    def test_final_profile_observed_bounds_negative(self) -> None:
        self.final_profile_fixture()
        (self.retained / "build-cxx-observed.json").write_bytes(
            b"x" * (8 * 1024**2 + 1)
        )
        with self.assertRaises(ValueError):
            self.produce()

    def test_final_profile_report_missing_conflict_negative(self) -> None:
        self.final_negative(
            "build-capture-report.json",
            lambda value: value["missing"].append("invented"),
        )

    def test_positive_existing_formats(self) -> None:
        receipts, report = self.produce()
        self.assertEqual(report["driver"], "MISSING")
        self.assertEqual(report["status"], "UNREGISTERED")
        self.assertEqual(
            set(receipts["worker-build-receipt.json"]),
            {"schema", "worker_sha256", "source_archive_sha256"},
        )
        for role in seam.ROLES:
            receipt = receipts[role + ".receipt.json"]
            self.assertEqual(
                set(receipt),
                {"schema", "source_commit", "source_archive_sha256", "elf_sha256"},
            )
            self.assertEqual(receipt["elf_sha256"], self.digest(seam.ROLES[role]))
            self.assertEqual(
                report["receipt_sha256"][role + ".receipt.json"],
                hashlib.sha256(seam.encode(receipt)).hexdigest(),
            )

    def test_actualbytes_mismatch(self) -> None:
        (self.retained / "yonik-worker").write_bytes(b"\x7fELF" + bytes(120))
        with self.assertRaises(ValueError):
            self.produce()

    def test_missingclosure(self) -> None:
        marker = json.loads((self.retained / "rust-captured-only.json").read_bytes())
        marker["build_capture"] = None
        self.write("rust-captured-only.json", marker)
        self.pins["rust-captured-only.json"] = self.digest("rust-captured-only.json")
        with self.assertRaises(ValueError):
            self.produce()

    def test_unpinned(self) -> None:
        self.pins.pop("rust-captured-only.json")
        with self.assertRaises(ValueError):
            self.produce()

    def test_stale(self) -> None:
        self.commit = "d" * 40
        with self.assertRaises(ValueError):
            self.produce()

    def test_dup_unknown_schema(self) -> None:
        path = self.retained / "frozen.json"
        original = path.read_text()
        for raw in (
            '{"schema":2,' + original[1:],
            original[:-1] + ',"unknown":0}',
            original.replace('"schema": 2', '"schema": true'),
        ):
            path.write_text(raw)
            self.pins["frozen.json"] = self.digest("frozen.json")
            with self.assertRaises(ValueError):
                self.produce()

    def test_bounds(self) -> None:
        with patch.object(seam, "MAX_METADATA", 8), self.assertRaises(ValueError):
            self.produce()

    def test_nofollow_file_and_ancestor(self) -> None:
        path = self.retained / "source.tar"
        path.rename(self.root / "archive")
        path.symlink_to(self.root / "archive")
        with self.assertRaises(OSError):
            self.produce()
        alias = self.root / "alias"
        alias.symlink_to(self.retained, target_is_directory=True)
        with self.assertRaises(OSError):
            seam.produce(alias, self.pins, self.commit)

    def test_mutation(self) -> None:
        original = seam.read_artifact
        calls = 0

        def changing(*args: object, **kwargs: object) -> tuple[str, bytes]:
            nonlocal calls
            result = original(*args, **kwargs)
            calls += 1
            if calls == 7:
                (self.retained / "frozen.json").write_bytes(b"{}")
            return result

        with (
            patch.object(seam, "read_artifact", side_effect=changing),
            self.assertRaises(ValueError),
        ):
            self.produce()

    def test_pathidentity_same_bytes_replacement(self) -> None:
        original = seam.read_artifact
        calls = 0

        def replacing(*args: object, **kwargs: object) -> tuple[str, bytes]:
            nonlocal calls
            result = original(*args, **kwargs)
            calls += 1
            if calls == 7:
                target = self.retained / "frozen.json"
                replacement = self.retained / "replacement"
                replacement.write_bytes(target.read_bytes())
                replacement.replace(target)
            return result

        with (
            patch.object(seam, "read_artifact", side_effect=replacing),
            self.assertRaises(ValueError),
        ):
            self.produce()

    def test_outputoverwrite(self) -> None:
        receipts, report = self.produce()
        old = Path.cwd()
        try:
            os.chdir(self.root)
            output = self.root / "output"
            seam.emit(output, receipts, report)
            with self.assertRaises(FileExistsError):
                seam.emit(output, receipts, report)
            self.assertEqual(
                (output / "worker-build-receipt.json").read_bytes(),
                seam.encode(receipts["worker-build-receipt.json"]),
            )
            with self.assertRaises(ValueError):
                seam.emit(Path("/etc/forbidden"), receipts, report)
        finally:
            os.chdir(old)


if __name__ == "__main__":
    unittest.main()
