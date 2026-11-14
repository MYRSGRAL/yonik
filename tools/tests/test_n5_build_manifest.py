"""Чистые офлайн fixtures; ELF никогда не запускается."""

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "n5", Path(__file__).parents[1] / "n5_build_manifest.py"
)
n5 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(n5)


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.worker = self.root / "worker"
        self.source = self.root / "source"
        self.receipt = self.root / "receipt.json"
        self.provenance = self.root / "provenance.json"
        self.worker.write_bytes(b"\x7fELF" + b"fixture" * 20)
        self.source.write_bytes(b"retained source archive fixture")
        self.build = {
            "schema": 1,
            "worker_sha256": hashlib.sha256(self.worker.read_bytes()).hexdigest(),
            "source_archive_sha256": hashlib.sha256(
                self.source.read_bytes()
            ).hexdigest(),
        }
        self.pins = {
            "schema": 1,
            "policy_id": n5.POLICY,
            "policy_sha256": "12" * 32,
            "kernel_release": "6.12.1-test",
            "kernel_machine": "x86_64",
            "kernel_abi": n5.ABI,
            "kernel_build_id": "ab" * 20,
        }
        self.save()

    def save(self) -> None:
        self.receipt.write_text(json.dumps(self.build))
        self.provenance.write_text(json.dumps(self.pins))

    def produce(self) -> tuple[dict, dict]:
        return n5.produce(self.worker, self.source, self.receipt, self.provenance)

    def test_exact_tuple(self) -> None:
        manifest, report = self.produce()
        self.assertEqual(
            set(manifest),
            {
                "schema",
                "worker_sha256",
                "source_archive_sha256",
                "policy_id",
                "policy_sha256",
                "kernel_release",
                "kernel_machine",
                "kernel_abi",
                "kernel_build_id",
            },
        )
        self.assertEqual(manifest["kernel_build_id"], [171] * 20)
        self.assertEqual(
            bytes(manifest["worker_sha256"]).hex(), self.build["worker_sha256"]
        )
        self.assertEqual(
            bytes(manifest["source_archive_sha256"]).hex(),
            self.build["source_archive_sha256"],
        )
        self.assertEqual(report["status"], "UNREGISTERED")
        self.assertEqual(report["admission"], "NOT_ADMISSION")
        self.assertNotEqual(
            manifest["policy_sha256"], list(bytes.fromhex(n5.FROZEN_CONTROL))
        )
        self.assertLessEqual(len(n5.encode(manifest)), 4096)

    def test_invalid_pins(self) -> None:
        for key, value in [
            ("schema", True),
            ("policy_id", "other"),
            ("kernel_machine", "arm64"),
            ("kernel_abi", "other"),
            ("kernel_release", "a\nb"),
            ("kernel_release", "x" * 129),
            ("kernel_build_id", "00" * 20),
            ("kernel_build_id", "AB" * 20),
            ("kernel_build_id", "ab" * 19),
            ("kernel_build_id", [1] * 20),
            ("policy_sha256", "00" * 32),
            ("extra", "unknown"),
        ]:
            with self.subTest(key=key, value=value):
                original = dict(self.pins)
                self.pins[key] = value
                self.save()
                with self.assertRaises(ValueError):
                    self.produce()
                self.pins = original
        del self.pins["kernel_build_id"]
        self.save()
        with self.assertRaises(ValueError):
            self.produce()

    def test_receipt_mismatch_and_zero(self) -> None:
        for key in ("worker_sha256", "source_archive_sha256"):
            for value in ("00" * 32, "ff" * 32, "", None):
                with self.subTest(key=key, value=value):
                    original = self.build[key]
                    self.build[key] = value
                    self.save()
                    with self.assertRaises(ValueError):
                        self.produce()
                    self.build[key] = original

    def test_duplicate_unknown_missing_and_non_json(self) -> None:
        for raw in (
            '{"schema":1,"schema":1}',
            '{"schema":1,"unknown":2}',
            "{}",
            "[1]",
            "NaN",
            "{",
        ):
            self.receipt.write_text(raw)
            with self.assertRaises(ValueError):
                self.produce()

    def test_symlink_and_parent_symlink(self) -> None:
        link = self.root / "link"
        link.symlink_to(self.worker)
        with self.assertRaises(OSError):
            n5.read_artifact(link, 4096)
        link.unlink()
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            n5.read_artifact(link / "worker", 4096)

    def test_bounds_magic_and_nonregular(self) -> None:
        for data in (b"", b"not ELF"):
            self.worker.write_bytes(data)
            with self.assertRaises(ValueError):
                n5.read_artifact(self.worker, 4096, elf=True)
        self.worker.write_bytes(b"\x7fELFtoo large")
        with self.assertRaises(ValueError):
            n5.read_artifact(self.worker, 4, elf=True)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            n5.read_artifact(fifo, 4096)

    def test_sparse_artifact_and_metadata_caps(self) -> None:
        for path, limit in (
            (self.worker, n5.MAX_ELF),
            (self.source, n5.MAX_SOURCE),
            (self.receipt, n5.MAX_METADATA),
        ):
            with self.subTest(path=path):
                original = path.read_bytes()
                with path.open("wb") as stream:
                    stream.truncate(limit + 1)
                with self.assertRaises(ValueError):
                    self.produce()
                path.write_bytes(original)

    def test_provenance_duplicate_and_unknown(self) -> None:
        raw = json.dumps(self.pins)
        for invalid in (
            raw[:-1] + ',"kernel_build_id":"' + "12" * 20 + '"}',
            raw[:-1] + ',"unknown":1}',
        ):
            self.provenance.write_text(invalid)
            with self.assertRaises(ValueError):
                self.produce()

    def test_mutation_and_path_replacement(self) -> None:
        real_read = os.read
        for replace in (False, True):
            changed = False

            def mutating_read(fd: int, count: int) -> bytes:
                nonlocal changed
                data = real_read(fd, count)
                if not changed:
                    changed = True
                    if replace:
                        self.worker.unlink()
                    self.worker.write_bytes(b"\x7fELFchanged")
                return data

            with patch.object(n5.os, "read", side_effect=mutating_read):
                with self.assertRaises(ValueError):
                    n5.read_artifact(self.worker, 4096, elf=True)

    def test_emit_exclusive_and_system_path_rejected(self) -> None:
        manifest, report = self.produce()
        with patch.object(n5.Path, "cwd", return_value=self.root):
            output = self.root / "candidate"
            n5.emit(output, manifest, report)
            self.assertEqual(
                json.loads((output / "deployment.json").read_bytes()), manifest
            )
            self.assertEqual(json.loads((output / "report.json").read_bytes()), report)
            with self.assertRaises(FileExistsError):
                n5.emit(output, manifest, report)
            with self.assertRaises(ValueError):
                n5.emit(Path("/usr/lib/yonik"), manifest, report)


if __name__ == "__main__":
    unittest.main()
