"""Конечный gate 14 границ exact source172; не свидетельство принятия в main."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.tests.test_p11_acceptance_closure import CONTEXTS, ROOT

LEDGER = ROOT / "docs/validation/p11-integrated-candidate.json"


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def fresh(blobs: dict[str, str], root: Path = ROOT) -> bool:
    return all(
        git("hash-object", str(root / path)) == blob for path, blob in blobs.items()
    )


def checked_blobs(ledger: dict) -> dict[str, str]:
    blobs = dict(ledger["source_blobs"])
    for path, update in ledger.get("reviewed_source_updates", {}).items():
        if path not in blobs or not update["scope"] or not update["review"]:
            raise ValueError("Обновление source требует исходной привязки и review")
        blobs[path] = update["blob"]
    return blobs


def producer_log(evidence: dict[str, str], root: Path = ROOT) -> bytes:
    binding = json.loads((root / evidence["binding"]).read_text())
    if binding["source_head"] != evidence["source"]:
        raise ValueError("Producer evidence относится к другому source")
    log = (root / evidence["log"]).read_bytes()
    if hashlib.sha256(log).hexdigest() != evidence["log_sha256"]:
        raise ValueError("SHA256 producer log не совпадает")
    return log


class IntegratedCandidate(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = json.loads(LEDGER.read_text())

    def test_historical_source_hashes(self) -> None:
        source = self.ledger["source"]
        self.assertEqual(source, "6f45329b2e0a9b1659232fd4558d75308a6bc6c7")
        for blob in checked_blobs(self.ledger).values():
            self.assertRegex(blob, r"^[0-9a-f]{40}$")
        if git("rev-parse", "--is-shallow-repository") == "true":
            self.skipTest("Исторические Git-объекты требуют полной истории")
        for path, blob in self.ledger["source_blobs"].items():
            self.assertEqual(git("rev-parse", f"{source}:{path}"), blob)
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", source, "HEAD"], cwd=ROOT, check=True
        )
        if self.ledger.get("source_accepted_in_main"):
            subprocess.run(
                [
                    "git",
                    "merge-base",
                    "--is-ancestor",
                    source,
                    self.ledger["accepted_main_observed"],
                ],
                cwd=ROOT,
                check=True,
            )
        for path, update in self.ledger.get("reviewed_source_updates", {}).items():
            self.assertEqual(
                git("rev-parse", f"{update['source']}:{path}"), update["blob"]
            )
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", update["source"], "HEAD"],
                cwd=ROOT,
                check=True,
            )

    def test_freshness_checks_the_tree_supplied_by_the_caller(self) -> None:
        path = next(iter(self.ledger["source_blobs"]))
        with tempfile.TemporaryDirectory(prefix="yonik-p11-freshness-") as temporary:
            root = Path(temporary)
            candidate = root / path
            candidate.parent.mkdir(parents=True)
            candidate.write_text("исходный текст")
            binding = {path: git("hash-object", str(candidate))}
            self.assertTrue(fresh(binding, root))
            candidate.write_text("изменённый текст")
            self.assertFalse(fresh(binding, root))

    def test_reviewed_source_update_does_not_rebind_old_execution(self) -> None:
        checked = checked_blobs(self.ledger)
        self.assertNotEqual(checked, self.ledger["source_blobs"])
        self.assertFalse(fresh(self.ledger["source_blobs"]))
        for path in self.ledger["reviewed_source_updates"]:
            damaged = json.loads(json.dumps(self.ledger))
            damaged["reviewed_source_updates"][path]["blob"] = "0" * 40
            self.assertFalse(fresh(checked_blobs(damaged)))
            damaged["reviewed_source_updates"][path]["review"] = ""
            with self.assertRaises(ValueError):
                checked_blobs(damaged)

    def test_original_12_plus_import_startup_exactly_once(self) -> None:
        original = self.ledger["original_inventory"]
        historical = json.loads(
            (ROOT / "docs/validation/p11-acceptance-closure.json").read_text()
        )
        self.assertEqual(original, historical["original_inventory"])
        expected = {r["id"] for r in original["boundaries"] + original["separate"]}
        rows = self.ledger["boundaries"]
        self.assertEqual(len(rows), 14)
        self.assertEqual({r["id"] for r in rows}, expected)
        for row in rows:
            with self.subTest(boundary=row["id"]):
                self.assertIn(row["file"], self.ledger["source_blobs"])
                self.assertTrue(row["publication"])
                self.assertTrue(row["representative_contract"])
                for reason, identity in row["representative_contract"].items():
                    self.assertEqual(CONTEXTS[reason], identity)
        self.assertIs(self.ledger["P11_main_closed"], False)

    def test_all_typed_producer_references_have_final_contract(self) -> None:
        # Дополняет representative rows всеми Cause-ссылками четырёх producers.
        for name in (
            "desktop_schedule",
            "source_failure",
            "maintenance_job",
            "backend_startup",
        ):
            source = (
                (ROOT / f"crates/yonik-desktop/src/{name}.rs")
                .read_text()
                .split("#[cfg(test)]", 1)[0]
            )
            causes = set(re.findall(r"Cause::([A-Za-z0-9_]+)", source))
            self.assertTrue(causes)
            for cause in causes:
                reason = re.sub(r"(?<!^)(?=[A-Z])", "_", cause).lower()
                self.assertIn(reason, CONTEXTS, (name, cause))

    def test_reused_producer_evidence_is_bound_and_not_runtime_claim(self) -> None:
        evidence = self.ledger["producer_evidence"]
        # Локальный полный log не обязателен для CI; source binding проверяется Git.
        if git("rev-parse", "--is-shallow-repository") == "true":
            self.skipTest(
                "Повторное использование Rust evidence требует полной Git history"
            )
        for path in self.ledger["source_blobs"]:
            if path.startswith("crates/yonik-desktop/"):
                self.assertEqual(
                    git("rev-parse", f"{evidence['source']}:{path}"),
                    self.ledger["source_blobs"][path],
                )
        if (
            not (ROOT / evidence["log"]).exists()
            and not (ROOT / evidence["binding"]).exists()
        ):
            self.skipTest("Локальные файлы исторического producer evidence отсутствуют")
        log = producer_log(evidence)
        for test in (
            "fetch_causes_strict_v2_generation_fence",
            "probe_producer_exports_typed_failure_and_rejects_stale_generation",
            "boundaries_preserve_admission_and_replacement_failures",
            "join_failure_keeps_owner_context_and_unconfirmed_drain",
            "thread_start_failure_publishes_closed_context_before_return",
            "manual_source_failure_сохраняет_enum_до_публикации",
            "actual_backup_conflict_is_bound_to_ack_and_v1_is_unchanged",
        ):
            self.assertIn((test + " ... ok").encode(), log)

    def test_missing_local_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="p11-missing-evidence-") as temporary:
            with self.assertRaises(FileNotFoundError):
                producer_log(self.ledger["producer_evidence"], Path(temporary))
