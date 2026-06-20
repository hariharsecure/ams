from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams_codex.doc_action_patch_dry_run import _hash_without as _dry_run_hash_without
from ams_codex.doc_action_patch_dry_run_readback import (
    REQUIRED_READBACK_PHRASES,
    DocActionPatchDryRunReadbackReceiptStore,
    _hash_without,
)
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_doc_action_patch_dry_run import _dry_run_fixture
from test_doc_action_patch_preview import _minimal_repo


VALID_READBACK = (
    "I reviewed the doc patch dry run. "
    "Artifact hash matches the dry run plan. "
    "Source hash matches the dry run plan. "
    "Source doc writes remain disabled. "
    "Source doc moves remain disabled. "
    "Source doc archives remain disabled. "
    "Generated surface rewrites remain disabled. "
    "A later live execution approval is required."
)


class DocActionPatchDryRunReadbackReceiptTest(unittest.TestCase):
    def test_readback_receipt_verifies_dry_run_without_approval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _readback_fixture(store, root, Path(td) / "artifacts")
            receipt = fixture["dry_run_readback_receipt"]

            self.assertEqual(receipt["status"], "readback_verified")
            self.assertTrue(all(receipt["required_gates"].values()))
            self.assertEqual(receipt["required_readback_phrases"], REQUIRED_READBACK_PHRASES)
            self.assertTrue(receipt["readback"]["required_phrases_present"])
            self.assertFalse(receipt["readback"]["raw_readback_stored"])
            self.assertFalse(receipt["approval_granted"])
            self.assertFalse(receipt["live_execution_allowed"])
            self.assertFalse(receipt["source_file_write_allowed"])
            self.assertFalse(receipt["patch_artifact_write_allowed"])
            self.assertEqual(receipt["source_write_actions"], [])
            self.assertNotIn(VALID_READBACK, str(receipt))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_missing_phrase_blocks_receipt_without_breaking_replay(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _dry_run_fixture(store, root, Path(td) / "artifacts")

            receipt = DocActionPatchDryRunReadbackReceiptStore(store).create(
                doc_action_patch_dry_run_plan_id=fixture["dry_run_plan"]["doc_action_patch_dry_run_plan_id"],
                readback_ref="local://tests/doc-action-patch-dry-run-readback-missing",
                readback_text="I reviewed the doc patch dry run.",
                requested_by="test-operator",
                label="test-doc-action-patch-dry-run-readback-blocked",
            )

            self.assertEqual(receipt["status"], "blocked")
            self.assertFalse(receipt["required_gates"]["required_phrases_present"])
            self.assertTrue(receipt["readback"]["missing_required_phrases"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_readback_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _readback_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["doc_action_patch_dry_run_readback_receipts"][
                fixture["dry_run_readback_receipt"]["doc_action_patch_dry_run_readback_receipt_id"]
            ]
            record["source_file_write_allowed"] = True
            record["doc_action_patch_dry_run_readback_receipt_sha256"] = _hash_without(
                record,
                "doc_action_patch_dry_run_readback_receipt_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_dry_run_readback.source_file_write_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_stale_dry_run_plan_after_readback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _readback_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            plan = state["doc_action_patch_dry_run_plans"][fixture["dry_run_plan"]["doc_action_patch_dry_run_plan_id"]]
            plan["label"] = "tampered-dry-run-plan"
            plan["doc_action_patch_dry_run_plan_sha256"] = _dry_run_hash_without(
                plan,
                "doc_action_patch_dry_run_plan_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_dry_run_readback.dry_run_plan_hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_phrase_evidence_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _readback_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["doc_action_patch_dry_run_readback_receipts"][
                fixture["dry_run_readback_receipt"]["doc_action_patch_dry_run_readback_receipt_id"]
            ]
            record["readback"]["phrase_results"][0]["evidence_sha256"] = "sha256:" + ("0" * 64)
            record["doc_action_patch_dry_run_readback_receipt_sha256"] = _hash_without(
                record,
                "doc_action_patch_dry_run_readback_receipt_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_dry_run_readback.phrase_evidence_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_doc_action_patch_dry_run_readback_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            _readback_fixture(store, root, Path(td) / "artifacts")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_patch_dry_run_readback_receipts", collections)


def _readback_fixture(store: JsonStore, root: Path, artifact_root: Path) -> dict[str, dict]:
    fixture = _dry_run_fixture(store, root, artifact_root)
    dry_run_readback_receipt = DocActionPatchDryRunReadbackReceiptStore(store).create(
        doc_action_patch_dry_run_plan_id=fixture["dry_run_plan"]["doc_action_patch_dry_run_plan_id"],
        readback_ref="local://tests/doc-action-patch-dry-run-readback-ready",
        readback_text=VALID_READBACK,
        requested_by="test-operator",
        label="test-doc-action-patch-dry-run-readback-ready",
    )
    return {**fixture, "dry_run_readback_receipt": dry_run_readback_receipt}


if __name__ == "__main__":
    unittest.main()
