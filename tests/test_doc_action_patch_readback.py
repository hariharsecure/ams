from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams_codex.doc_action_patch_preview import _hash_without as _preview_hash_without
from ams_codex.doc_action_patch_readback import (
    REQUIRED_READBACK_PHRASES,
    DocActionPatchReadbackReceiptStore,
    _hash_without,
)
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_doc_action_patch_preview import _minimal_repo, _patch_fixture


VALID_READBACK = (
    "I reviewed the doc action patch preview. "
    "Literal patches remain disabled. "
    "Source doc writes remain disabled. "
    "Source doc moves remain disabled. "
    "Source doc archives remain disabled. "
    "Generated surface rewrites remain disabled. "
    "A later explicit approval is required."
)


class DocActionPatchReadbackReceiptTest(unittest.TestCase):
    def test_readback_receipt_verifies_preview_but_grants_no_authority(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _readback_fixture(store, root)

            receipt = fixture["readback_receipt"]

            self.assertEqual(receipt["status"], "readback_verified")
            self.assertTrue(all(receipt["required_gates"].values()))
            self.assertEqual(receipt["required_readback_phrases"], REQUIRED_READBACK_PHRASES)
            self.assertFalse(receipt["readback"]["raw_readback_stored"])
            self.assertTrue(receipt["readback"]["required_phrases_present"])
            self.assertFalse(receipt["approval_granted"])
            self.assertFalse(receipt["live_execution_allowed"])
            self.assertFalse(receipt["source_file_write_allowed"])
            self.assertFalse(receipt["source_file_move_allowed"])
            self.assertFalse(receipt["source_file_delete_allowed"])
            self.assertFalse(receipt["archive_create_allowed"])
            self.assertFalse(receipt["generated_surface_rewrite_allowed"])
            self.assertFalse(receipt["literal_patch_store_allowed"])
            self.assertFalse(receipt["preview_artifact_write_allowed"])
            self.assertEqual(receipt["approval_actions"], [])
            self.assertEqual(receipt["execution_actions"], [])
            self.assertEqual(receipt["patch_actions"], [])
            self.assertNotIn(VALID_READBACK, str(receipt))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_missing_phrase_blocks_receipt_without_breaking_replay(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _patch_fixture(store, root)

            receipt = DocActionPatchReadbackReceiptStore(store).create(
                doc_action_patch_preview_id=fixture["patch_preview"]["doc_action_patch_preview_id"],
                readback_ref="local://tests/doc-action-patch-readback-missing",
                readback_text="I reviewed the doc action patch preview. Literal patches remain disabled.",
                requested_by="test-operator",
                source_root=root,
                label="test-doc-action-patch-readback-blocked",
            )

            self.assertEqual(receipt["status"], "blocked")
            self.assertFalse(receipt["required_gates"]["required_phrases_present"])
            self.assertIn("doc_action_patch_readback.gate_failed:required_phrases_present", receipt["reason_codes"])
            self.assertTrue(receipt["readback"]["missing_required_phrases"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_receipt_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _readback_fixture(store, root)
            state = store.load()
            record = state["doc_action_patch_readback_receipts"][
                fixture["readback_receipt"]["doc_action_patch_readback_receipt_id"]
            ]
            record["source_file_write_allowed"] = True
            record["doc_action_patch_readback_receipt_sha256"] = _hash_without(
                record,
                "doc_action_patch_readback_receipt_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_readback.source_file_write_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_stale_patch_preview_after_readback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _readback_fixture(store, root)
            state = store.load()
            preview_id = fixture["patch_preview"]["doc_action_patch_preview_id"]
            preview = state["doc_action_patch_previews"][preview_id]
            preview["policy"]["source_file_write_allowed"] = True
            preview["doc_action_patch_preview_sha256"] = _preview_hash_without(
                preview,
                "doc_action_patch_preview_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            joined = "\n".join(replay["errors"])
            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_readback", joined)
            self.assertIn("patch preview hash mismatch", joined)
            self.assertIn("doc_action_patch_preview.policy_source_file_write_allowed_not_false", joined)

    def test_replay_catches_phrase_evidence_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            fixture = _readback_fixture(store, root)
            state = store.load()
            record = state["doc_action_patch_readback_receipts"][
                fixture["readback_receipt"]["doc_action_patch_readback_receipt_id"]
            ]
            record["readback"]["phrase_results"][0]["evidence_sha256"] = "sha256:" + ("0" * 64)
            record["doc_action_patch_readback_receipt_sha256"] = _hash_without(
                record,
                "doc_action_patch_readback_receipt_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_readback.phrase_evidence_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_doc_action_patch_readback_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td), oversized_status=True)
            store = JsonStore(root / "store.json")
            _readback_fixture(store, root)

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_patch_readback_receipts", collections)


def _readback_fixture(store: JsonStore, root: Path) -> dict[str, dict]:
    fixture = _patch_fixture(store, root)
    readback_receipt = DocActionPatchReadbackReceiptStore(store).create(
        doc_action_patch_preview_id=fixture["patch_preview"]["doc_action_patch_preview_id"],
        readback_ref="local://tests/doc-action-patch-readback-ready",
        readback_text=VALID_READBACK,
        requested_by="test-operator",
        source_root=root,
        label="test-doc-action-patch-readback-ready",
    )
    return {**fixture, "readback_receipt": readback_receipt}


if __name__ == "__main__":
    unittest.main()
