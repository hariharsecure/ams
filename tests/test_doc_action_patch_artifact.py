from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams_codex.doc_action_patch_artifact import DocActionPatchArtifactReceiptStore, _hash_without
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_doc_action_patch_preview import _minimal_repo
from test_doc_action_patch_readback import _readback_fixture


class DocActionPatchArtifactReceiptTest(unittest.TestCase):
    def test_artifact_receipt_writes_external_patch_artifacts_without_source_writes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            artifact_root = Path(td) / "artifacts"
            store = JsonStore(Path(td) / "store.json")
            fixture = _readback_fixture(store, root)
            before_hashes = _source_hashes(root, fixture["patch_preview"])

            receipt = DocActionPatchArtifactReceiptStore(store).create(
                doc_action_patch_readback_receipt_id=fixture["readback_receipt"][
                    "doc_action_patch_readback_receipt_id"
                ],
                source_root=root,
                artifact_root=artifact_root,
                label="test-doc-action-patch-artifact",
            )

            self.assertEqual(receipt["status"], "artifact_ready")
            self.assertTrue(all(receipt["required_gates"].values()))
            self.assertEqual(receipt["artifact_summary"]["artifact_count"], 1)
            self.assertTrue(receipt["artifact_summary"]["patch_artifact_written"])
            self.assertFalse(receipt["artifact_summary"]["raw_patch_stored_in_ams_state"])
            self.assertFalse(receipt["artifact_summary"]["source_files_modified"])
            self.assertTrue(receipt["live_boundaries"]["patch_artifact_written"])
            self.assertFalse(receipt["live_boundaries"]["source_file_rewritten"])
            artifact = receipt["artifacts"][0]
            self.assertTrue(Path(artifact["artifact_path"]).is_file())
            self.assertFalse(artifact["artifact_path_under_source_root"])
            self.assertFalse(artifact["raw_patch_stored_in_ams_state"])
            self.assertEqual(before_hashes, _source_hashes(root, fixture["patch_preview"]))
            self.assertNotIn("secret body", str(receipt))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_artifact_root_inside_source_root_blocks_without_breaking_replay(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _readback_fixture(store, root)

            receipt = DocActionPatchArtifactReceiptStore(store).create(
                doc_action_patch_readback_receipt_id=fixture["readback_receipt"][
                    "doc_action_patch_readback_receipt_id"
                ],
                source_root=root,
                artifact_root=root / ".ams_patch_artifacts",
                label="test-doc-action-patch-artifact-blocked",
            )

            self.assertEqual(receipt["status"], "blocked")
            self.assertFalse(receipt["required_gates"]["artifact_root_outside_source_root"])
            self.assertFalse(receipt["required_gates"]["patch_artifacts_written"])
            self.assertEqual(receipt["artifacts"], [])
            self.assertFalse(receipt["live_boundaries"]["patch_artifact_written"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_artifact_file_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _artifact_fixture(store, root, Path(td) / "artifacts")
            artifact_path = Path(fixture["artifact_receipt"]["artifacts"][0]["artifact_path"])
            artifact_path.write_text("tampered patch\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_artifact.artifact_hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_source_drift_after_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _artifact_fixture(store, root, Path(td) / "artifacts")
            source_path = fixture["artifact_receipt"]["artifacts"][0]["source_path"]
            (root / source_path).write_text("# Changed\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_artifact.source_ref_sha256_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_artifact_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _artifact_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["doc_action_patch_artifact_receipts"][
                fixture["artifact_receipt"]["doc_action_patch_artifact_receipt_id"]
            ]
            record["artifacts"][0]["source_file_rewritten"] = True
            record["doc_action_patch_artifact_receipt_sha256"] = _hash_without(
                record,
                "doc_action_patch_artifact_receipt_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_artifact.artifact_source_file_rewritten_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_doc_action_patch_artifact_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            _artifact_fixture(store, root, Path(td) / "artifacts")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_patch_artifact_receipts", collections)


def _artifact_fixture(store: JsonStore, root: Path, artifact_root: Path) -> dict[str, dict]:
    fixture = _readback_fixture(store, root)
    artifact_receipt = DocActionPatchArtifactReceiptStore(store).create(
        doc_action_patch_readback_receipt_id=fixture["readback_receipt"]["doc_action_patch_readback_receipt_id"],
        source_root=root,
        artifact_root=artifact_root,
        label="test-doc-action-patch-artifact-ready",
    )
    return {**fixture, "artifact_receipt": artifact_receipt}


def _source_hashes(root: Path, patch_preview: dict) -> dict[str, bytes]:
    return {
        preview["source_path"]: (root / preview["source_path"]).read_bytes()
        for preview in patch_preview["patch_previews"]
    }


if __name__ == "__main__":
    unittest.main()
