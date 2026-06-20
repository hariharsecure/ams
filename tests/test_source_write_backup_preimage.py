from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.source_write_backup_preimage import (
    SourceWriteBackupPreimageReceiptStore,
    _hash_without,
)
from ams_codex.store import JsonStore
from ams_codex.workspace import path_is_under

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_source_write_preflight import _source_write_preflight_fixture
from test_doc_action_patch_preview import _minimal_repo


class SourceWriteBackupPreimageReceiptTest(unittest.TestCase):
    def test_backup_preimage_receipt_writes_external_backup_without_source_write(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _source_write_preflight_fixture(store, root, Path(td) / "artifacts")
            backup_root = Path(td) / "source-backups"

            receipt = SourceWriteBackupPreimageReceiptStore(store).create(
                source_write_executor_preflight_id=fixture["source_write_preflight"][
                    "source_write_executor_preflight_id"
                ],
                source_root=root,
                backup_root=backup_root,
                label="test-source-write-backup-preimage",
            )

            backup_path = Path(receipt["backup_artifact"]["backup_path"])
            source_path = root / receipt["source_path"]
            self.assertEqual(receipt["status"], "backup_preimage_captured")
            self.assertTrue(all(receipt["required_gates"].values()))
            self.assertTrue(backup_path.is_file())
            self.assertTrue(path_is_under(backup_path, backup_root.resolve(strict=False)))
            self.assertFalse(path_is_under(backup_path, root.resolve(strict=False)))
            self.assertEqual(receipt["backup_artifact"]["backup_sha256"], receipt["captured_source_ref"]["sha256"])
            self.assertEqual(backup_path.read_bytes(), source_path.read_bytes())
            self.assertTrue(receipt["source_backup_write_allowed"])
            self.assertFalse(receipt["source_file_write_allowed"])
            self.assertEqual(receipt["source_write_actions"], [])
            self.assertEqual(receipt["rollback_actions"], [])
            self.assertEqual(receipt["post_write_replay_actions"], [])
            self.assertFalse(receipt["backup_artifact"]["raw_source_stored_in_ams_state"])
            self.assertNotIn("generated historical line 42", str(receipt))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_backup_root_under_source_root_blocks_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _source_write_preflight_fixture(store, root, Path(td) / "artifacts")
            backup_root = root / ".ams-source-backups"

            receipt = SourceWriteBackupPreimageReceiptStore(store).create(
                source_write_executor_preflight_id=fixture["source_write_preflight"][
                    "source_write_executor_preflight_id"
                ],
                source_root=root,
                backup_root=backup_root,
                label="test-source-write-backup-preimage",
            )

            self.assertEqual(receipt["status"], "blocked")
            self.assertIn(
                "source_write_backup_preimage.gate_failed:backup_root_outside_source_root",
                receipt["reason_codes"],
            )
            self.assertEqual(receipt["backup_artifact"]["backup_path"], "")
            self.assertFalse(backup_root.exists())
            self.assertFalse(receipt["source_backup_write_allowed"])
            self.assertFalse(receipt["live_boundaries"]["source_backup_written"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_source_drift_after_backup_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _source_write_backup_preimage_fixture(store, root, Path(td) / "artifacts", Path(td) / "backups")
            source_path = fixture["source_write_backup_preimage"]["source_path"]
            (root / source_path).write_text("# Changed after backup\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("source_write_backup_preimage.captured_source_ref_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_backup_artifact_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _source_write_backup_preimage_fixture(store, root, Path(td) / "artifacts", Path(td) / "backups")
            backup_path = Path(fixture["source_write_backup_preimage"]["backup_artifact"]["backup_path"])
            backup_path.write_text("tampered backup\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("source_write_backup_preimage.backup_artifact_hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_rehashed_source_write_authority_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _source_write_backup_preimage_fixture(store, root, Path(td) / "artifacts", Path(td) / "backups")
            state = store.load()
            record = state["source_write_backup_preimage_receipts"][
                fixture["source_write_backup_preimage"]["source_write_backup_preimage_receipt_id"]
            ]
            record["source_file_write_allowed"] = True
            record["source_write_backup_preimage_receipt_sha256"] = _hash_without(
                record,
                "source_write_backup_preimage_receipt_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("source_write_backup_preimage.source_file_write_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_source_write_backup_preimage_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            _source_write_backup_preimage_fixture(store, root, Path(td) / "artifacts", Path(td) / "backups")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("source_write_backup_preimage_receipts", collections)


def _source_write_backup_preimage_fixture(
    store: JsonStore,
    root: Path,
    artifact_root: Path,
    backup_root: Path,
) -> dict[str, dict]:
    fixture = _source_write_preflight_fixture(store, root, artifact_root)
    receipt = SourceWriteBackupPreimageReceiptStore(store).create(
        source_write_executor_preflight_id=fixture["source_write_preflight"][
            "source_write_executor_preflight_id"
        ],
        source_root=root,
        backup_root=backup_root,
        label="test-source-write-backup-preimage",
    )
    return {**fixture, "source_write_backup_preimage": receipt}


if __name__ == "__main__":
    unittest.main()
