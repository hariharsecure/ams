from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.source_write_executor_lease import SourceWriteExecutorLeaseStore, _hash_without
from ams_codex.store import JsonStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_doc_action_patch_preview import _minimal_repo
from test_source_write_backup_preimage import _source_write_backup_preimage_fixture


class SourceWriteExecutorLeaseTest(unittest.TestCase):
    def test_lease_consumes_backup_preimage_without_source_write(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _source_write_backup_preimage_fixture(store, root, Path(td) / "artifacts", Path(td) / "backups")

            lease = SourceWriteExecutorLeaseStore(store).create(
                source_write_backup_preimage_receipt_id=fixture["source_write_backup_preimage"][
                    "source_write_backup_preimage_receipt_id"
                ],
                source_root=root,
                label="test-source-write-lease",
            )

            self.assertEqual(lease["status"], "ready_for_source_write_receipt")
            self.assertTrue(lease["lease_active"])
            self.assertTrue(all(lease["required_gates"].values()))
            self.assertEqual(lease["source_path"], "STATUS.md")
            self.assertTrue(lease["lease_scope"]["exclusive"])
            self.assertEqual(lease["lease_scope"]["overlapping_active_lease_ids"], [])
            self.assertFalse(lease["source_file_write_allowed"])
            self.assertFalse(lease["source_backup_write_allowed"])
            self.assertEqual(lease["source_write_actions"], [])
            self.assertEqual(lease["rollback_actions"], [])
            self.assertEqual(lease["post_write_replay_actions"], [])
            self.assertEqual(len(lease["lease_actions"]), 1)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_second_active_scope_blocks_without_breaking_first_lease(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _source_write_backup_preimage_fixture(store, root, Path(td) / "artifacts", Path(td) / "backups")
            receipt_id = fixture["source_write_backup_preimage"]["source_write_backup_preimage_receipt_id"]
            first = SourceWriteExecutorLeaseStore(store).create(
                source_write_backup_preimage_receipt_id=receipt_id,
                source_root=root,
                label="test-source-write-lease",
            )

            second = SourceWriteExecutorLeaseStore(store).create(
                source_write_backup_preimage_receipt_id=receipt_id,
                source_root=root,
                label="test-source-write-lease-second",
            )

            self.assertEqual(first["status"], "ready_for_source_write_receipt")
            self.assertEqual(second["status"], "blocked")
            self.assertFalse(second["lease_active"])
            self.assertIn(first["source_write_executor_lease_id"], second["lease_scope"]["overlapping_active_lease_ids"])
            self.assertIn("source_write_executor_lease.gate_failed:exclusive_scope_clear", second["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_source_drift_after_lease(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _source_write_executor_lease_fixture(store, root, Path(td) / "artifacts", Path(td) / "backups")
            (root / fixture["source_write_lease"]["source_path"]).write_text("# Changed after lease\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("source_write_executor_lease.current_source_ref_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_rehashed_source_write_authority_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _source_write_executor_lease_fixture(store, root, Path(td) / "artifacts", Path(td) / "backups")
            state = store.load()
            record = state["source_write_executor_leases"][
                fixture["source_write_lease"]["source_write_executor_lease_id"]
            ]
            record["source_file_write_allowed"] = True
            record["source_write_executor_lease_sha256"] = _hash_without(
                record,
                "source_write_executor_lease_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("source_write_executor_lease.source_file_write_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_source_write_executor_leases(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            _source_write_executor_lease_fixture(store, root, Path(td) / "artifacts", Path(td) / "backups")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("source_write_executor_leases", collections)


def _source_write_executor_lease_fixture(
    store: JsonStore,
    root: Path,
    artifact_root: Path,
    backup_root: Path,
) -> dict[str, dict]:
    fixture = _source_write_backup_preimage_fixture(store, root, artifact_root, backup_root)
    lease = SourceWriteExecutorLeaseStore(store).create(
        source_write_backup_preimage_receipt_id=fixture["source_write_backup_preimage"][
            "source_write_backup_preimage_receipt_id"
        ],
        source_root=root,
        label="test-source-write-lease",
    )
    return {**fixture, "source_write_lease": lease}


if __name__ == "__main__":
    unittest.main()
