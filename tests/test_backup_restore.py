from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.backup_restore import StoreBackupDrillStore
from ams_codex.store import JsonStore, empty_state
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle


class BackupRestoreDrillTest(unittest.TestCase):
    def test_backup_restore_drill_passes_for_clean_store(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            store.save(empty_state(), check_revision=False)

            drill = StoreBackupDrillStore(store).create(
                backup_path=root / "backup.json",
                restore_path=root / "restore.json",
                label="clean-drill",
            )

            self.assertEqual(drill["status"], "passed")
            self.assertTrue(drill["source_replay_ok"])
            self.assertTrue(drill["backup_replay_ok"])
            self.assertTrue(drill["restore_replay_ok"])
            self.assertEqual(drill["source_state_sha256"], drill["backup_state_sha256"])
            self.assertEqual(drill["backup_state_sha256"], drill["restore_state_sha256"])
            self.assertTrue((root / "backup.json").exists())
            self.assertTrue((root / "restore.json").exists())
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_backup_restore_drill_records_replay_failure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            state = empty_state()
            state["indexes"]["rag_index_plan_ids"] = {"missing": "missing"}
            store.save(state, check_revision=False, validate=False)

            drill = StoreBackupDrillStore(store).create(
                backup_path=root / "backup.json",
                restore_path=root / "restore.json",
                label="failing-drill",
            )

            self.assertEqual(drill["status"], "failed")
            self.assertFalse(drill["source_replay_ok"])
            self.assertFalse(drill["backup_replay_ok"])
            self.assertFalse(drill["restore_replay_ok"])
            self.assertIn("store_backup_drill.source_replay_failed", drill["reason_codes"])

    def test_replay_catches_backup_drill_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            store.save(empty_state(), check_revision=False)
            drill = StoreBackupDrillStore(store).create(
                backup_path=root / "backup.json",
                restore_path=root / "restore.json",
                label="tamper-drill",
            )
            state = store.load()
            state["store_backup_drills"][drill["store_backup_drill_id"]]["status"] = "failed"
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("store_backup_drill.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_backup_drills(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            store.save(empty_state(), check_revision=False)
            StoreBackupDrillStore(store).create(
                backup_path=root / "backup.json",
                restore_path=root / "restore.json",
                label="oracle-drill",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("store_backup_drills", collections)


if __name__ == "__main__":
    unittest.main()
