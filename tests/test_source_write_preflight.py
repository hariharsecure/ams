from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.source_write_preflight import SourceWriteExecutorPreflightStore, _hash_without
from ams.store import JsonStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_doc_action_patch_apply_acceptance import _apply_acceptance_fixture
from test_doc_action_patch_preview import _minimal_repo


class SourceWriteExecutorPreflightTest(unittest.TestCase):
    def test_preflight_consumes_apply_acceptance_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _apply_acceptance_fixture(store, root, Path(td) / "artifacts")

            preflight = SourceWriteExecutorPreflightStore(store).create(
                doc_action_patch_apply_acceptance_packet_id=fixture["apply_acceptance_packet"][
                    "doc_action_patch_apply_acceptance_packet_id"
                ],
                source_root=root,
                label="test-source-write-preflight",
            )

            self.assertEqual(preflight["status"], "ready_for_backup_preimage_capture")
            self.assertTrue(all(preflight["required_gates"].values()))
            self.assertEqual(preflight["source_path"], "STATUS.md")
            self.assertFalse(preflight["architecture_gate_proof"]["required"])
            self.assertFalse(preflight["blast_radius_proof"]["required"])
            self.assertTrue(preflight["preimage_requirements"]["source_hash_matches_acceptance"])
            self.assertTrue(preflight["preimage_requirements"]["backup_required_before_write"])
            self.assertFalse(preflight["preimage_requirements"]["backup_written"])
            self.assertTrue(preflight["preimage_requirements"]["post_write_replay_required"])
            self.assertFalse(preflight["source_file_write_allowed"])
            self.assertFalse(preflight["source_backup_write_allowed"])
            self.assertEqual(preflight["backup_actions"], [])
            self.assertEqual(preflight["source_write_actions"], [])
            self.assertEqual(preflight["post_write_replay_actions"], [])
            self.assertEqual(len(preflight["preflight_actions"]), 1)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_source_drift_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _source_write_preflight_fixture(store, root, Path(td) / "artifacts")
            source_path = fixture["source_write_preflight"]["source_path"]
            (root / source_path).write_text("# Changed\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("source_write_executor_preflight.preimage_requirements_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_write_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _source_write_preflight_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["source_write_executor_preflights"][
                fixture["source_write_preflight"]["source_write_executor_preflight_id"]
            ]
            record["source_file_write_allowed"] = True
            record["source_write_executor_preflight_sha256"] = _hash_without(
                record,
                "source_write_executor_preflight_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("source_write_executor_preflight.source_file_write_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_source_write_preflights(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            _source_write_preflight_fixture(store, root, Path(td) / "artifacts")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("source_write_executor_preflights", collections)


def _source_write_preflight_fixture(store: JsonStore, root: Path, artifact_root: Path) -> dict[str, dict]:
    fixture = _apply_acceptance_fixture(store, root, artifact_root)
    preflight = SourceWriteExecutorPreflightStore(store).create(
        doc_action_patch_apply_acceptance_packet_id=fixture["apply_acceptance_packet"][
            "doc_action_patch_apply_acceptance_packet_id"
        ],
        source_root=root,
        label="test-source-write-preflight",
    )
    return {**fixture, "source_write_preflight": preflight}


if __name__ == "__main__":
    unittest.main()
