from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams_codex.doc_action_patch_artifact_approval import _hash_without as _approval_hash_without
from ams_codex.doc_action_patch_dry_run import DocActionPatchDryRunPlanStore, _hash_without
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_doc_action_patch_artifact_approval import _approval_fixture
from test_doc_action_patch_preview import _minimal_repo


class DocActionPatchDryRunPlanTest(unittest.TestCase):
    def test_dry_run_plan_consumes_approval_packet_without_source_writes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _dry_run_fixture(store, root, Path(td) / "artifacts")
            plan = fixture["dry_run_plan"]
            action = plan["dry_run_actions"][0]

            self.assertEqual(plan["status"], "dry_run_ready")
            self.assertTrue(all(plan["required_gates"].values()))
            self.assertEqual(action["action_id"], fixture["approval_packet"]["selected_artifact"]["action_id"])
            self.assertTrue(action["artifact_hash_verified"])
            self.assertTrue(action["source_hash_matches_approval_packet"])
            self.assertGreaterEqual(action["patch_hunk_count"], 1)
            self.assertTrue(action["patch_nonempty"])
            self.assertTrue(plan["dry_run_summary"]["dry_run_only"])
            self.assertFalse(plan["dry_run_summary"]["raw_patch_stored_in_ams_state"])
            self.assertFalse(plan["approval_granted"])
            self.assertFalse(plan["live_execution_allowed"])
            self.assertFalse(plan["source_file_write_allowed"])
            self.assertFalse(plan["live_boundaries"]["source_file_rewritten"])
            self.assertFalse(plan["live_boundaries"]["patch_artifact_written"])
            self.assertEqual(plan["source_write_actions"], [])
            self.assertNotIn("secret body", str(plan))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_create_defaults_to_approval_packet_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _approval_fixture(store, root, Path(td) / "artifacts")

            plan = DocActionPatchDryRunPlanStore(store).create(
                doc_action_patch_artifact_approval_packet_id=fixture["approval_packet"][
                    "doc_action_patch_artifact_approval_packet_id"
                ],
                label="test-doc-action-patch-dry-run-default-root",
            )

            self.assertEqual(plan["source_root"], str(root.resolve(strict=False)))
            self.assertEqual(plan["status"], "dry_run_ready")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_artifact_tamper_after_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _dry_run_fixture(store, root, Path(td) / "artifacts")
            artifact_path = Path(fixture["dry_run_plan"]["dry_run_actions"][0]["artifact_path"])
            artifact_path.write_text("tampered patch\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_dry_run.artifact_hash_verified_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_source_drift_after_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _dry_run_fixture(store, root, Path(td) / "artifacts")
            source_path = fixture["dry_run_plan"]["dry_run_actions"][0]["source_path"]
            (root / source_path).write_text("# Changed\n", encoding="utf-8")

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_dry_run.source_ref_sha256_mismatch", "\n".join(replay["errors"]))

    def test_replay_catches_dry_run_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _dry_run_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            record = state["doc_action_patch_dry_run_plans"][
                fixture["dry_run_plan"]["doc_action_patch_dry_run_plan_id"]
            ]
            record["source_file_write_allowed"] = True
            record["doc_action_patch_dry_run_plan_sha256"] = _hash_without(
                record,
                "doc_action_patch_dry_run_plan_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_dry_run.source_file_write_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_stale_approval_after_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            fixture = _dry_run_fixture(store, root, Path(td) / "artifacts")
            state = store.load()
            approval = state["doc_action_patch_artifact_approval_packets"][
                fixture["approval_packet"]["doc_action_patch_artifact_approval_packet_id"]
            ]
            approval["label"] = "tampered-approval-packet"
            approval["doc_action_patch_artifact_approval_packet_sha256"] = _approval_hash_without(
                approval,
                "doc_action_patch_artifact_approval_packet_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("doc_action_patch_dry_run.approval_packet_hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_doc_action_patch_dry_run_plans(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td) / "repo", oversized_status=True)
            store = JsonStore(Path(td) / "store.json")
            _dry_run_fixture(store, root, Path(td) / "artifacts")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("doc_action_patch_dry_run_plans", collections)


def _dry_run_fixture(store: JsonStore, root: Path, artifact_root: Path) -> dict[str, dict]:
    fixture = _approval_fixture(store, root, artifact_root)
    dry_run_plan = DocActionPatchDryRunPlanStore(store).create(
        doc_action_patch_artifact_approval_packet_id=fixture["approval_packet"][
            "doc_action_patch_artifact_approval_packet_id"
        ],
        source_root=root,
        label="test-doc-action-patch-dry-run",
    )
    return {**fixture, "dry_run_plan": dry_run_plan}


if __name__ == "__main__":
    unittest.main()
