from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.semantic_hook_approval import _hash_without
from ams_codex.semantic_hook_target_snapshot import SemanticHookTargetSnapshotStore

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_semantic_hook_approval import SSH_KEYGEN, _approval_fixture, _create_ready_binding


@unittest.skipUnless(SSH_KEYGEN, "ssh-keygen required for semantic hook target snapshot tests")
class SemanticHookTargetSnapshotTest(unittest.TestCase):
    def test_ready_target_snapshot_is_hash_only_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)

            snapshot = SemanticHookTargetSnapshotStore(fixture["store"]).create(
                semantic_hook_approval_binding_id=fixture["binding"]["semantic_hook_approval_binding_id"],
                source_root=Path.cwd(),
                home_root=fixture["home_root"],
                label="test-semantic-hook-target-snapshot",
            )

            self.assertEqual(snapshot["status"], "ready_for_operator_review")
            self.assertEqual(snapshot["target_count"], 3)
            self.assertTrue(all(snapshot["required_gates"].values()))
            self.assertFalse(snapshot["approval_granted"])
            self.assertFalse(snapshot["live_install_allowed"])
            self.assertFalse(snapshot["hook_file_write_allowed"])
            self.assertFalse(snapshot["backup_write_allowed"])
            self.assertFalse(snapshot["restore_allowed"])
            self.assertTrue(all(target["raw_content_stored"] is False for target in snapshot["target_snapshots"]))
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_symlink_target_blocks_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            hooks_dir = fixture["home_root"] / ".codex"
            hooks_dir.mkdir(parents=True)
            target = root / "actual-hooks.json"
            target.write_text("{}", encoding="utf-8")
            (hooks_dir / "hooks.json").symlink_to(target)

            snapshot = SemanticHookTargetSnapshotStore(fixture["store"]).create(
                semantic_hook_approval_binding_id=fixture["binding"]["semantic_hook_approval_binding_id"],
                source_root=Path.cwd(),
                home_root=fixture["home_root"],
                label="test-semantic-hook-target-symlink",
            )

            self.assertEqual(snapshot["status"], "blocked")
            self.assertFalse(snapshot["required_gates"]["no_symlinks"])
            self.assertIn("semantic_hook_target_snapshot.no_symlinks_missing", snapshot["reason_codes"])
            self.assertTrue(any(reason.startswith("semantic_hook_target_snapshot.symlink_target:") for reason in snapshot["reason_codes"]))
            self.assertTrue(ReplayChecker(fixture["store"]).check()["ok"])

    def test_replay_catches_snapshot_authority_tamper_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            snapshot = _create_ready_snapshot(fixture)
            state = fixture["store"].load()
            record = state["semantic_hook_target_snapshots"][snapshot["semantic_hook_target_snapshot_id"]]
            record["hook_file_write_allowed"] = True
            record["semantic_hook_target_snapshot_sha256"] = _hash_without(
                record,
                "semantic_hook_target_snapshot_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn("semantic_hook_target_snapshot.hook_file_write_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_catches_stale_approval_binding_after_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            _create_ready_snapshot(fixture)
            state = fixture["store"].load()
            binding = state["semantic_hook_approval_bindings"][fixture["binding"]["semantic_hook_approval_binding_id"]]
            binding["live_install_allowed"] = True
            binding["semantic_hook_approval_binding_sha256"] = _hash_without(
                binding,
                "semantic_hook_approval_binding_sha256",
            )
            fixture["store"].save(state, validate=False)

            replay = ReplayChecker(fixture["store"]).check()

            self.assertFalse(replay["ok"])
            self.assertIn("semantic_hook_target_snapshot.approval_binding_hash_mismatch", "\n".join(replay["errors"]))
            self.assertIn("semantic_hook_target_snapshot.required_gates_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_semantic_hook_target_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = _fixture_with_binding(root)
            _create_ready_snapshot(fixture)

            result = ReplayOracle(fixture["store"]).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("semantic_hook_target_snapshots", collections)


def _fixture_with_binding(root: Path) -> dict[str, object]:
    fixture = _approval_fixture(root)
    fixture["binding"] = _create_ready_binding(fixture)
    fixture["home_root"] = root / "home"
    fixture["home_root"].mkdir()
    return fixture


def _create_ready_snapshot(fixture: dict[str, object]) -> dict[str, object]:
    return SemanticHookTargetSnapshotStore(fixture["store"]).create(
        semantic_hook_approval_binding_id=fixture["binding"]["semantic_hook_approval_binding_id"],
        source_root=Path.cwd(),
        home_root=fixture["home_root"],
        label="test-semantic-hook-target-ready",
    )


if __name__ == "__main__":
    unittest.main()
