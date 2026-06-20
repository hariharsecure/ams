from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ams.cli import cmd_generated_status_snapshot
from ams.generated_artifact import hash_without
from ams.generated_status import GeneratedStatusSnapshotStore, build_generated_status_snapshot
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.session_start_brief import SessionStartBriefStore
from ams.store import JsonStore


class GeneratedStatusSnapshotTest(unittest.TestCase):
    def test_generated_status_writes_compact_file_without_raw_source_body(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")

            snapshot = GeneratedStatusSnapshotStore(store).create(
                source_root=root,
                output_path="GENERATED_STATUS.md",
                label="test-generated-status",
            )

            output = root / "GENERATED_STATUS.md"
            self.assertTrue(output.exists())
            self.assertEqual(snapshot["status"], "allow")
            self.assertTrue(snapshot["write_result"]["created_new_file"])
            self.assertLessEqual(snapshot["rendered"]["line_count"], snapshot["line_budget"])
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("AMS Generated Status", rendered)
            self.assertNotIn("secret body", rendered)
            serialized = str(snapshot)
            self.assertNotIn("secret body", serialized)
            self.assertFalse(snapshot["dangerous_boundaries"]["source_file_rewritten"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_generated_status_defers_overwrite_without_approval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            (root / "GENERATED_STATUS.md").write_text("# stale\n", encoding="utf-8")
            store = JsonStore(root / "store.json")

            snapshot = GeneratedStatusSnapshotStore(store).create(
                source_root=root,
                output_path="GENERATED_STATUS.md",
                label="test-generated-status",
            )

            self.assertEqual(snapshot["status"], "defer")
            self.assertIn("generated_status_snapshot.overwrite_requires_approval", snapshot["reason_codes"])
            self.assertFalse(snapshot["write_result"]["write_performed"])
            self.assertEqual((root / "GENERATED_STATUS.md").read_text(encoding="utf-8"), "# stale\n")

    def test_existing_matching_output_is_not_rewritten_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            first = build_generated_status_snapshot(
                source_root=root,
                label="test-generated-status",
                now="2026-06-12T00:00:00Z",
            )

            second = build_generated_status_snapshot(
                source_root=root,
                label="test-generated-status",
                now="2026-06-13T00:00:00Z",
            )

            self.assertEqual(first["rendered"]["sha256"], second["rendered"]["sha256"])
            self.assertEqual(second["status"], "allow")
            self.assertFalse(second["write_result"]["write_performed"])
            self.assertTrue(second["write_result"]["output_already_current"])
            self.assertFalse(second["write_result"]["rewrote_existing_generated_file"])
            rendered = (root / "GENERATED_STATUS.md").read_text(encoding="utf-8")
            self.assertIn("Source snapshot:", rendered)
            self.assertNotIn("Updated: 2026-06", rendered)

    def test_generated_status_and_session_start_do_not_rewrite_each_other(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")

            GeneratedStatusSnapshotStore(store).create(
                source_root=root,
                label="test-generated-status",
                allow_overwrite=True,
            )
            SessionStartBriefStore(store).create(
                source_root=root,
                label="test-start-brief",
                allow_overwrite=True,
            )
            status_second = GeneratedStatusSnapshotStore(store).create(
                source_root=root,
                label="test-generated-status-second",
            )
            start_second = SessionStartBriefStore(store).create(
                source_root=root,
                label="test-start-brief-second",
            )

            self.assertEqual(status_second["status"], "allow")
            self.assertTrue(status_second["write_result"]["output_already_current"])
            self.assertFalse(status_second["write_result"]["write_performed"])
            self.assertEqual(start_second["status"], "allow")
            self.assertTrue(start_second["write_result"]["output_already_current"])
            self.assertFalse(start_second["write_result"]["write_performed"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_generated_status_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")
            snapshot = GeneratedStatusSnapshotStore(store).create(source_root=root, label="test-generated-status")
            state = store.load()
            state["generated_status_snapshots"][snapshot["generated_status_snapshot_id"]]["rendered"]["line_count"] = 999
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("generated_status_snapshot.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_reports_malformed_numeric_field_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")
            snapshot = GeneratedStatusSnapshotStore(store).create(source_root=root, label="test-generated-status")
            state = store.load()
            state["generated_status_snapshots"][snapshot["generated_status_snapshot_id"]]["rendered"]["line_count"] = "bad"
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("generated_status_snapshot.schema_invalid", "\n".join(replay["errors"]))

    def test_replay_rejects_rehashed_source_rewrite_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")
            snapshot = GeneratedStatusSnapshotStore(store).create(source_root=root, label="test-generated-status")
            state = store.load()
            record = state["generated_status_snapshots"][snapshot["generated_status_snapshot_id"]]
            record["dangerous_boundaries"]["source_file_rewritten"] = True
            record["generated_status_snapshot_sha256"] = hash_without(record, "generated_status_snapshot_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("generated_status_snapshot.source_file_rewritten_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_generated_status_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")
            GeneratedStatusSnapshotStore(store).create(source_root=root, label="test-generated-status")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("generated_status_snapshots", collections)

    def test_cli_writes_generated_status_and_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            args = SimpleNamespace(
                store=str(root / "store.json"),
                source_root=str(root),
                output_path="GENERATED_STATUS.md",
                label="test-generated-status",
                include_local_session_metadata=False,
                session_window_days=92,
                no_write_file=False,
                allow_overwrite=False,
            )

            self.assertEqual(cmd_generated_status_snapshot(args), 0)
            self.assertTrue((root / "GENERATED_STATUS.md").exists())


def _minimal_repo(root: Path) -> Path:
    root.mkdir(exist_ok=True)
    (root / "AGENTS.md").write_text("# Agent Instructions\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
    (root / "README.md").write_text("# Demo\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "MAP.md").write_text("# Map\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    status_body = "# Status\n\nStatus: active\nUpdated: 2026-06-12\n\nsecret body\n"
    status_body += "\n".join(f"- generated historical line {index}" for index in range(901)) + "\n"
    (root / "STATUS.md").write_text(status_body, encoding="utf-8")
    (root / "MILESTONE_35_GENERATED_STATUS.md").write_text(
        "# MILESTONE-35\n\nStatus: complete\nDate: 2026-06-12\n\n## Verification\n\nok\n\n## Next Risk\n\nNone.\n",
        encoding="utf-8",
    )
    return root


if __name__ == "__main__":
    unittest.main()
