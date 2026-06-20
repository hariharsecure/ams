from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ams.cli import cmd_session_start_brief
from ams.generated_artifact import hash_without
from ams.markdown_authority import MarkdownAuthorityStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.session_start_brief import SessionStartBriefStore, build_session_start_brief
from ams.store import JsonStore


class SessionStartBriefTest(unittest.TestCase):
    def test_session_start_brief_writes_compact_start_surface(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")

            brief = SessionStartBriefStore(store).create(source_root=root, label="test-start-brief")

            output = root / "NEW_CODEX_SESSION.md"
            self.assertTrue(output.exists())
            self.assertEqual(brief["status"], "allow")
            self.assertLessEqual(brief["rendered"]["line_count"], brief["line_budget"])
            text = output.read_text(encoding="utf-8")
            self.assertIn("GENERATED_STATUS.md", text)
            self.assertIn("MILESTONE_36_SESSION_START_BRIEF.md", text)
            self.assertNotIn("MILESTONE_0_SIGNED_POLICY.md", text)
            self.assertFalse(brief["operator_guidance"]["read_all_milestones_on_start"])
            self.assertTrue(all(ref["raw_content_stored"] is False for ref in brief["source_refs"]))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_session_start_brief_defers_overwrite_without_approval(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            (root / "NEW_CODEX_SESSION.md").write_text("# stale\n", encoding="utf-8")
            store = JsonStore(root / "store.json")

            brief = SessionStartBriefStore(store).create(source_root=root, label="test-start-brief")

            self.assertEqual(brief["status"], "defer")
            self.assertIn("session_start_brief.overwrite_requires_approval", brief["reason_codes"])
            self.assertFalse(brief["write_result"]["write_performed"])
            self.assertEqual((root / "NEW_CODEX_SESSION.md").read_text(encoding="utf-8"), "# stale\n")

    def test_existing_matching_output_is_not_rewritten_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            first = build_session_start_brief(
                source_root=root,
                label="test-start-brief",
                now="2026-06-12T00:00:00Z",
            )

            second = build_session_start_brief(
                source_root=root,
                label="test-start-brief",
                now="2026-06-13T00:00:00Z",
            )

            self.assertEqual(first["rendered"]["sha256"], second["rendered"]["sha256"])
            self.assertEqual(second["status"], "allow")
            self.assertFalse(second["write_result"]["write_performed"])
            self.assertTrue(second["write_result"]["output_already_current"])
            self.assertFalse(second["write_result"]["rewrote_existing_session_start_file"])
            rendered = (root / "NEW_CODEX_SESSION.md").read_text(encoding="utf-8")
            self.assertIn("Source snapshot:", rendered)
            self.assertNotIn("Updated: 2026-06", rendered)

    def test_replay_catches_session_start_brief_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")
            brief = SessionStartBriefStore(store).create(source_root=root, label="test-start-brief")
            state = store.load()
            state["session_start_briefs"][brief["session_start_brief_id"]]["rendered"]["line_count"] = 999
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("session_start_brief.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_rejects_rehashed_live_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")
            brief = SessionStartBriefStore(store).create(source_root=root, label="test-start-brief")
            state = store.load()
            record = state["session_start_briefs"][brief["session_start_brief_id"]]
            record["boundaries"]["live_process_started"] = True
            record["session_start_brief_sha256"] = hash_without(record, "session_start_brief_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("session_start_brief.live_process_started_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_session_start_briefs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")
            SessionStartBriefStore(store).create(source_root=root, label="test-start-brief")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("session_start_briefs", collections)

    def test_cli_writes_session_start_brief_and_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            args = SimpleNamespace(
                store=str(root / "store.json"),
                source_root=str(root),
                output_path="NEW_CODEX_SESSION.md",
                label="test-start-brief",
                no_write_file=False,
                allow_overwrite=False,
            )

            self.assertEqual(cmd_session_start_brief(args), 0)
            self.assertTrue((root / "NEW_CODEX_SESSION.md").exists())

    def test_milestone_69_next_work_matches_memory_authority_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            (root / "GENERATED_STATUS.md").write_text(
                "# AMS Generated Status\n\n- Latest milestone: `MILESTONE_69_MEMORY_SUPERSESSION_AND_RAG_ANALYSIS.md`\n",
                encoding="utf-8",
            )
            (root / "MILESTONE_69_MEMORY_SUPERSESSION_AND_RAG_ANALYSIS.md").write_text(
                "# MILESTONE-69\n\nStatus: complete\nDate: 2026-06-14\n",
                encoding="utf-8",
            )

            brief = build_session_start_brief(
                source_root=root,
                label="test-start-brief",
                now="2026-06-14T00:00:00Z",
            )

            text = (root / "NEW_CODEX_SESSION.md").read_text(encoding="utf-8")
            self.assertEqual(brief["latest_milestone_doc"], "MILESTONE_69_MEMORY_SUPERSESSION_AND_RAG_ANALYSIS.md")
            self.assertIn("MarkdownAuthorityIndex", text)
            self.assertIn("memory-source readback", text)
            self.assertNotIn("MILESTONE-34 doc-retirement", text)

    def test_milestone_71_next_work_matches_graph_preflight_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            (root / "GENERATED_STATUS.md").write_text(
                "# AMS Generated Status\n\n- Latest milestone: `MILESTONE_71_CODEBASE_SPIDER_GRAPH_INDEX.md`\n",
                encoding="utf-8",
            )
            (root / "MILESTONE_71_CODEBASE_SPIDER_GRAPH_INDEX.md").write_text(
                "# MILESTONE-71\n\nStatus: complete\nDate: 2026-06-15\n",
                encoding="utf-8",
            )

            brief = build_session_start_brief(
                source_root=root,
                label="test-start-brief",
                now="2026-06-15T00:00:00Z",
            )

            text = (root / "NEW_CODEX_SESSION.md").read_text(encoding="utf-8")
            self.assertEqual(brief["latest_milestone_doc"], "MILESTONE_71_CODEBASE_SPIDER_GRAPH_INDEX.md")
            self.assertIn("graph-backed source-change preflight", text)
            self.assertIn("BlastRadiusReview", text)
            self.assertNotIn("Build `CodebaseSpiderGraphIndex`", text)

    def test_milestone_72_next_work_matches_source_write_executor_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            (root / "GENERATED_STATUS.md").write_text(
                "# AMS Generated Status\n\n- Latest milestone: `MILESTONE_72_BLAST_RADIUS_REVIEW.md`\n",
                encoding="utf-8",
            )
            (root / "MILESTONE_72_BLAST_RADIUS_REVIEW.md").write_text(
                "# MILESTONE-72\n\nStatus: complete\nDate: 2026-06-15\n",
                encoding="utf-8",
            )

            brief = build_session_start_brief(
                source_root=root,
                label="test-start-brief",
                now="2026-06-15T00:00:00Z",
            )

            text = (root / "NEW_CODEX_SESSION.md").read_text(encoding="utf-8")
            self.assertEqual(brief["latest_milestone_doc"], "MILESTONE_72_BLAST_RADIUS_REVIEW.md")
            self.assertIn("exclusive source-write executor preflight", text)
            self.assertIn("BlastRadiusReview", text)
            self.assertNotIn("graph-backed source-change preflight", text)

    def test_milestone_73_next_work_matches_backup_preimage_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            (root / "GENERATED_STATUS.md").write_text(
                "# AMS Generated Status\n\n- Latest milestone: `MILESTONE_73_SOURCE_WRITE_PREFLIGHT.md`\n",
                encoding="utf-8",
            )
            (root / "MILESTONE_73_SOURCE_WRITE_PREFLIGHT.md").write_text(
                "# MILESTONE-73\n\nStatus: complete\nDate: 2026-06-15\n",
                encoding="utf-8",
            )

            brief = build_session_start_brief(
                source_root=root,
                label="test-start-brief",
                now="2026-06-15T00:00:00Z",
            )

            text = (root / "NEW_CODEX_SESSION.md").read_text(encoding="utf-8")
            self.assertEqual(brief["latest_milestone_doc"], "MILESTONE_73_SOURCE_WRITE_PREFLIGHT.md")
            self.assertIn("backup/preimage receipt", text)
            self.assertIn("post-write replay/readback settlement", text)
            self.assertNotIn("exclusive source-write executor preflight", text)

    def test_milestone_74_next_work_matches_post_write_replay_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            (root / "GENERATED_STATUS.md").write_text(
                "# AMS Generated Status\n\n- Latest milestone: `MILESTONE_74_SOURCE_WRITE_BACKUP_PREIMAGE.md`\n",
                encoding="utf-8",
            )
            (root / "MILESTONE_74_SOURCE_WRITE_BACKUP_PREIMAGE.md").write_text(
                "# MILESTONE-74\n\nStatus: complete\nDate: 2026-06-15\n",
                encoding="utf-8",
            )

            brief = build_session_start_brief(
                source_root=root,
                label="test-start-brief",
                now="2026-06-15T00:00:00Z",
            )

            text = (root / "NEW_CODEX_SESSION.md").read_text(encoding="utf-8")
            self.assertEqual(brief["latest_milestone_doc"], "MILESTONE_74_SOURCE_WRITE_BACKUP_PREIMAGE.md")
            self.assertIn("post-write replay/readback settlement", text)
            self.assertIn("authorized postimage changes", text)
            self.assertNotIn("Build the backup/preimage receipt", text)

    def test_milestone_75_next_work_matches_source_write_receipt_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            (root / "GENERATED_STATUS.md").write_text(
                "# AMS Generated Status\n\n- Latest milestone: `MILESTONE_75_SOURCE_WRITE_EXECUTOR_LEASE.md`\n",
                encoding="utf-8",
            )
            (root / "MILESTONE_75_SOURCE_WRITE_EXECUTOR_LEASE.md").write_text(
                "# MILESTONE-75\n\nStatus: complete\nDate: 2026-06-15\n",
                encoding="utf-8",
            )

            brief = build_session_start_brief(
                source_root=root,
                label="test-start-brief",
                now="2026-06-15T00:00:00Z",
            )

            text = (root / "NEW_CODEX_SESSION.md").read_text(encoding="utf-8")
            self.assertEqual(brief["latest_milestone_doc"], "MILESTONE_75_SOURCE_WRITE_EXECUTOR_LEASE.md")
            self.assertIn("source-write receipt", text)
            self.assertIn("postimage hashes", text)
            self.assertNotIn("Build the post-write replay/readback settlement", text)

    def test_milestone_76_next_work_matches_real_agent_system_trial_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            (root / "GENERATED_STATUS.md").write_text(
                "# AMS Generated Status\n\n- Latest milestone: `MILESTONE_76_REAL_AGENT_SYSTEM_TRIAL.md`\n",
                encoding="utf-8",
            )
            (root / "MILESTONE_76_REAL_AGENT_SYSTEM_TRIAL.md").write_text(
                "# MILESTONE-76\n\nStatus: complete\nDate: 2026-06-15\n",
                encoding="utf-8",
            )

            brief = build_session_start_brief(
                source_root=root,
                label="test-start-brief",
                now="2026-06-15T00:00:00Z",
            )

            text = (root / "NEW_CODEX_SESSION.md").read_text(encoding="utf-8")
            self.assertEqual(brief["latest_milestone_doc"], "MILESTONE_76_REAL_AGENT_SYSTEM_TRIAL.md")
            self.assertIn("no-Discord real-agent system trial", text)
            self.assertIn("--allow-real-agents", text)
            self.assertIn("source-write receipt", text)
            self.assertNotIn("Build the source-write receipt", text)

    def test_session_start_brief_uses_markdown_authority_index_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            (root / "SUPPORTING_RESEARCH.md").write_text(
                "# Support\n\nStatus: support\nDate: 2026-06-12\n",
                encoding="utf-8",
            )
            store = JsonStore(root / "store.json")
            MarkdownAuthorityStore(store).create(source_root=root, label="test-authority")

            brief = SessionStartBriefStore(store).create(source_root=root, label="test-start-brief")

            source_paths = [ref["path"] for ref in brief["source_refs"]]
            self.assertIn("AGENTS.md", source_paths)
            self.assertIn("GENERATED_STATUS.md", source_paths)
            self.assertIn("MILESTONE_36_SESSION_START_BRIEF.md", source_paths)
            self.assertNotIn("SUPPORTING_RESEARCH.md", source_paths)
            self.assertNotIn("MILESTONE_0_SIGNED_POLICY.md", source_paths)
            self.assertTrue(ReplayChecker(store).check()["ok"])


def _minimal_repo(root: Path) -> Path:
    root.mkdir(exist_ok=True)
    (root / "AGENTS.md").write_text("# Agent Instructions\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "STATUS.md").write_text("# Status\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "MAP.md").write_text("# Map\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "GENERATED_STATUS.md").write_text(
        "# AMS Generated Status\n\n- Latest milestone: `MILESTONE_36_SESSION_START_BRIEF.md`\n",
        encoding="utf-8",
    )
    (root / "MILESTONE_36_SESSION_START_BRIEF.md").write_text(
        "# MILESTONE-36\n\nStatus: complete\nDate: 2026-06-12\n\n## Verification\n\nok\n\n## Next Risk\n\nNone.\n",
        encoding="utf-8",
    )
    (root / "MILESTONE_0_SIGNED_POLICY.md").write_text("# old milestone\n", encoding="utf-8")
    return root


if __name__ == "__main__":
    unittest.main()
