from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ams_codex.cli import cmd_markdown_audit
from ams_codex.markdown_governance import MarkdownAuditStore, _hash_without
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore


class MarkdownGovernanceTest(unittest.TestCase):
    def test_markdown_audit_records_hash_only_authority_map(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AGENTS.md").write_text("# Agent Instructions\n\n- Run tests.\n", encoding="utf-8")
            (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
            (root / "README.md").write_text(
                "# Demo\n\nStatus: complete\nUpdated: 2026-06-12\n",
                encoding="utf-8",
            )
            (root / "MILESTONE_32_MARKDOWN_GOVERNANCE.md").write_text(
                "# MILESTONE-32 Markdown Governance\n\n"
                "Status: complete\n"
                "Date: 2026-06-12 America/Chicago\n\n"
                "## Verification\n\npython3 -m pytest -q\n\n"
                "## Next Risk\n\nNone.\n",
                encoding="utf-8",
            )
            store = JsonStore(root / "store.json")

            audit = MarkdownAuditStore(store).create(source_root=root, label="test")

            self.assertEqual(audit["scan_mode"], "metadata_hash_only")
            self.assertFalse(audit["raw_markdown_stored"])
            self.assertTrue(audit["instruction_files"]["all_present"])
            self.assertIn("AGENTS.md", audit["authority_index"]["instruction_docs"])
            self.assertEqual(audit["authority_index"]["latest_milestone_doc"], "MILESTONE_32_MARKDOWN_GOVERNANCE.md")
            self.assertEqual(audit["status"], "allow")
            self.assertEqual(audit["reason_codes"], ["markdown_audit.ok"])
            serialized = str(audit)
            self.assertNotIn("Run tests.", serialized)
            self.assertNotIn("Agent Instructions", serialized)
            self.assertNotIn("MILESTONE-32 Markdown Governance", serialized)
            self.assertNotIn("2026-06-12 America/Chicago", serialized)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_markdown_audit_flags_missing_metadata_and_instruction_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("# Demo\n", encoding="utf-8")
            (root / "MILESTONE_32_MARKDOWN_GOVERNANCE.md").write_text("# MILESTONE-32 Markdown Governance\n", encoding="utf-8")
            store = JsonStore(root / "store.json")

            audit = MarkdownAuditStore(store).create(source_root=root, label="test")

            self.assertEqual(audit["status"], "defer")
            self.assertIn("markdown_audit.instruction_files_missing", audit["reason_codes"])
            self.assertIn("markdown_audit.metadata_gaps", audit["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_markdown_audit_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AGENTS.md").write_text("# Agent Instructions\n", encoding="utf-8")
            (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
            (root / "README.md").write_text("# Demo\n\nStatus: complete\n", encoding="utf-8")
            store = JsonStore(root / "store.json")
            audit = MarkdownAuditStore(store).create(source_root=root, label="test")
            state = store.load()
            state["markdown_audits"][audit["markdown_audit_id"]]["markdown_file_count"] = 999
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("markdown_audit.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_rejects_rehashed_raw_file_summary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AGENTS.md").write_text("# Agent Instructions\n", encoding="utf-8")
            (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
            (root / "README.md").write_text("# Demo\n\nStatus: complete\n", encoding="utf-8")
            store = JsonStore(root / "store.json")
            audit = MarkdownAuditStore(store).create(source_root=root, label="test")
            state = store.load()
            record = state["markdown_audits"][audit["markdown_audit_id"]]
            record["file_summaries"][0]["raw_content_stored"] = True
            record["markdown_audit_sha256"] = _hash_without(record, "markdown_audit_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("markdown_audit.schema_invalid", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_markdown_audits(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AGENTS.md").write_text("# Agent Instructions\n", encoding="utf-8")
            (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
            (root / "README.md").write_text("# Demo\n\nStatus: complete\n", encoding="utf-8")
            store = JsonStore(root / "store.json")
            MarkdownAuditStore(store).create(source_root=root, label="test")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("markdown_audits", collections)

    def test_scanner_excludes_sensitive_dirs_and_orders_hyphenated_milestones(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AGENTS.md").write_text("# Agent Instructions\n", encoding="utf-8")
            (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
            (root / "README.md").write_text("# Demo\n\nStatus: active\n", encoding="utf-8")
            (root / "MILESTONE-2_ALPHA.md").write_text(
                "# MILESTONE-2\n\nStatus: complete\nDate: 2026-06-10\n\n## Verification\n\nok\n\n## Next\n\nNone.\n",
                encoding="utf-8",
            )
            (root / "MILESTONE-32_ALPHA.md").write_text(
                "# MILESTONE-32\n\nStatus: complete\nDate: 2026-06-12\n\n## Verification\n\nok\n\n## Next\n\nNone.\n",
                encoding="utf-8",
            )
            (root / ".claude").mkdir()
            (root / ".claude" / "secret.md").write_text("# Do not scan\n", encoding="utf-8")
            (root / "transcripts").mkdir()
            (root / "transcripts" / "raw.md").write_text("# Do not scan\n", encoding="utf-8")
            (root / "UPPER.MD").write_text("# Upper\n", encoding="utf-8")

            audit = MarkdownAuditStore(JsonStore(root / "store.json")).create(source_root=root, label="test")

            paths = {summary["path"] for summary in audit["file_summaries"]}
            self.assertIn("UPPER.MD", paths)
            self.assertNotIn(".claude/secret.md", paths)
            self.assertNotIn("transcripts/raw.md", paths)
            self.assertEqual(audit["authority_index"]["latest_milestone_doc"], "MILESTONE-32_ALPHA.md")

    def test_session_window_is_validated_and_labeled_generically(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AGENTS.md").write_text("# Agent Instructions\n", encoding="utf-8")
            (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
            (root / "README.md").write_text("# Demo\n\nStatus: active\n", encoding="utf-8")
            store = JsonStore(root / "store.json")

            audit = MarkdownAuditStore(store).create(source_root=root, label="test", session_window_days=7)

            self.assertEqual(audit["session_metadata"]["window_days"], 7)
            self.assertNotIn("thread_count_90d", str(audit))
            with self.assertRaises(ValueError):
                MarkdownAuditStore(store).create(source_root=root, label="bad", session_window_days=0)

    def test_cli_returns_nonzero_for_defer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "README.md").write_text("# Demo\n", encoding="utf-8")
            args = SimpleNamespace(
                store=str(root / "store.json"),
                source_root=str(root),
                label="test",
                include_local_session_metadata=False,
                session_window_days=92,
            )

            self.assertEqual(cmd_markdown_audit(args), 1)


if __name__ == "__main__":
    unittest.main()
