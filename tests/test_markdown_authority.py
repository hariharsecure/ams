from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ams_codex.cli import cmd_markdown_authority_index
from ams_codex.markdown_authority import MarkdownAuthorityStore
from ams_codex.models import hash_without
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore


class MarkdownAuthorityTest(unittest.TestCase):
    def test_authority_index_records_startup_surface_without_raw_content(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _authority_repo(Path(td))
            store = JsonStore(root / "store.json")

            result = MarkdownAuthorityStore(store).create(source_root=root, label="test-authority")

            index = result["index"]
            self.assertEqual(index["status"], "allow")
            self.assertEqual(index["reason_codes"], ["markdown_authority_index.allow"])
            self.assertEqual(index["latest_milestone_doc"], "MILESTONE_69_MEMORY_SUPERSESSION_AND_RAG_ANALYSIS.md")
            self.assertEqual(
                index["startup_surface"],
                [
                    "AGENTS.md",
                    "GENERATED_STATUS.md",
                    "MAP.md",
                    "MILESTONE_69_MEMORY_SUPERSESSION_AND_RAG_ANALYSIS.md",
                    "STATUS.md",
                ],
            )
            self.assertNotIn("MILESTONE_1_TOOL_SURFACE_REGISTRY.md", index["startup_surface"])
            serialized = str(result)
            self.assertNotIn("do not store this instruction body", serialized)
            self.assertTrue(all(entry["raw_content_stored"] is False for entry in result["entries"]))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_stale_generated_status_defers_and_excludes_generated_status_from_startup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _authority_repo(Path(td))
            (root / "GENERATED_STATUS.md").write_text(
                "# AMS Generated Status\n\n- Latest milestone: `MILESTONE_1_TOOL_SURFACE_REGISTRY.md`\n",
                encoding="utf-8",
            )
            store = JsonStore(root / "store.json")

            result = MarkdownAuthorityStore(store).create(source_root=root, label="test-authority")

            index = result["index"]
            self.assertEqual(index["status"], "defer")
            self.assertIn("markdown_authority_index.generated_status_stale", index["reason_codes"])
            self.assertIn(
                "markdown_authority_index.required_startup_not_included:GENERATED_STATUS.md",
                index["reason_codes"],
            )
            self.assertNotIn("GENERATED_STATUS.md", index["startup_surface"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_explicit_supersession_marks_old_doc_inactive_and_symmetric(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _authority_repo(Path(td))
            store = JsonStore(root / "store.json")

            result = MarkdownAuthorityStore(store).create(
                source_root=root,
                label="test-authority",
                supersession_edges=[
                    {
                        "old_path": "MILESTONE_1_TOOL_SURFACE_REGISTRY.md",
                        "new_path": "MILESTONE_69_MEMORY_SUPERSESSION_AND_RAG_ANALYSIS.md",
                        "mode": "temporal_update",
                    }
                ],
            )

            by_path = {entry["path"]: entry for entry in result["entries"]}
            old = by_path["MILESTONE_1_TOOL_SURFACE_REGISTRY.md"]
            new = by_path["MILESTONE_69_MEMORY_SUPERSESSION_AND_RAG_ANALYSIS.md"]
            self.assertEqual(old["authority_level"], "superseded")
            self.assertEqual(old["status"], "inactive")
            self.assertFalse(old["startup_include"])
            self.assertEqual(old["superseded_by"], ["MILESTONE_69_MEMORY_SUPERSESSION_AND_RAG_ANALYSIS.md"])
            self.assertIn("MILESTONE_1_TOOL_SURFACE_REGISTRY.md", new["supersedes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_rejects_rehashed_entry_with_missing_source_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _authority_repo(Path(td))
            store = JsonStore(root / "store.json")
            result = MarkdownAuthorityStore(store).create(source_root=root, label="test-authority")
            state = store.load()
            entry_id = result["entries"][0]["markdown_authority_entry_id"]
            entry = state["markdown_authority_entries"][entry_id]
            entry["source_sha256"] = None
            entry["markdown_authority_entry_sha256"] = hash_without(entry, "markdown_authority_entry_sha256")
            index = next(iter(state["markdown_authority_indexes"].values()))
            for ref in index["entry_refs"]:
                if ref["markdown_authority_entry_id"] == entry_id:
                    ref["markdown_authority_entry_sha256"] = entry["markdown_authority_entry_sha256"]
            index["markdown_authority_index_sha256"] = hash_without(index, "markdown_authority_index_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("markdown_authority_entry.source_hash_missing", "\n".join(replay["errors"]))

    def test_replay_rejects_rehashed_invalid_startup_inclusion(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _authority_repo(Path(td))
            store = JsonStore(root / "store.json")
            MarkdownAuthorityStore(store).create(source_root=root, label="test-authority")
            state = store.load()
            entry = next(
                item
                for item in state["markdown_authority_entries"].values()
                if item["path"] == "MILESTONE_1_TOOL_SURFACE_REGISTRY.md"
            )
            entry["startup_include"] = True
            entry["markdown_authority_entry_sha256"] = hash_without(entry, "markdown_authority_entry_sha256")
            index = next(iter(state["markdown_authority_indexes"].values()))
            index["startup_surface"].append(entry["path"])
            index["startup_surface"].sort()
            for ref in index["entry_refs"]:
                if ref["markdown_authority_entry_id"] == entry["markdown_authority_entry_id"]:
                    ref["markdown_authority_entry_sha256"] = entry["markdown_authority_entry_sha256"]
            index["markdown_authority_index_sha256"] = hash_without(index, "markdown_authority_index_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("markdown_authority_entry.invalid_startup_authority", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_markdown_authority_records(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _authority_repo(Path(td))
            store = JsonStore(root / "store.json")
            MarkdownAuthorityStore(store).create(source_root=root, label="test-authority")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("markdown_authority_indexes", collections)
            self.assertIn("markdown_authority_entries", collections)

    def test_cli_returns_nonzero_for_deferred_authority_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")
            args = SimpleNamespace(
                store=str(root / "store.json"),
                source_root=str(root),
                label="test-authority",
                supersedes=[],
            )

            self.assertEqual(cmd_markdown_authority_index(args), 1)


def _authority_repo(root: Path) -> Path:
    root.mkdir(exist_ok=True)
    (root / "AGENTS.md").write_text(
        "# Agents\n\nStatus: active\nUpdated: 2026-06-15\n\n"
        "do not store this instruction body\n",
        encoding="utf-8",
    )
    (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
    (root / "STATUS.md").write_text("# Status\n\nStatus: active\nUpdated: 2026-06-15\n", encoding="utf-8")
    (root / "MAP.md").write_text("# Map\n\nStatus: active\nUpdated: 2026-06-15\n", encoding="utf-8")
    (root / "README.md").write_text("# Demo\n\nStatus: active\nUpdated: 2026-06-15\n", encoding="utf-8")
    (root / "GENERATED_STATUS.md").write_text(
        "# AMS Generated Status\n\n"
        "Status: generated\n\n"
        "- Latest milestone: `MILESTONE_69_MEMORY_SUPERSESSION_AND_RAG_ANALYSIS.md`\n",
        encoding="utf-8",
    )
    (root / "MILESTONE_1_TOOL_SURFACE_REGISTRY.md").write_text(
        "# MILESTONE-1\n\nStatus: complete\nDate: 2026-06-10\n\n## Verification\n\nok\n\n## Next\n\nNone.\n",
        encoding="utf-8",
    )
    (root / "MILESTONE_69_MEMORY_SUPERSESSION_AND_RAG_ANALYSIS.md").write_text(
        "# MILESTONE-69\n\nStatus: complete\nDate: 2026-06-14\n\n## Verification\n\nok\n\n## Next\n\nMILESTONE-70.\n",
        encoding="utf-8",
    )
    (root / "AMS_PREBUILD_SUPERSEDING_IDEAS_PLAN_2026-06-15.md").write_text(
        "# Plan\n\nStatus: pre-build plan\nDate: 2026-06-15\n\n## Sources\n\n- local\n",
        encoding="utf-8",
    )
    return root


if __name__ == "__main__":
    unittest.main()
