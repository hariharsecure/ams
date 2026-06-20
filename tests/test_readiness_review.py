from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ams_codex.cli import cmd_readiness_review
from ams_codex.readiness_review import ReadinessReviewStore, _hash_without
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore


class ReadinessReviewTest(unittest.TestCase):
    def test_readiness_review_records_overall_critique_without_live_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")

            review = ReadinessReviewStore(store).create(source_root=root, label="test-readiness")

            self.assertEqual(review["review_scope"], "local_preproduction")
            self.assertEqual(review["status"], "defer")
            self.assertFalse(review["live_boundaries"]["discord_call_performed"])
            self.assertFalse(review["live_boundaries"]["raw_content_stored"])
            self.assertGreaterEqual(review["score"]["dimension_count"], 10)
            self.assertEqual(review["evidence_summary"]["repo"]["latest_milestone_doc"], "MILESTONE_33_READINESS.md")
            self.assertIn("context_docs_memory", {d["dimension_id"] for d in review["dimensions"]})
            self.assertTrue(review["priority_actions"])
            serialized = str(review)
            self.assertNotIn("secret body", serialized)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_readiness_review_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")
            review = ReadinessReviewStore(store).create(source_root=root, label="test-readiness")
            state = store.load()
            state["readiness_reviews"][review["readiness_review_id"]]["score"]["score_total"] = 999
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("readiness_review.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_rejects_rehashed_live_boundary_flip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")
            review = ReadinessReviewStore(store).create(source_root=root, label="test-readiness")
            state = store.load()
            record = state["readiness_reviews"][review["readiness_review_id"]]
            record["live_boundaries"]["network_call_performed"] = True
            record["readiness_review_sha256"] = _hash_without(record, "readiness_review_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("readiness_review.network_call_performed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_readiness_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            store = JsonStore(root / "store.json")
            ReadinessReviewStore(store).create(source_root=root, label="test-readiness")

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("readiness_reviews", collections)

    def test_cli_returns_nonzero_for_defer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _minimal_repo(Path(td))
            args = SimpleNamespace(
                store=str(root / "store.json"),
                source_root=str(root),
                label="test-readiness",
                include_local_session_metadata=False,
                session_window_days=92,
            )

            self.assertEqual(cmd_readiness_review(args), 1)


def _minimal_repo(root: Path) -> Path:
    (root / "ams_codex").mkdir()
    (root / "schemas").mkdir()
    (root / "tests").mkdir()
    (root / "AGENTS.md").write_text("# Agent Instructions\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
    (root / "README.md").write_text("# Demo\n\nStatus: active\n\nsecret body\n", encoding="utf-8")
    (root / "STATUS.md").write_text("# Status\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "MAP.md").write_text("# Map\n\nStatus: active\n", encoding="utf-8")
    (root / "MILESTONES.md").write_text("# Milestones\n\nStatus: active\n", encoding="utf-8")
    (root / "AMS_100_PERCENT_PLAN.md").write_text("# Plan\n\nStatus: active\nUpdated: 2026-06-12\n", encoding="utf-8")
    (root / "MILESTONE_33_READINESS.md").write_text(
        "# MILESTONE-33\n\nStatus: complete\nDate: 2026-06-12\n\n## Verification\n\nok\n\n## Next Risk\n\nNone.\n",
        encoding="utf-8",
    )
    for rel in [
        "store.py",
        "replay.py",
        "replay_oracle.py",
        "schema_validation.py",
        "dispatch.py",
        "signed_policy.py",
        "package_manifest.py",
        "capability_policy.py",
        "resource_policy.py",
        "markdown_governance.py",
        "shadow_approval.py",
        "provider_auth.py",
        "discord_canary.py",
        "discord_canary_receipt.py",
        "terminal_source.py",
        "resource_telemetry.py",
        "backup_restore.py",
        "conformance_pack.py",
        "rag_index_plan.py",
        "rag_embedding_job.py",
        "rag_retrieval_query.py",
        "agent_memory_sim.py",
        "real_agent_trial.py",
        "intervention_settlement.py",
        "attention_router.py",
    ]:
        (root / "ams_codex" / rel).write_text("def marker():\n    return 1\n", encoding="utf-8")
    (root / "ams_codex" / "__init__.py").write_text("", encoding="utf-8")
    (root / "schemas" / "markdown_audit.schema.json").write_text("{}", encoding="utf-8")
    (root / "tests" / "test_demo.py").write_text("def test_demo():\n    assert True\n", encoding="utf-8")
    return root


if __name__ == "__main__":
    unittest.main()
