from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.memory_supersession import MemorySupersessionStore
from ams_codex.models import canonical_json, hash_without, sha256_text
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore


class MemorySupersessionTest(unittest.TestCase):
    def test_promotes_first_clean_claim_without_raw_value_storage(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            result = MemorySupersessionStore(store).create_review(
                domain="ams",
                subject="startup authority",
                predicate="current source",
                value_sha256=_value_hash("generated-status"),
                source_ref="md://GENERATED_STATUS.md#latest",
                value_summary="GENERATED_STATUS.md is current startup status surface",
            )

            self.assertEqual(result["review"]["status"], "promoted")
            self.assertIn("claim", result)
            self.assertFalse(result["claim"]["raw_value_stored"])
            self.assertFalse(result["claim"]["retrieval_is_authority"])
            self.assertEqual(result["review"]["created_memory_claim_id"], result["claim"]["memory_claim_id"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_duplicate_claim_is_noop_and_does_not_create_second_claim(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            memory = MemorySupersessionStore(store)

            first = memory.create_review(
                domain="ams",
                subject="rag",
                predicate="authority",
                value_sha256=_value_hash("recall-only"),
                source_ref="m9://rag-policy",
            )
            second = memory.create_review(
                domain="ams",
                subject="rag",
                predicate="authority",
                value_sha256=_value_hash("recall-only"),
                source_ref="m9://rag-policy-repeat",
            )

            state = store.load()
            self.assertEqual(first["review"]["status"], "promoted")
            self.assertEqual(second["review"]["status"], "duplicate")
            self.assertNotIn("claim", second)
            self.assertEqual(len(state["memory_claims"]), 1)
            self.assertEqual(
                second["review"]["duplicate_claim_ref"]["memory_claim_id"],
                first["claim"]["memory_claim_id"],
            )
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_conflicting_claim_requires_operator_and_blocks_quiet_build(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            memory = MemorySupersessionStore(store)
            memory.create_review(
                domain="ams",
                subject="session policy",
                predicate="resume behavior",
                value_sha256=_value_hash("resume-existing-thread"),
                source_ref="operator://channel_a/session-policy-a",
            )

            result = memory.create_review(
                domain="ams",
                subject="session policy",
                predicate="resume behavior",
                value_sha256=_value_hash("always-new-thread"),
                source_ref="operator://channel_a/session-policy-b",
            )

            self.assertEqual(result["review"]["status"], "needs_operator")
            self.assertFalse(result["review"]["quiet_build_allowed"])
            self.assertIn("conflict", result)
            self.assertEqual(result["conflict"]["build_quietly_allowed"], False)
            self.assertEqual(result["conflict"]["requires_operator_resolution"], True)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_global_scope_conflicts_with_project_scope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            memory = MemorySupersessionStore(store)
            memory.create_review(
                domain="ams",
                subject="doc writes",
                predicate="executor",
                scope="global",
                value_sha256=_value_hash("single-executor"),
                source_ref="m9://68",
            )

            result = memory.create_review(
                domain="ams",
                subject="doc writes",
                predicate="executor",
                scope="project:AMS_codex",
                value_sha256=_value_hash("direct-agent-writes"),
                source_ref="prompt://new-request",
            )

            self.assertEqual(result["review"]["status"], "needs_operator")
            self.assertIn("memory_promotion.conflict_requires_operator", result["review"]["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_non_overlapping_temporal_claim_can_promote(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            memory = MemorySupersessionStore(store)
            memory.create_review(
                domain="ams",
                subject="model preference",
                predicate="primary verifier",
                value_sha256=_value_hash("claude-fable"),
                source_ref="operator://past",
                valid_until="2026-05-31",
            )

            result = memory.create_review(
                domain="ams",
                subject="model preference",
                predicate="primary verifier",
                value_sha256=_value_hash("codex-then-claude"),
                source_ref="operator://current",
                valid_from="2026-06-01",
            )

            self.assertEqual(result["review"]["status"], "promoted")
            self.assertIn("claim", result)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_supersession_requires_operator_proof_then_records_old_and_new_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            memory = MemorySupersessionStore(store)
            first = memory.create_review(
                domain="ams",
                subject="latest milestone",
                predicate="accepted",
                value_sha256=_value_hash("milestone-68"),
                source_ref="git://tag/milestone-68",
            )

            blocked = memory.create_review(
                domain="ams",
                subject="latest milestone",
                predicate="accepted",
                value_sha256=_value_hash("milestone-69"),
                source_ref="git://tag/milestone-69",
                supersedes_claim_id=first["claim"]["memory_claim_id"],
                operator_confirmed=True,
            )
            accepted = memory.create_review(
                domain="ams",
                subject="latest milestone",
                predicate="accepted",
                value_sha256=_value_hash("milestone-69"),
                source_ref="git://tag/milestone-69",
                supersedes_claim_id=first["claim"]["memory_claim_id"],
                operator_confirmed=True,
                operator_confirmation_ref="operator://approval/milestone-69",
                operator_confirmation_sha256=_value_hash("approval-milestone-69"),
            )

            self.assertEqual(blocked["review"]["status"], "needs_operator")
            self.assertNotIn("supersession", blocked)
            self.assertEqual(accepted["review"]["status"], "promoted")
            self.assertIn("supersession", accepted)
            self.assertEqual(
                accepted["supersession"]["old_memory_claim_id"],
                first["claim"]["memory_claim_id"],
            )
            self.assertEqual(
                accepted["supersession"]["new_memory_claim_id"],
                accepted["claim"]["memory_claim_id"],
            )
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_rag_reference_cannot_act_as_authority(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            result = MemorySupersessionStore(store).create_review(
                domain="ams",
                subject="operator preference",
                predicate="daily session",
                value_sha256=_value_hash("continue-on-summary"),
                source_ref="rag://candidate",
                rag_retrieval_refs=[
                    {
                        "rag_retrieval_query_id": "missing-query",
                        "retrieval_query_sha256": _value_hash("missing-query"),
                        "retrieval_is_authority": True,
                    }
                ],
            )

            self.assertEqual(result["review"]["status"], "blocked")
            self.assertNotIn("claim", result)
            self.assertIn("memory_promotion.rag_authority_not_allowed", result["review"]["reason_codes"])
            self.assertIn("memory_promotion.rag_ref_missing_query", result["review"]["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_rehashed_conflict_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            memory = MemorySupersessionStore(store)
            memory.create_review(
                domain="ams",
                subject="memory",
                predicate="promotion",
                value_sha256=_value_hash("review-first"),
                source_ref="operator://a",
            )
            result = memory.create_review(
                domain="ams",
                subject="memory",
                predicate="promotion",
                value_sha256=_value_hash("promote-directly"),
                source_ref="operator://b",
            )
            conflict_id = result["conflict"]["memory_conflict_record_id"]

            state = store.load()
            conflict = state["memory_conflict_records"][conflict_id]
            conflict["build_quietly_allowed"] = True
            conflict["memory_conflict_record_sha256"] = hash_without(
                conflict,
                "memory_conflict_record_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()
            self.assertFalse(replay["ok"])
            self.assertIn("memory_conflict.build_quietly_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_memory_collections(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            memory = MemorySupersessionStore(store)
            first = memory.create_review(
                domain="ams",
                subject="latest milestone",
                predicate="accepted",
                value_sha256=_value_hash("milestone-68"),
                source_ref="git://tag/milestone-68",
            )
            memory.create_review(
                domain="ams",
                subject="latest milestone",
                predicate="accepted",
                value_sha256=_value_hash("milestone-69"),
                source_ref="git://tag/milestone-69",
                supersedes_claim_id=first["claim"]["memory_claim_id"],
                operator_confirmed=True,
                operator_confirmation_ref="operator://approval/milestone-69",
                operator_confirmation_sha256=_value_hash("approval-milestone-69"),
            )
            memory.create_review(
                domain="ams",
                subject="latest milestone",
                predicate="accepted",
                value_sha256=_value_hash("milestone-70"),
                source_ref="operator://future-conflict",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("memory_claims", collections)
            self.assertIn("memory_promotion_reviews", collections)
            self.assertIn("memory_supersession_records", collections)
            self.assertIn("memory_conflict_records", collections)


def _value_hash(value: str) -> str:
    return sha256_text(canonical_json(["memory-test", value]))


if __name__ == "__main__":
    unittest.main()
