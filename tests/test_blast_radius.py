from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ams.admission import AdmissionReviewStore
from ams.architecture_audit import ArchitectureAuditStore
from ams.architecture_gate import ArchitectureGateStore
from ams.blast_radius import BlastRadiusReviewStore
from ams.capability_policy import build_capability_request, evaluate_capability_request
from ams.cli import cmd_blast_radius_review
from ams.codebase_spider_graph import CodebaseSpiderGraphStore
from ams.codex_adapter import CodexDryRunAdapter
from ams.context import ContextStore
from ams.dispatch import dispatch
from ams.models import hash_without
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.resource_claim import ResourceClaimStore
from ams.run_trace import RunTraceStore
from ams.session_registry import SessionRegistry
from ams.store import JsonStore


class BlastRadiusReviewTest(unittest.TestCase):
    def test_review_allows_fresh_source_change_with_related_test(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")

            review = BlastRadiusReviewStore(store).create(
                source_root=root,
                package_name="ams",
                subject_kind="task_run",
                subject_id="task-1",
                paths=["ams/beta.py"],
                label="test-blast",
            )

            self.assertEqual(review["decision"], "allow")
            self.assertEqual(review["reason_codes"], ["blast_radius.reviewed"])
            self.assertIn("ams/alpha.py", review["impact_summary"]["impact_paths"])
            self.assertEqual(review["impact_summary"]["related_tests"], ["tests/test_beta.py"])
            self.assertEqual({ref["query_kind"] for ref in review["query_refs"]}, {
                "impact_slice",
                "related_tests",
                "stale_graph_check",
            })
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_review_defers_when_related_tests_are_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            (root / "ams" / "lonely.py").write_text("def lonely():\n    return 1\n", encoding="utf-8")
            store = JsonStore(root / "store.json")

            review = BlastRadiusReviewStore(store).create(
                source_root=root,
                package_name="ams",
                subject_kind="task_run",
                subject_id="task-1",
                paths=["ams/lonely.py"],
                label="test-blast",
            )

            self.assertEqual(review["decision"], "defer")
            self.assertIn("blast_radius.related_tests_missing", review["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_review_defers_when_graph_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")
            CodebaseSpiderGraphStore(store).create(source_root=root, package_name="ams", label="test-graph")
            (root / "ams" / "beta.py").write_text("def value():\n    return 'changed'\n", encoding="utf-8")

            review = BlastRadiusReviewStore(store).create(
                source_root=root,
                package_name="ams",
                subject_kind="task_run",
                subject_id="task-1",
                paths=["ams/beta.py"],
                label="test-blast",
            )

            self.assertEqual(review["decision"], "defer")
            self.assertIn("blast_radius.graph_query_stale", review["reason_codes"])
            self.assertIn("blast_radius.stale_paths", review["reason_codes"])
            self.assertEqual(review["impact_summary"]["stale_paths"], [
                {"path": "ams/beta.py", "reason": "hash_mismatch"}
            ])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_review_defers_unsafe_paths_without_reading_outside_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            (root.parent / "outside.txt").write_text("outside secret should not be read", encoding="utf-8")
            store = JsonStore(root / "store.json")

            review = BlastRadiusReviewStore(store).create(
                source_root=root,
                package_name="ams",
                subject_kind="task_run",
                subject_id="task-1",
                paths=["../outside.txt"],
                label="test-blast",
            )

            self.assertEqual(review["decision"], "defer")
            self.assertEqual(review["reason_codes"], ["blast_radius.unsafe_path"])
            self.assertEqual(review["impact_summary"]["rejected_paths"], [
                {"path": "../outside.txt", "reason": "unsafe_path"}
            ])
            self.assertNotIn("outside secret should not be read", str(review))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_rejects_rehashed_false_allow_for_stale_review(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")
            CodebaseSpiderGraphStore(store).create(source_root=root, package_name="ams", label="test-graph")
            (root / "ams" / "beta.py").write_text("def value():\n    return 'changed'\n", encoding="utf-8")
            review = BlastRadiusReviewStore(store).create(
                source_root=root,
                package_name="ams",
                subject_kind="task_run",
                subject_id="task-1",
                paths=["ams/beta.py"],
                label="test-blast",
            )
            state = store.load()
            record = state["blast_radius_reviews"][review["blast_radius_review_id"]]
            record["decision"] = "allow"
            record["reason_codes"] = ["blast_radius.reviewed"]
            record["blast_radius_review_sha256"] = hash_without(record, "blast_radius_review_sha256")
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("blast_radius.false_allow", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_blast_radius_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")
            BlastRadiusReviewStore(store).create(
                source_root=root,
                package_name="ams",
                subject_kind="task_run",
                subject_id="task-1",
                paths=["ams/beta.py"],
                label="test-blast",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("blast_radius_reviews", collections)

    def test_cli_writes_blast_radius_review(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            args = SimpleNamespace(
                store=str(root / "store.json"),
                source_root=str(root),
                package_name="ams",
                subject_kind="task_run",
                subject_id="task-1",
                path=["ams/beta.py"],
                change_intent="source_change",
                graph_snapshot_id=None,
                ensure_graph=True,
                depth=2,
                max_impact_paths=80,
                label="test-cli",
            )

            self.assertEqual(cmd_blast_radius_review(args), 0)
            self.assertTrue(ReplayChecker(JsonStore(root / "store.json")).check()["ok"])

    def test_dispatch_refuses_source_change_without_blast_radius_review(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            task_run = _ready_task_run(store)
            root = _graph_repo(Path(td) / "repo")
            gate = _architecture_gate(root, store, task_run, paths=["ams/beta.py"])
            request = _capability_request(paths=["ams/beta.py"], gate_bundle=gate)
            verdict = evaluate_capability_request(request)
            self.assertEqual(verdict["status"], "allow", verdict["reason_codes"])
            AdmissionReviewStore(store).create(
                subject_kind="task_run",
                subject_id=task_run["task_run_id"],
                operation="capability.dispatch",
                request=request,
                verdict=verdict,
            )

            result = dispatch(store, task_run["task_run_id"])

            self.assertFalse(result["dispatched"])
            self.assertEqual(result["reason_code"], "dispatch.blast_radius_review_required")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_dispatch_accepts_matching_blast_radius_review(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")
            task_run = _ready_task_run(store)
            gate = _architecture_gate(root, store, task_run, paths=["ams/beta.py"])
            review = BlastRadiusReviewStore(store).create(
                source_root=root,
                package_name="ams",
                subject_kind="task_run",
                subject_id=task_run["task_run_id"],
                paths=["ams/beta.py"],
                label="test-blast",
            )
            request = _capability_request(paths=["ams/beta.py"], blast_radius=review, gate_bundle=gate)
            verdict = evaluate_capability_request(request)
            self.assertEqual(verdict["status"], "allow", verdict["reason_codes"])
            AdmissionReviewStore(store).create(
                subject_kind="task_run",
                subject_id=task_run["task_run_id"],
                operation="capability.dispatch",
                request=request,
                verdict=verdict,
            )

            result = dispatch(store, task_run["task_run_id"])

            self.assertTrue(result["dispatched"], result)
            self.assertTrue(ReplayChecker(store).check()["ok"])


def _graph_repo(root: Path) -> Path:
    pkg = root / "ams"
    tests = root / "tests"
    pkg.mkdir(parents=True)
    tests.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "alpha.py").write_text(
        "from . import beta\n\n\ndef run():\n    return beta.value()\n",
        encoding="utf-8",
    )
    (pkg / "beta.py").write_text(
        "def value():\n    return 'secret_source_body'\n",
        encoding="utf-8",
    )
    (tests / "test_beta.py").write_text(
        "from ams import beta\n\n\ndef test_value():\n    assert beta.value()\n",
        encoding="utf-8",
    )
    return root


def _ready_task_run(store: JsonStore) -> dict:
    event = {"channel_id": "chan", "message_id": "root", "content": "build"}
    session, _ = SessionRegistry(store).ingest_event(event)
    session = CodexDryRunAdapter(store).bind_thread(session["session_id"], "thread-1")
    context = ContextStore(store).create_for_event(session, event)
    task_run = RunTraceStore(store).create_run(
        session["session_id"],
        context["context_id"],
        tool_scope=["ApplyPatch"],
    )
    claim = ResourceClaimStore(store).reserve(task_run["task_run_id"])
    ResourceClaimStore(store).transition(claim["claim"]["resource_claim_id"], "active")
    return task_run


def _architecture_gate(root: Path, store: JsonStore, task_run: dict, *, paths: list[str]) -> dict:
    audit = ArchitectureAuditStore(store).create(source_root=root, package_name="ams")
    gate = ArchitectureGateStore(store).create(
        subject_kind="task_run",
        subject_id=task_run["task_run_id"],
        paths=paths,
        architecture_audit_id=audit["architecture_audit_id"],
    )
    return {"audit": audit, "gate": gate}


def _capability_request(
    *,
    paths: list[str],
    blast_radius: dict | None = None,
    gate_bundle: dict | None = None,
) -> dict:
    audit = (gate_bundle or {}).get("audit") or {}
    gate = (gate_bundle or {}).get("gate") or {}
    return build_capability_request(
        tier="signed_maintainer",
        action="write",
        paths=paths,
        tools=["ApplyPatch", "Tests"],
        egress_mode="ams_outbox",
        change_request_id="chg_blast_radius",
        admission_review_id="adm_blast_radius",
        signed_policy_sha256="sha256:" + "a" * 64,
        architecture_gate_review_id=gate.get("architecture_gate_review_id"),
        architecture_audit_id=audit.get("architecture_audit_id"),
        architecture_audit_sha256=audit.get("architecture_audit_sha256"),
        blast_radius_review_id=(blast_radius or {}).get("blast_radius_review_id"),
        blast_radius_review_sha256=(blast_radius or {}).get("blast_radius_review_sha256"),
    )


if __name__ == "__main__":
    unittest.main()
