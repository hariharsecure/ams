from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.admission import AdmissionReviewStore
from ams.architecture_audit import ArchitectureAuditStore
from ams.architecture_gate import ArchitectureGateStore
from ams.blast_radius import BlastRadiusReviewStore
from ams.capability_policy import build_capability_request, evaluate_capability_request
from ams.codex_adapter import CodexDryRunAdapter
from ams.context import ContextStore
from ams.dispatch import dispatch
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.resource_claim import ResourceClaimStore
from ams.run_trace import RunTraceStore
from ams.session_registry import SessionRegistry
from ams.store import JsonStore


class ArchitectureGateTest(unittest.TestCase):
    def test_gate_review_allows_unscoped_paths_without_audit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            task_run = _ready_task_run(store)

            gate = ArchitectureGateStore(store).create(
                subject_kind="task_run",
                subject_id=task_run["task_run_id"],
                paths=["README.md"],
            )

            self.assertFalse(gate["required"])
            self.assertEqual(gate["decision"], "allow")
            self.assertEqual(gate["reason_codes"], ["architecture_gate.not_required"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_dispatch_refuses_architecture_scoped_change_without_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            task_run = _ready_task_run(store)
            request = _capability_request(paths=["ams/replay.py"])
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
            self.assertEqual(result["reason_code"], "dispatch.architecture_gate_required")
            self.assertIn("ams/replay.py", result["scoped_paths"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_dispatch_refuses_denied_architecture_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            task_run = _ready_task_run(store)
            audit = _architecture_audit(root, status="deny", store=store)
            self.assertEqual(audit["status"], "deny")
            gate = ArchitectureGateStore(store).create(
                subject_kind="task_run",
                subject_id=task_run["task_run_id"],
                paths=["ams/replay.py"],
                architecture_audit_id=audit["architecture_audit_id"],
            )
            self.assertEqual(gate["decision"], "deny")
            request = _capability_request(
                paths=["ams/replay.py"],
                gate=gate,
                audit=audit,
            )
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
            self.assertEqual(result["reason_code"], "dispatch.architecture_gate_denied")
            self.assertIn("architecture.import_cycle", result["architecture_reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_dispatch_allows_deferred_gate_with_explicit_admission(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            task_run = _ready_task_run(store)
            audit = _architecture_audit(root, status="defer", store=store)
            self.assertEqual(audit["status"], "defer")
            gate = ArchitectureGateStore(store).create(
                subject_kind="task_run",
                subject_id=task_run["task_run_id"],
                paths=["ams/replay.py"],
                architecture_audit_id=audit["architecture_audit_id"],
            )
            self.assertEqual(gate["decision"], "defer")
            blast = BlastRadiusReviewStore(store).create(
                source_root=root,
                package_name="ams",
                subject_kind="task_run",
                subject_id=task_run["task_run_id"],
                paths=["ams/replay.py"],
                label="test-blast-radius",
            )
            request = _capability_request(
                paths=["ams/replay.py"],
                gate=gate,
                audit=audit,
                blast_radius=blast,
            )
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

    def test_replay_catches_architecture_gate_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            task_run = _ready_task_run(store)
            audit = _architecture_audit(root, status="allow", store=store)
            gate = ArchitectureGateStore(store).create(
                subject_kind="task_run",
                subject_id=task_run["task_run_id"],
                paths=["ams/replay.py"],
                architecture_audit_id=audit["architecture_audit_id"],
            )
            state = store.load()
            state["architecture_gate_reviews"][gate["architecture_gate_review_id"]]["decision"] = "deny"
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("architecture_gate.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_architecture_gates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            store = JsonStore(root / "store.json")
            audit = _architecture_audit(root, status="allow", store=store)
            ArchitectureGateStore(store).create(
                subject_kind="change_request",
                subject_id="chg_arch_gate",
                paths=["ams/replay.py"],
                architecture_audit_id=audit["architecture_audit_id"],
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("architecture_gate_reviews", collections)


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


def _capability_request(
    *,
    paths: list[str],
    gate: dict | None = None,
    audit: dict | None = None,
    blast_radius: dict | None = None,
) -> dict:
    return build_capability_request(
        tier="signed_maintainer",
        action="write",
        paths=paths,
        tools=["ApplyPatch", "Tests"],
        egress_mode="ams_outbox",
        change_request_id="chg_arch_gate",
        admission_review_id="adm_arch_gate",
        signed_policy_sha256="sha256:" + "a" * 64,
        architecture_gate_review_id=(gate or {}).get("architecture_gate_review_id"),
        architecture_audit_id=(audit or {}).get("architecture_audit_id"),
        architecture_audit_sha256=(audit or {}).get("architecture_audit_sha256"),
        blast_radius_review_id=(blast_radius or {}).get("blast_radius_review_id"),
        blast_radius_review_sha256=(blast_radius or {}).get("blast_radius_review_sha256"),
    )


def _architecture_audit(root: Path, *, status: str, store: JsonStore) -> dict:
    pkg = root / "ams"
    pkg.mkdir(exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    if status == "deny":
        (pkg / "a.py").write_text("from . import b\n\ndef fa():\n    return b.fb()\n", encoding="utf-8")
        (pkg / "b.py").write_text("from . import a\n\ndef fb():\n    return a.fa()\n", encoding="utf-8")
    elif status == "defer":
        duplicate = "def same():\n    total = 1\n    total += 1\n    return total\n"
        (pkg / "a.py").write_text(duplicate, encoding="utf-8")
        (pkg / "b.py").write_text(duplicate, encoding="utf-8")
    else:
        (pkg / "a.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    return ArchitectureAuditStore(store).create(source_root=root, package_name="ams")


if __name__ == "__main__":
    unittest.main()
