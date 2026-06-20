from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.admission import AdmissionReviewStore
from ams.ams_event import AMSEventStore
from ams.capability_policy import build_capability_request, evaluate_capability_request
from ams.context import ContextStore
from ams.outbox import OutboxStore
from ams.replay import ReplayChecker
from ams.resource_claim import ResourceClaimStore
from ams.run_trace import RunTraceStore
from ams.session_registry import SessionRegistry
from ams.store import JsonStore


def _session_context_run(store: JsonStore) -> tuple[dict, dict, dict]:
    event = {"channel_id": "chan", "message_id": "root", "content": "build"}
    session, _ = SessionRegistry(store).ingest_event(event)
    context = ContextStore(store).create_for_event(session, event)
    task_run = RunTraceStore(store).create_run(
        session["session_id"],
        context["context_id"],
        model="gpt-5.5",
        tool_scope=["Read"],
    )
    return session, context, task_run


class M8FContractsTest(unittest.TestCase):
    def test_ams_event_is_hash_checked_and_linked(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            session, _, task_run = _session_context_run(store)
            event = AMSEventStore(store).append(
                event_type="ams.task_run.planned",
                source="ams://local/test",
                subject=task_run["task_run_id"],
                data={"state": "planned"},
                session_id=session["session_id"],
                task_run_id=task_run["task_run_id"],
            )
            self.assertEqual(event["specversion"], "1.0")
            self.assertTrue(event["event_sha256"].startswith("sha256:"))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_admission_review_wraps_capability_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            _, _, task_run = _session_context_run(store)
            request = build_capability_request(
                tier="builder",
                action="write",
                paths=["tests/test_new_behavior.py"],
                tools=["ApplyPatch"],
            )
            verdict = evaluate_capability_request(request)
            review = AdmissionReviewStore(store).create(
                subject_kind="task_run",
                subject_id=task_run["task_run_id"],
                operation="capability.write",
                request=request,
                verdict=verdict,
            )
            self.assertTrue(review["response"]["allowed"])
            self.assertEqual(review["response"]["status"], "allow")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_resource_claim_reserve_activate_release(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            _, _, task_run = _session_context_run(store)
            result = ResourceClaimStore(store).reserve(task_run["task_run_id"])
            self.assertTrue(result["reserved"], result["verdict"])
            claim = result["claim"]
            self.assertEqual(claim["state"], "reserved")
            active = ResourceClaimStore(store).transition(claim["resource_claim_id"], "active")
            self.assertEqual(active["state"], "active")
            released = ResourceClaimStore(store).transition(claim["resource_claim_id"], "released")
            self.assertEqual(released["state"], "released")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_rejects_dispatched_run_without_resource_claim(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            _, _, task_run = _session_context_run(store)
            RunTraceStore(store).append_event(task_run["task_run_id"], "run.dispatch_intent")
            RunTraceStore(store).append_event(task_run["task_run_id"], "run.dispatched")
            result = ReplayChecker(store).check()
            self.assertFalse(result["ok"])
            self.assertIn("without resource_claim", "\n".join(result["errors"]))

    def test_outbox_item_and_receipt_are_hash_checked(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            _, _, task_run = _session_context_run(store)
            review = AdmissionReviewStore(store).create(
                subject_kind="task_run",
                subject_id=task_run["task_run_id"],
                operation="egress.discord",
                request={"target": "discord", "channel_id": "chan"},
                status="allow",
                reason_codes=["dry_run"],
            )
            item = OutboxStore(store).create_item(
                task_run["task_run_id"],
                channel_id="chan",
                endpoint="/channels/chan/messages",
                payload={"content": "dry run"},
                admission_review_id=review["admission_review_id"],
            )
            self.assertEqual(item["state"], "queued")
            receipt = OutboxStore(store).record_receipt(
                item["outbox_id"],
                status="readback_verified",
                response_payload={"message_id": "msg-1"},
                readback_ref="discord://chan/msg-1",
            )
            self.assertEqual(receipt["status"], "readback_verified")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_sent_outbox_receipt_requires_readback_and_message_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            _, _, task_run = _session_context_run(store)
            item = OutboxStore(store).create_item(
                task_run["task_run_id"],
                channel_id="chan",
                endpoint="/channels/chan/messages",
                payload={"content": "dry run"},
            )
            with self.assertRaises(ValueError):
                OutboxStore(store).record_receipt(
                    item["outbox_id"],
                    status="sent",
                    response_payload={"message_id": None},
                    readback_ref=None,
                )


if __name__ == "__main__":
    unittest.main()
