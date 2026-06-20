from __future__ import annotations

import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from ams.admission import AdmissionReviewStore
from ams.outbox import OutboxStore
from ams.replay import ReplayChecker
from ams.simulation import run_full_simulation
from ams.store import JsonStore
from ams.surface_promise import SurfacePromiseStore


class SurfacePromiseTest(unittest.TestCase):
    def test_readback_verified_outbox_satisfies_surface_promise(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            result = _completed_run(store)

            promise = SurfacePromiseStore(store).create(
                result["task_run_id"],
                promised_surfaces=[
                    {
                        "surface": "discord",
                        "target": "discord",
                        "channel_id": "chan",
                        "outbox_id": result["outbox_id"],
                        "required": True,
                        "required_readback": True,
                    }
                ],
                source_packet_ref="source-packet://q183",
                promise_reason="milestone_post_promised",
            )

            self.assertEqual(promise["surface_delivery_status"], "delivered_and_readback_verified")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_completed_task_with_missing_promised_surface_fails_replay(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            result = _completed_run(store)

            promise = SurfacePromiseStore(store).create(
                result["task_run_id"],
                promised_surfaces=[
                    {
                        "surface": "discord",
                        "target": "discord",
                        "channel_id": "missing-channel",
                        "required": True,
                        "required_readback": True,
                    }
                ],
                promise_reason="q184_q185_surface_delivery_regression",
            )
            replay = ReplayChecker(store).check()

            self.assertEqual(promise["surface_delivery_status"], "surface_promise_mismatch")
            self.assertFalse(replay["ok"])
            self.assertIn("surface_promise.terminal_task_missing_surface_delivery", "\n".join(replay["errors"]))

    def test_deferred_outbox_with_reason_is_acceptable_blocked_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            result = _completed_run(store)
            review = AdmissionReviewStore(store).create(
                subject_kind="task_run",
                subject_id=result["task_run_id"],
                operation="egress.discord",
                request={"target": "discord", "channel_id": "deferred-chan"},
                status="defer",
                reason_codes=["publisher_paused"],
            )
            item = OutboxStore(store).create_item(
                result["task_run_id"],
                target="discord",
                channel_id="deferred-chan",
                endpoint="/channels/deferred-chan/messages",
                payload={"content": "deferred"},
                admission_review_id=review["admission_review_id"],
            )
            OutboxStore(store).record_receipt(
                item["outbox_id"],
                status="deferred",
                reason_codes=["publisher_paused"],
            )

            promise = SurfacePromiseStore(store).create(
                result["task_run_id"],
                promised_surfaces=[
                    {
                        "surface": "discord",
                        "target": "discord",
                        "channel_id": "deferred-chan",
                        "outbox_id": item["outbox_id"],
                        "required": True,
                        "required_readback": True,
                    }
                ],
            )

            self.assertEqual(promise["surface_delivery_status"], "blocked_with_reason_and_deferred")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_rejects_sent_receipt_without_readback_or_provider_message(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            result = _completed_run(store)
            state = store.load()
            outbox_id = result["outbox_id"]
            receipt_id = result["receipt_id"]
            bad_receipt = deepcopy(state["outbox_receipts"][receipt_id])
            bad_receipt["readback_ref"] = None
            bad_receipt["response_payload"] = {}
            bad_receipt["response_sha256"] = "sha256:" + "0" * 64
            bad_receipt["receipt_sha256"] = "sha256:" + "0" * 64
            state["outbox_receipts"][receipt_id] = bad_receipt
            state["outbox_items"][outbox_id]["outbox_sha256"] = state["outbox_items"][outbox_id]["outbox_sha256"]
            store.save(state)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("missing readback/provider message id", "\n".join(replay["errors"]))


def _completed_run(store: JsonStore) -> dict:
    return run_full_simulation(
        {"channel_id": "chan", "message_id": "root", "content": "build"},
        store,
    )


if __name__ == "__main__":
    unittest.main()
