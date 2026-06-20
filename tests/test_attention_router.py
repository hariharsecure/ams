from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.attention_router import AttentionRouterStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.session_registry import SessionRegistry
from ams.store import JsonStore


class AttentionRouterTest(unittest.TestCase):
    def test_a305_training_failure_routes_to_training_ops_with_ack_and_vector_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            signal = AttentionRouterStore(store).ingest(
                {
                    "source_surface": "claude_code",
                    "source_kind": "transcript_observation",
                    "claude_session_id": "43cd35cb-888c-4888-8a26-e230a2fba305",
                    "source_event_id": "15413",
                    "observed_at": "2026-06-10T20:25:00Z",
                    "content": (
                        "Track-A failed around 13:24 UTC and did not auto-requeue; "
                        "SIGUSR1 hit durable checkpoint rsync causing broken pipe."
                    ),
                }
            )

            self.assertEqual(signal["route_domain"], "training_ops")
            self.assertIn("resource_capacity", signal["additional_domains"])
            self.assertEqual(signal["priority"], "P1")
            self.assertEqual(signal["route_status"], "needs_ack")
            self.assertTrue(signal["ack_required"])
            self.assertEqual(signal["vector_memory"]["collection"], "ams_attention_training_ops")
            self.assertEqual(signal["vector_memory"]["authority"], "ams_store")
            self.assertFalse(signal["raw_content_stored"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_a305_discord_order_probe_routes_to_surface_discord_session(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            session, _ = SessionRegistry(store).ingest_event(
                {
                    "channel_id": "000000000000000002",
                    "message_id": "root-channel-b",
                    "content": "channel-b root",
                    "attention_id": "attn-channel-b",
                }
            )

            signal = AttentionRouterStore(store).ingest(
                {
                    "channel_id": "000000000000000002",
                    "message_id": "000000000000000004",
                    "root_message_id": "root-channel-b",
                    "author_id": "000000000000000005",
                    "received_at": "2026-06-10T20:31:33Z",
                    "content": (
                        "if this message go to you before the message on channel-b, "
                        "something need to have RCA @OPERATOR-AUTHORED @ROUTE-A"
                    ),
                }
            )

            self.assertEqual(signal["session_id"], session["session_id"])
            self.assertEqual(signal["attention_id"], "attn-channel-b")
            self.assertEqual(signal["route_domain"], "surface_discord")
            self.assertEqual(signal["priority"], "P1")
            self.assertEqual(signal["vector_memory"]["metadata"]["domain"], "surface_discord")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_poultry_welfare_signal_routes_to_farm_domains_with_p0_ack(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            signal = AttentionRouterStore(store).ingest(
                {
                    "source_surface": "farm_gateway",
                    "source_kind": "device_alarm",
                    "source_ref": "farm-gateway://site-a/house-2/alarm-771",
                    "source_event_id": "alarm-771",
                    "observed_at": "2026-06-12T13:40:00Z",
                    "content": (
                        "House 2 poultry flock has no water after gateway restart; "
                        "telemetry gap and water outage need immediate operator ack."
                    ),
                }
            )

            self.assertEqual(signal["route_domain"], "animal_welfare")
            self.assertIn("cyber_physical_ops", signal["additional_domains"])
            self.assertEqual(signal["priority"], "P0")
            self.assertEqual(signal["route_status"], "needs_ack")
            self.assertTrue(signal["ack_required"])
            self.assertEqual(signal["vector_memory"]["collection"], "ams_attention_animal_welfare")
            self.assertIn("attention.importance.cyber_physical_safety", signal["reason_codes"])
            self.assertIn("attention.urgency.cyber_physical_safety", signal["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_attention_signal_hash_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            signal = AttentionRouterStore(store).ingest(
                {
                    "source_surface": "discord",
                    "source_ref": "discord://chan/msg",
                    "content": "gateway.disconnect on tracked channel needs RCA",
                }
            )
            state = store.load()
            state["attention_signals"][signal["attention_signal_id"]]["priority"] = "P3"
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("attention_signal.hash_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_attention_signals(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            AttentionRouterStore(store).ingest(
                {
                    "source_surface": "manual",
                    "source_ref": "manual://attention-test",
                    "content": "AMS replay gate status update please",
                }
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("attention_signals", collections)


if __name__ == "__main__":
    unittest.main()
