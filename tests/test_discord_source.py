from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.discord_source import DiscordSourcePacketStore
from ams_codex.models import content_hash
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore


class DiscordSourcePacketTest(unittest.TestCase):
    def test_read_only_discord_source_packet_creates_attention_signal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            packet = DiscordSourcePacketStore(store).create(
                {
                    "channel_id": "000000000000000002",
                    "message_id": "000000000000000004",
                    "root_message_id": "root-channel-b",
                    "author_id": "000000000000000005",
                    "received_at": "2026-06-11T21:15:00Z",
                    "content": "Discord order probe needs RCA @OPERATOR-AUTHORED @ROUTE-A",
                    "summary": "Discord message ordering probe needs RCA and route-a attention.",
                    "attachments": [
                        {
                            "id": "att-1",
                            "content_type": "image/png",
                            "size": 1234,
                            "sha256": "sha256:" + "1" * 64,
                        }
                    ],
                },
                create_attention_signal=True,
            )

            self.assertEqual(packet["status"], "ready_for_attention")
            self.assertTrue(packet["attention_signal_created"])
            self.assertFalse(packet["send_allowed"])
            self.assertFalse(packet["gateway_started"])
            self.assertFalse(packet["bulk_history_allowed"])
            self.assertFalse(packet["token_stored"])
            self.assertFalse(packet["raw_content_stored"])
            self.assertEqual(packet["content_sha256"], content_hash("Discord order probe needs RCA @OPERATOR-AUTHORED @ROUTE-A"))
            self.assertEqual(packet["attachment_count"], 1)
            state = store.load()
            signal = state["attention_signals"][packet["attention_signal_id"]]
            self.assertEqual(signal["source_ref"], packet["source_ref"])
            self.assertEqual(signal["route_domain"], "surface_discord")
            self.assertFalse(signal["raw_content_stored"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_send_or_secret_fields_block_without_storing_values(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            packet = DiscordSourcePacketStore(store).create(
                {
                    "channel_id": "chan",
                    "message_id": "msg",
                    "content_sha256": "sha256:" + "2" * 64,
                    "summary": "Discord source packet with forbidden live fields.",
                    "send_allowed": True,
                    "bot_token": "do-not-store-this",
                    "webhook_url": "https://discord.example.invalid/webhook",
                },
                create_attention_signal=True,
            )

            self.assertEqual(packet["status"], "blocked")
            self.assertFalse(packet["attention_signal_created"])
            self.assertFalse(packet["send_allowed"])
            self.assertFalse(packet["token_stored"])
            self.assertEqual(packet["forbidden_secret_key_count"], 1)
            self.assertEqual(packet["forbidden_send_key_count"], 2)
            serialized = str(packet)
            self.assertNotIn("do-not-store-this", serialized)
            self.assertNotIn("discord.example.invalid", serialized)
            self.assertIn("discord_source.blocked_secret_field_present", packet["reason_codes"])
            self.assertIn("discord_source.blocked_send_field_present", packet["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_read_only_flag_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            packet = DiscordSourcePacketStore(store).create(
                {
                    "channel_id": "chan",
                    "message_id": "msg",
                    "content_sha256": "sha256:" + "3" * 64,
                    "summary": "Discord source packet for tamper test.",
                }
            )
            state = store.load()
            state["discord_source_packets"][packet["discord_source_packet_id"]]["send_allowed"] = True
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("discord_source.send_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_discord_source_packets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            DiscordSourcePacketStore(store).create(
                {
                    "channel_id": "chan",
                    "message_id": "msg",
                    "content_sha256": "sha256:" + "4" * 64,
                    "summary": "Discord source packet for oracle coverage.",
                }
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("discord_source_packets", collections)


if __name__ == "__main__":
    unittest.main()
