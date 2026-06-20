from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.models import content_hash
from ams_codex.replay import ReplayChecker
from ams_codex.replay_oracle import ReplayOracle
from ams_codex.store import JsonStore
from ams_codex.terminal_source import TerminalSourcePacketStore


class TerminalSourcePacketTest(unittest.TestCase):
    def test_read_only_tmux_source_packet_creates_attention_signal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            content = "tmux pane shows Codex terminal compaction warning; user is waiting for AMS status"

            packet = TerminalSourcePacketStore(store).create(
                {
                    "source_surface": "tmux",
                    "terminal_session_id": "codex-a305",
                    "tmux_session_name": "codex-a305",
                    "tmux_window_id": "win-1",
                    "tmux_pane_id": "pane-2",
                    "source_event_id": "evt-terminal-1",
                    "source_actor": "operator",
                    "observed_at": "2026-06-12T00:00:00Z",
                    "content": content,
                    "summary": "tmux terminal pane reports Codex compaction warning and waiting status.",
                    "artifact_refs": [
                        {
                            "ref": "local://terminal/tmux/codex-a305/pane-2",
                            "kind": "transcript_excerpt_hash",
                            "sha256": "sha256:" + "8" * 64,
                        }
                    ],
                },
                create_attention_signal=True,
            )

            self.assertEqual(packet["status"], "ready_for_attention")
            self.assertTrue(packet["attention_signal_created"])
            self.assertEqual(packet["source_surface"], "tmux")
            self.assertTrue(packet["source_ref"].startswith("tmux://codex-a305/"))
            self.assertFalse(packet["monitor_started"])
            self.assertFalse(packet["attach_performed"])
            self.assertFalse(packet["capture_performed"])
            self.assertFalse(packet["command_input_allowed"])
            self.assertFalse(packet["keystroke_injection_allowed"])
            self.assertFalse(packet["process_signal_allowed"])
            self.assertFalse(packet["token_stored"])
            self.assertFalse(packet["raw_content_stored"])
            self.assertEqual(packet["content_sha256"], content_hash(content))
            self.assertEqual(packet["artifact_count"], 1)
            state = store.load()
            signal = state["attention_signals"][packet["attention_signal_id"]]
            self.assertEqual(signal["source_ref"], packet["source_ref"])
            self.assertEqual(signal["route_domain"], "surface_terminal")
            self.assertFalse(signal["raw_content_stored"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_tmux_source_packet_prioritizes_terminal_domain_with_ams_context(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            packet = TerminalSourcePacketStore(store).create(
                {
                    "source_surface": "tmux",
                    "terminal_session_id": "codex-a305",
                    "tmux_session_name": "codex-a305",
                    "tmux_window_id": "win-1",
                    "tmux_pane_id": "pane-2",
                    "source_event_id": "evt-terminal-ams-context",
                    "content_sha256": "sha256:" + "7" * 64,
                    "summary": "tmux terminal pane reports Codex compaction warning and AMS status request.",
                },
                create_attention_signal=True,
            )

            state = store.load()
            signal = state["attention_signals"][packet["attention_signal_id"]]
            self.assertEqual(signal["route_domain"], "surface_terminal")
            self.assertIn("ams_kernel", signal["additional_domains"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_injection_or_secret_fields_block_without_storing_values(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            packet = TerminalSourcePacketStore(store).create(
                {
                    "source_surface": "terminal",
                    "terminal_session_id": "local-shell",
                    "source_event_id": "evt-terminal-2",
                    "content_sha256": "sha256:" + "9" * 64,
                    "summary": "Terminal source packet with forbidden live-control fields.",
                    "send_keys": "do-not-send-this",
                    "token": "do-not-store-this",
                    "process_signal": "SIGKILL",
                },
                create_attention_signal=True,
            )

            self.assertEqual(packet["status"], "blocked")
            self.assertFalse(packet["attention_signal_created"])
            self.assertFalse(packet["command_input_allowed"])
            self.assertFalse(packet["keystroke_injection_allowed"])
            self.assertFalse(packet["process_signal_allowed"])
            self.assertEqual(packet["forbidden_secret_key_count"], 1)
            self.assertEqual(packet["forbidden_injection_key_count"], 2)
            serialized = str(packet)
            self.assertNotIn("do-not-send-this", serialized)
            self.assertNotIn("do-not-store-this", serialized)
            self.assertIn("terminal_source.blocked_secret_field_present", packet["reason_codes"])
            self.assertIn("terminal_source.blocked_injection_field_present", packet["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_invalid_source_surface_blocks_as_terminal_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            packet = TerminalSourcePacketStore(store).create(
                {
                    "source_surface": "ssh",
                    "terminal_session_id": "remote-shell",
                    "source_event_id": "evt-terminal-3",
                    "content_sha256": "sha256:" + "a" * 64,
                    "summary": "Invalid source surface should be blocked without schema failure.",
                }
            )

            self.assertEqual(packet["status"], "blocked")
            self.assertEqual(packet["source_surface"], "terminal")
            self.assertIn("terminal_source.blocked_source_surface_invalid", packet["reason_codes"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_catches_injection_flag_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            packet = TerminalSourcePacketStore(store).create(
                {
                    "source_surface": "terminal",
                    "terminal_session_id": "local-shell",
                    "source_event_id": "evt-terminal-4",
                    "content_sha256": "sha256:" + "b" * 64,
                    "summary": "Terminal source packet for tamper test.",
                }
            )
            state = store.load()
            state["terminal_source_packets"][packet["terminal_source_packet_id"]]["keystroke_injection_allowed"] = True
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("terminal_source.keystroke_injection_allowed_not_false", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_terminal_source_packets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            TerminalSourcePacketStore(store).create(
                {
                    "source_surface": "terminal",
                    "terminal_session_id": "local-shell",
                    "source_event_id": "evt-terminal-5",
                    "content_sha256": "sha256:" + "c" * 64,
                    "summary": "Terminal source packet for oracle coverage.",
                }
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("terminal_source_packets", collections)


if __name__ == "__main__":
    unittest.main()
