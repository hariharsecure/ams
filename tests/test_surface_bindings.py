from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams.claude_adapter import ClaudeDryRunAdapter
from ams.codex_adapter import CodexDryRunAdapter
from ams.context import ContextStore
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.session_registry import SessionRegistry
from ams.store import JsonStore
from ams.surface_bindings import SurfaceBindingStore


class SurfaceBindingsTest(unittest.TestCase):
    def test_codex_runtime_surface_can_bind_to_provider_session(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            session = _session(store)
            session = CodexDryRunAdapter(store).bind_thread(session["session_id"], "codex-thread-1")
            surface = SurfaceBindingStore(store).declare_surface(
                provider="openai_codex",
                surface="app-server",
                runtime_name="studio-codex-app-server",
                transport="stdio",
                session_semantics="persistent_thread",
                capability_tier="builder",
            )

            binding = SurfaceBindingStore(store).bind_surface(
                runtime_surface_id=surface["runtime_surface_id"],
                session_id=session["session_id"],
                provider_session_id="codex-thread-1",
            )

            self.assertEqual(binding["provider"], "openai_codex")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_claude_runtime_surface_can_bind_to_provider_session(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            session = _session(store)
            session = ClaudeDryRunAdapter(store).bind_session(
                session["session_id"],
                "claude-session-1",
                claude_agent_id="claude-verifier-1",
            )
            surface = SurfaceBindingStore(store).declare_surface(
                provider="anthropic_claude",
                surface="agent-sdk",
                runtime_name="studio-claude-sdk",
                transport="stdio",
                session_semantics="resumable_session",
                capability_tier="verifier",
            )

            binding = SurfaceBindingStore(store).bind_surface(
                runtime_surface_id=surface["runtime_surface_id"],
                session_id=session["session_id"],
                provider_session_id="claude-session-1",
                binding_role="verifier",
            )

            self.assertEqual(binding["provider"], "anthropic_claude")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_local_model_endpoints_are_declared_without_probe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            bindings = SurfaceBindingStore(store)

            ollama = bindings.declare_surface(
                provider="local_ollama",
                surface="ollama-api",
                runtime_name="local-ollama",
                transport="localhost_http",
                endpoint="http://localhost:11434/v1",
                binding_kind="local_model_endpoint",
            )
            lm_studio = bindings.declare_surface(
                provider="local_openai_compatible",
                surface="openai-compatible",
                runtime_name="lm-studio",
                transport="localhost_http",
                endpoint="http://127.0.0.1:1234/v1",
                binding_kind="local_model_endpoint",
            )

            self.assertEqual(ollama["status"], "declared")
            self.assertEqual(lm_studio["status"], "declared")
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_terminal_tmux_surface_is_capture_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            surface = SurfaceBindingStore(store).declare_surface(
                provider="local_terminal",
                surface="tmux-pane",
                runtime_name="main-dev-pane",
                transport="tmux",
                endpoint="session:window.pane",
                binding_kind="human_surface",
                session_semantics="human_visible_stream",
            )

            self.assertTrue(surface["capture_only"])
            self.assertFalse(surface["inject_allowed"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_terminal_injection_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")

            with self.assertRaisesRegex(ValueError, "surface.runtime_terminal_injection_denied"):
                SurfaceBindingStore(store).declare_surface(
                    provider="local_terminal",
                    surface="tmux-pane",
                    runtime_name="unsafe-pane",
                    transport="tmux",
                    endpoint="session:window.pane",
                    binding_kind="human_surface",
                    session_semantics="human_visible_stream",
                    inject_allowed=True,
                )

    def test_provider_session_mismatch_fails_replay(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            session = _session(store)
            CodexDryRunAdapter(store).bind_thread(session["session_id"], "codex-thread-1")
            surface = SurfaceBindingStore(store).declare_surface(
                provider="openai_codex",
                surface="app-server",
                runtime_name="studio-codex-app-server",
                transport="stdio",
            )
            state = store.load()
            binding = {
                "schema_version": "ams.ams.surface_binding.v0",
                "surface_binding_id": "surfbind_bad",
                "runtime_surface_id": surface["runtime_surface_id"],
                "session_id": session["session_id"],
                "provider": "openai_codex",
                "surface": "app-server",
                "provider_session_id": "wrong-thread",
                "task_run_id": None,
                "binding_role": "worker",
                "status": "bound",
                "created_at": "2026-06-10T00:00:00Z",
                "updated_at": "2026-06-10T00:00:00Z",
                "surface_binding_sha256": "sha256:" + "0" * 64,
            }
            state.setdefault("surface_bindings", {})[binding["surface_binding_id"]] = binding
            store.save(state)

            result = ReplayChecker(store).check()

            self.assertFalse(result["ok"])
            self.assertIn("surface.binding_provider_session_mismatch", "\n".join(result["errors"]))

    def test_replay_oracle_covers_surface_records(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = JsonStore(Path(td) / "store.json")
            session = _session(store)
            surface = SurfaceBindingStore(store).declare_surface(
                provider="local_ollama",
                surface="ollama-api",
                runtime_name="local-ollama",
                transport="localhost_http",
                endpoint="http://localhost:11434/v1",
                binding_kind="local_model_endpoint",
            )
            SurfaceBindingStore(store).bind_surface(
                runtime_surface_id=surface["runtime_surface_id"],
                session_id=session["session_id"],
                binding_role="observer",
            )

            result = ReplayOracle(store).check()

            surface_misses = [
                miss for miss in result["misses"]
                if miss["collection"] in {"runtime_surfaces", "surface_bindings"}
            ]
            self.assertEqual(surface_misses, [])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("runtime_surfaces", collections)
            self.assertIn("surface_bindings", collections)


def _session(store: JsonStore) -> dict:
    event = {"channel_id": "chan", "message_id": "root", "content": "build"}
    session, _ = SessionRegistry(store).ingest_event(event)
    ContextStore(store).create_for_event(session, event)
    return session


if __name__ == "__main__":
    unittest.main()
