from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ams_codex.context import ContextStore
from ams_codex.definition_registry import build_surface_definition
from ams_codex.resource_policy import build_default_resource_policy, evaluate_task_run
from ams_codex.run_trace import RunTraceStore
from ams_codex.session_registry import SessionRegistry
from ams_codex.store import JsonStore


def _task_run(provider: str = "openai_codex", surface: str = "app-server", tools: list[str] | None = None) -> dict:
    with tempfile.TemporaryDirectory() as td:
        store = JsonStore(Path(td) / "store.json")
        event = {"channel_id": "chan", "message_id": "root", "content": "build"}
        session, _ = SessionRegistry(store).ingest_event(event)
        context = ContextStore(store).create_for_event(session, event)
        if provider == "random_agent":
            state = store.load()
            surface_definition = build_surface_definition(
                provider="random_agent",
                surface=surface,
                allowed_methods=["run"],
                capabilities=["test_fixture"],
                requires_signed_policy=True,
                requires_readback=True,
            )
            state.setdefault("surface_definitions", {})[surface_definition["definition_id"]] = surface_definition
            store.save(state)
        return RunTraceStore(store).create_run(
            session["session_id"],
            context["context_id"],
            provider=provider,
            provider_surface=surface,
            model="qwen3-coder" if provider.startswith("local") else "gpt-5.5",
            tool_scope=tools or ["Read"],
        )


class ResourcePolicyTest(unittest.TestCase):
    def test_codex_task_run_is_allowed_by_default_policy(self) -> None:
        verdict = evaluate_task_run(_task_run(tools=["Read", "Edit"]), build_default_resource_policy())
        self.assertEqual(verdict["status"], "allow", verdict["reason_codes"])
        self.assertEqual(verdict["provider_profile_id"], "codex-app-server-default")

    def test_local_ollama_model_fits_when_read_only_and_capacity_available(self) -> None:
        verdict = evaluate_task_run(
            _task_run(provider="local_ollama", surface="ollama-api", tools=["Read"]),
            build_default_resource_policy(),
            current_usage={"available_local_resources": {"cpu_cores": 8, "memory_mb": 32768, "gpu_memory_mb": 24576}},
        )
        self.assertEqual(verdict["status"], "allow", verdict["reason_codes"])
        self.assertEqual(verdict["provider_profile_id"], "local-ollama-default")

    def test_local_model_cannot_request_write_tool_by_default(self) -> None:
        verdict = evaluate_task_run(
            _task_run(provider="local_ollama", surface="ollama-api", tools=["Read", "Edit"]),
            build_default_resource_policy(),
        )
        self.assertEqual(verdict["status"], "deny")
        self.assertIn("resource.tool_denied:Edit", verdict["reason_codes"])

    def test_local_openai_compatible_model_is_read_only_by_default(self) -> None:
        verdict = evaluate_task_run(
            _task_run(provider="local_openai_compatible", surface="openai-compatible", tools=["Read"]),
            build_default_resource_policy(),
            current_usage={"available_local_resources": {"cpu_cores": 8, "memory_mb": 32768, "gpu_memory_mb": 24576}},
        )
        self.assertEqual(verdict["status"], "allow", verdict["reason_codes"])
        self.assertEqual(verdict["provider_profile_id"], "local-openai-compatible-default")

    def test_unknown_provider_is_denied(self) -> None:
        verdict = evaluate_task_run(_task_run(provider="random_agent", surface="api"), build_default_resource_policy())
        self.assertEqual(verdict["status"], "deny")
        self.assertIn("resource.unknown_provider_profile", verdict["reason_codes"])

    def test_capacity_pressure_defers_instead_of_denies(self) -> None:
        verdict = evaluate_task_run(
            _task_run(provider="local_ollama", surface="ollama-api", tools=["Read"]),
            build_default_resource_policy(),
            current_usage={"available_local_resources": {"cpu_cores": 2, "memory_mb": 4096, "gpu_memory_mb": 1024}},
        )
        self.assertEqual(verdict["status"], "defer")
        self.assertIn("resource.insufficient_memory_mb", verdict["reason_codes"])

    def test_token_over_limit_is_denied(self) -> None:
        verdict = evaluate_task_run(
            _task_run(provider="local_ollama", surface="ollama-api", tools=["Read"]),
            build_default_resource_policy(),
            current_usage={"requested_input_tokens": 50000},
        )
        self.assertEqual(verdict["status"], "deny")
        self.assertIn("resource.input_tokens_over_limit", verdict["reason_codes"])


if __name__ == "__main__":
    unittest.main()
