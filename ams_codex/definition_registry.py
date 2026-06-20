from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


DEFAULT_DEFINITION_TIME = "2026-06-10T00:00:00Z"


def _record_hash(record: dict[str, Any]) -> str:
    material = deepcopy(record)
    for field in ("definition_sha256", "created_at", "updated_at"):
        material.pop(field, None)
    return sha256_text(canonical_json(material))


def _tool_ref(definition: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": definition["name"],
        "version": definition["version"],
        "definition_id": definition["definition_id"],
        "definition_sha256": definition["definition_sha256"],
    }


def _surface_ref(definition: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": definition["provider"],
        "surface": definition["surface"],
        "version": definition["version"],
        "definition_id": definition["definition_id"],
        "definition_sha256": definition["definition_sha256"],
    }


def definition_snapshot_sha256(
    *,
    tool_refs: list[dict[str, Any]],
    surface_ref: dict[str, Any] | None,
) -> str:
    return sha256_text(
        canonical_json(
            {
                "schema_version": "ams.ams_codex.definition_snapshot.v0",
                "tools": tool_refs,
                "surface": surface_ref,
            }
        )
    )


def build_tool_definition(
    *,
    name: str,
    version: str = "v0",
    scope: str = "local",
    tool_type: str = "local",
    runner: str | None = None,
    allowed_actions: list[str] | None = None,
    risk_flags: list[str] | None = None,
    egress_modes: list[str] | None = None,
    definition: dict[str, Any] | None = None,
    input_schema_sha256: str | None = None,
    signed_policy_sha256: str | None = None,
    status: str = "active",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    record = {
        "schema_version": "ams.ams_codex.tool_definition.v0",
        "definition_id": stable_id("tooldef", name, version),
        "name": name,
        "version": version,
        "scope": scope,
        "tool_type": tool_type,
        "runner": runner,
        "allowed_actions": allowed_actions or [],
        "risk_flags": risk_flags or [],
        "egress_modes": egress_modes or ["none"],
        "input_schema_sha256": input_schema_sha256,
        "signed_policy_sha256": signed_policy_sha256,
        "definition": definition or {},
        "status": status,
        "created_at": now,
        "updated_at": now,
    }
    record["definition_sha256"] = _record_hash(record)
    return record


def build_surface_definition(
    *,
    provider: str,
    surface: str,
    version: str = "v0",
    mode: str = "dry_run",
    endpoint: str | None = None,
    allowed_methods: list[str] | None = None,
    capabilities: list[str] | None = None,
    risk_flags: list[str] | None = None,
    requires_signed_policy: bool = True,
    requires_readback: bool = True,
    definition: dict[str, Any] | None = None,
    signed_policy_sha256: str | None = None,
    status: str = "active",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    record = {
        "schema_version": "ams.ams_codex.surface_definition.v0",
        "definition_id": stable_id("surfdef", provider, surface, version),
        "provider": provider,
        "surface": surface,
        "version": version,
        "mode": mode,
        "endpoint": endpoint,
        "allowed_methods": allowed_methods or [],
        "capabilities": capabilities or [],
        "risk_flags": risk_flags or [],
        "requires_signed_policy": requires_signed_policy,
        "requires_readback": requires_readback,
        "signed_policy_sha256": signed_policy_sha256,
        "definition": definition or {},
        "status": status,
        "created_at": now,
        "updated_at": now,
    }
    record["definition_sha256"] = _record_hash(record)
    return record


def default_tool_definitions() -> list[dict[str, Any]]:
    now = DEFAULT_DEFINITION_TIME
    return [
        build_tool_definition(
            name="Read",
            tool_type="filesystem",
            allowed_actions=["read"],
            definition={"description": "Read bounded workspace files through the agent runtime."},
            now=now,
        ),
        build_tool_definition(
            name="ShellReadOnly",
            tool_type="shell",
            allowed_actions=["read", "test"],
            risk_flags=["non_trivial"],
            definition={"description": "Run local shell commands that inspect or verify state."},
            now=now,
        ),
        build_tool_definition(
            name="Tests",
            tool_type="shell",
            allowed_actions=["test"],
            risk_flags=["non_trivial"],
            definition={"description": "Run local test suites or focused verification commands."},
            now=now,
        ),
        build_tool_definition(
            name="Edit",
            tool_type="filesystem",
            allowed_actions=["write"],
            risk_flags=["non_trivial"],
            definition={"description": "Edit workspace files through approved patch mechanisms."},
            now=now,
        ),
        build_tool_definition(
            name="ApplyPatch",
            tool_type="filesystem",
            allowed_actions=["write"],
            risk_flags=["non_trivial"],
            definition={"description": "Apply scoped patches to workspace files."},
            now=now,
        ),
        build_tool_definition(
            name="EgressOutbox",
            tool_type="egress",
            allowed_actions=["egress"],
            risk_flags=["egress"],
            egress_modes=["ams_outbox"],
            definition={"description": "Queue an AMS outbox item; never sends directly."},
            now=now,
        ),
        build_tool_definition(
            name="discord_client.send",
            tool_type="egress",
            allowed_actions=["egress"],
            risk_flags=["egress", "live_touch"],
            egress_modes=["direct"],
            definition={"description": "Direct Discord send path, disabled until signed live gate."},
            status="disabled",
            now=now,
        ),
    ]


def default_surface_definitions() -> list[dict[str, Any]]:
    now = DEFAULT_DEFINITION_TIME
    return [
        build_surface_definition(
            provider="openai_codex",
            surface="app-server",
            mode="dry_run",
            endpoint=None,
            allowed_methods=["thread/start", "thread/resume", "turn/start", "turn/steer"],
            capabilities=["code_worker", "bounded_runner"],
            risk_flags=["non_trivial"],
            requires_signed_policy=True,
            requires_readback=True,
            definition={"description": "Codex app-server envelope surface; local dry-run only here."},
            now=now,
        ),
        build_surface_definition(
            provider="anthropic_claude",
            surface="agent-sdk",
            mode="dry_run",
            endpoint=None,
            allowed_methods=["session/start", "session/resume"],
            capabilities=["verifier", "worker"],
            risk_flags=["non_trivial"],
            requires_signed_policy=True,
            requires_readback=True,
            definition={"description": "Claude Agent SDK request surface; local dry-run only here."},
            now=now,
        ),
        build_surface_definition(
            provider="local_ollama",
            surface="ollama-api",
            mode="dry_run",
            endpoint=None,
            allowed_methods=["generate", "chat"],
            capabilities=["local_model", "bounded_runner"],
            risk_flags=["non_trivial"],
            requires_signed_policy=True,
            requires_readback=True,
            definition={"description": "Local Ollama-compatible model surface; local dry-run only here."},
            now=now,
        ),
        build_surface_definition(
            provider="local_openai_compatible",
            surface="openai-compatible",
            mode="dry_run",
            endpoint=None,
            allowed_methods=["chat.completions", "responses", "embeddings"],
            capabilities=["local_model", "bounded_runner", "structured_output"],
            risk_flags=["non_trivial"],
            requires_signed_policy=True,
            requires_readback=True,
            definition={
                "description": "Generic loopback OpenAI-compatible local model surface for LM Studio, llama.cpp, vLLM, or similar runtimes."
            },
            now=now,
        ),
        build_surface_definition(
            provider="local_terminal",
            surface="terminal-capture",
            mode="dry_run",
            endpoint=None,
            allowed_methods=["capture", "read", "status"],
            capabilities=["human_visible_stream", "surface_capture"],
            risk_flags=["non_trivial"],
            requires_signed_policy=True,
            requires_readback=True,
            definition={
                "description": "Local terminal transcript capture surface; no injection or send-keys in v0."
            },
            now=now,
        ),
        build_surface_definition(
            provider="local_terminal",
            surface="tmux-pane",
            mode="dry_run",
            endpoint=None,
            allowed_methods=["capture", "read", "status"],
            capabilities=["human_visible_stream", "surface_capture"],
            risk_flags=["non_trivial"],
            requires_signed_policy=True,
            requires_readback=True,
            definition={
                "description": "Local tmux pane capture surface; no injection or send-keys in v0."
            },
            now=now,
        ),
        build_surface_definition(
            provider="discord",
            surface="ams_outbox",
            mode="shadow",
            endpoint=None,
            allowed_methods=["queue", "receipt", "readback"],
            capabilities=["egress_queue"],
            risk_flags=["egress"],
            requires_signed_policy=True,
            requires_readback=True,
            definition={"description": "AMS-owned Discord outbox/readback surface; no direct send."},
            now=now,
        ),
    ]


def default_registry() -> dict[str, Any]:
    return {
        "tool_definitions": {item["definition_id"]: item for item in default_tool_definitions()},
        "surface_definitions": {item["definition_id"]: item for item in default_surface_definitions()},
    }


def ensure_default_definitions_in_state(state: dict[str, Any]) -> dict[str, Any]:
    defaults = default_registry()
    installed = {"tool_definitions": [], "surface_definitions": []}
    for collection in ("tool_definitions", "surface_definitions"):
        target = state.setdefault(collection, {})
        for definition_id, definition in defaults[collection].items():
            if definition_id not in target:
                target[definition_id] = deepcopy(definition)
                installed[collection].append(definition_id)
    return installed


def resolve_definition_snapshot(
    state: dict[str, Any],
    *,
    provider: str,
    surface: str | None,
    tool_scope: list[str] | None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    tool_refs: list[dict[str, Any]] = []
    for tool in tool_scope or []:
        definition = find_tool_definition(state, tool)
        if not definition:
            reason_codes.append(f"definition.tool_missing:{tool}")
            continue
        if definition.get("status") != "active":
            reason_codes.append(f"definition.tool_not_active:{tool}")
            continue
        if definition.get("definition_sha256") != _record_hash(definition):
            reason_codes.append(f"definition.tool_hash_mismatch:{tool}")
            continue
        tool_refs.append(_tool_ref(definition))

    surface_ref = None
    if surface:
        surface_definition = find_surface_definition(state, provider, surface)
        if not surface_definition:
            reason_codes.append(f"definition.surface_missing:{provider}/{surface}")
        elif surface_definition.get("status") != "active":
            reason_codes.append(f"definition.surface_not_active:{provider}/{surface}")
        elif surface_definition.get("definition_sha256") != _record_hash(surface_definition):
            reason_codes.append(f"definition.surface_hash_mismatch:{provider}/{surface}")
        else:
            surface_ref = _surface_ref(surface_definition)
    else:
        reason_codes.append(f"definition.surface_missing:{provider}/None")

    return {
        "ok": not reason_codes,
        "reason_codes": reason_codes,
        "tool_definition_refs": tool_refs,
        "surface_definition_ref": surface_ref,
        "definition_snapshot_sha256": definition_snapshot_sha256(
            tool_refs=tool_refs,
            surface_ref=surface_ref,
        ) if not reason_codes else None,
    }


def pin_definitions_to_task_run(state: dict[str, Any], task_run: dict[str, Any]) -> dict[str, Any]:
    resolved = resolve_definition_snapshot(
        state,
        provider=str(task_run.get("provider") or ""),
        surface=task_run.get("provider_surface"),
        tool_scope=list(task_run.get("tool_scope") or []),
    )
    if not resolved["ok"]:
        raise ValueError("definition registry resolution failed: " + ",".join(resolved["reason_codes"]))
    task_run["tool_definition_refs"] = resolved["tool_definition_refs"]
    task_run["surface_definition_ref"] = resolved["surface_definition_ref"]
    task_run["definition_snapshot_sha256"] = resolved["definition_snapshot_sha256"]
    task_run["allowed_tools"] = [ref["name"] for ref in resolved["tool_definition_refs"]]
    return task_run


def validate_task_run_definition_pins(state: dict[str, Any], task_run: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    task_run_id = task_run.get("task_run_id")
    tool_scope = list(task_run.get("tool_scope") or [])
    refs = list(task_run.get("tool_definition_refs") or [])
    refs_by_name = {ref.get("name"): ref for ref in refs}
    for tool in tool_scope:
        ref = refs_by_name.get(tool)
        if not ref:
            reason_codes.append(f"definition.run_tool_unpinned:{tool}")
            continue
        definition = (state.get("tool_definitions") or {}).get(ref.get("definition_id"))
        if not definition:
            reason_codes.append(f"definition.run_tool_missing:{tool}")
            continue
        if definition.get("name") != tool:
            reason_codes.append(f"definition.run_tool_name_mismatch:{tool}")
        if definition.get("status") != "active":
            reason_codes.append(f"definition.run_tool_not_active:{tool}")
        actual_hash = _record_hash(definition)
        if definition.get("definition_sha256") != actual_hash:
            reason_codes.append(f"definition.tool_hash_mismatch:{tool}")
        if ref.get("definition_sha256") != definition.get("definition_sha256"):
            reason_codes.append(f"definition.run_tool_pin_mismatch:{tool}")

    if len(refs) != len(tool_scope):
        reason_codes.append(f"definition.run_tool_ref_count_mismatch:{task_run_id}")

    surface_ref = task_run.get("surface_definition_ref")
    provider = task_run.get("provider")
    surface = task_run.get("provider_surface")
    if surface:
        if not surface_ref:
            reason_codes.append(f"definition.run_surface_unpinned:{provider}/{surface}")
        else:
            definition = (state.get("surface_definitions") or {}).get(surface_ref.get("definition_id"))
            if not definition:
                reason_codes.append(f"definition.run_surface_missing:{provider}/{surface}")
            else:
                if definition.get("provider") != provider or definition.get("surface") != surface:
                    reason_codes.append(f"definition.run_surface_name_mismatch:{provider}/{surface}")
                if definition.get("status") != "active":
                    reason_codes.append(f"definition.run_surface_not_active:{provider}/{surface}")
                actual_hash = _record_hash(definition)
                if definition.get("definition_sha256") != actual_hash:
                    reason_codes.append(f"definition.surface_hash_mismatch:{provider}/{surface}")
                if surface_ref.get("definition_sha256") != definition.get("definition_sha256"):
                    reason_codes.append(f"definition.run_surface_pin_mismatch:{provider}/{surface}")

    expected_snapshot = definition_snapshot_sha256(tool_refs=refs, surface_ref=surface_ref)
    if task_run.get("definition_snapshot_sha256") != expected_snapshot:
        reason_codes.append(f"definition.run_snapshot_mismatch:{task_run_id}")
    return {
        "ok": not reason_codes,
        "reason_codes": reason_codes,
    }


def find_tool_definition(state: dict[str, Any], name: str) -> dict[str, Any] | None:
    matches = [
        definition for definition in (state.get("tool_definitions") or {}).values()
        if definition.get("name") == name
    ]
    if not matches:
        return None
    matches.sort(key=lambda item: str(item.get("version") or ""), reverse=True)
    return deepcopy(matches[0])


def find_surface_definition(state: dict[str, Any], provider: str, surface: str) -> dict[str, Any] | None:
    matches = [
        definition for definition in (state.get("surface_definitions") or {}).values()
        if definition.get("provider") == provider and definition.get("surface") == surface
    ]
    if not matches:
        return None
    matches.sort(key=lambda item: str(item.get("version") or ""), reverse=True)
    return deepcopy(matches[0])


class DefinitionRegistryStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def install_defaults(self) -> dict[str, Any]:
        with self.store.locked() as state:
            installed = ensure_default_definitions_in_state(state)
            summary = registry_summary(state)
        return {"installed": installed, "summary": summary}

    def status(self) -> dict[str, Any]:
        return registry_summary(self.store.load())


def registry_summary(state: dict[str, Any]) -> dict[str, Any]:
    tools = list((state.get("tool_definitions") or {}).values())
    surfaces = list((state.get("surface_definitions") or {}).values())
    active_tools = [item for item in tools if item.get("status") == "active"]
    active_surfaces = [item for item in surfaces if item.get("status") == "active"]
    return {
        "tool_definitions": len(tools),
        "surface_definitions": len(surfaces),
        "active_tools": len(active_tools),
        "active_surfaces": len(active_surfaces),
        "disabled_tools": sorted(item.get("name") for item in tools if item.get("status") == "disabled"),
        "surfaces": sorted(f"{item.get('provider')}/{item.get('surface')}:{item.get('mode')}" for item in surfaces),
    }
