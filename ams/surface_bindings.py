from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .definition_registry import (
    _record_hash,
    ensure_default_definitions_in_state,
    find_surface_definition,
)
from .models import canonical_json, sha256_text, stable_id, utc_now
from .provider_bindings import find_provider_session
from .store import JsonStore
from .workspace import workspace_root


ALLOWED_EGRESS_MODES = {"none", "ams_outbox"}
LOCALHOST_NAMES = {"localhost", "127.0.0.1", "::1"}
TERMINAL_SURFACES = {("local_terminal", "tmux-pane"), ("local_terminal", "terminal-capture")}


def _surface_ref(definition: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": definition["provider"],
        "surface": definition["surface"],
        "version": definition["version"],
        "definition_id": definition["definition_id"],
        "definition_sha256": definition["definition_sha256"],
    }


def _record_sha(record: dict[str, Any], hash_field: str) -> str:
    material = deepcopy(record)
    material.pop(hash_field, None)
    return sha256_text(canonical_json(material))


def build_runtime_surface(
    state: dict[str, Any],
    *,
    provider: str,
    surface: str,
    runtime_name: str,
    transport: str,
    endpoint: str | None = None,
    binding_kind: str = "provider_runtime",
    rollout_mode: str = "dry_run",
    status: str = "declared",
    process_owner: str = "external",
    capability_tier: str = "observer",
    resource_profile_id: str | None = None,
    workspace_roots: list[str] | None = None,
    egress_modes: list[str] | None = None,
    session_semantics: str = "stateless",
    inject_allowed: bool = False,
    approval_id: str | None = None,
    package_manifest_sha256: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    surface_definition = find_surface_definition(state, provider, surface)
    if not surface_definition:
        raise ValueError(f"surface.runtime_definition_missing:{provider}/{surface}")
    if surface_definition.get("status") != "active":
        raise ValueError(f"surface.runtime_definition_not_active:{provider}/{surface}")
    if surface_definition.get("definition_sha256") != _record_hash(surface_definition):
        raise ValueError(f"surface.runtime_definition_hash_mismatch:{provider}/{surface}")

    record = {
        "schema_version": "ams.ams.runtime_surface.v0",
        "runtime_surface_id": stable_id(
            "rtsurf",
            provider,
            surface,
            runtime_name,
            transport,
            endpoint,
            rollout_mode,
        ),
        "runtime_name": runtime_name,
        "binding_kind": binding_kind,
        "provider": provider,
        "surface": surface,
        "surface_definition_ref": _surface_ref(surface_definition),
        "transport": transport,
        "endpoint": endpoint,
        "rollout_mode": rollout_mode,
        "status": status,
        "process_owner": process_owner,
        "capability_tier": capability_tier,
        "resource_profile_id": resource_profile_id,
        "workspace_roots": workspace_roots or [workspace_root()],
        "egress_modes": egress_modes or ["none"],
        "session_semantics": session_semantics,
        "surface_binding_ids": [],
        "capture_only": (provider, surface) in TERMINAL_SURFACES,
        "inject_allowed": inject_allowed,
        "approval_id": approval_id,
        "package_manifest_sha256": package_manifest_sha256,
        "created_at": now,
        "updated_at": now,
    }
    validation = validate_runtime_surface_record(record, state=state)
    if not validation["ok"]:
        raise ValueError("runtime surface invalid: " + ",".join(validation["reason_codes"]))
    record["runtime_surface_sha256"] = _record_sha(record, "runtime_surface_sha256")
    return record


def build_surface_binding(
    state: dict[str, Any],
    *,
    runtime_surface_id: str,
    session_id: str,
    provider_session_id: str | None = None,
    task_run_id: str | None = None,
    binding_role: str = "worker",
    status: str = "bound",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    runtime_surface = (state.get("runtime_surfaces") or {}).get(runtime_surface_id)
    if not runtime_surface:
        raise ValueError(f"surface.binding_runtime_missing:{runtime_surface_id}")
    record = {
        "schema_version": "ams.ams.surface_binding.v0",
        "surface_binding_id": stable_id(
            "surfbind",
            runtime_surface_id,
            session_id,
            provider_session_id,
            task_run_id,
            binding_role,
        ),
        "runtime_surface_id": runtime_surface_id,
        "session_id": session_id,
        "provider": runtime_surface.get("provider"),
        "surface": runtime_surface.get("surface"),
        "provider_session_id": provider_session_id,
        "task_run_id": task_run_id,
        "binding_role": binding_role,
        "status": status,
        "created_at": now,
        "updated_at": now,
    }
    validation = validate_surface_binding_record(record, state=state)
    if not validation["ok"]:
        raise ValueError("surface binding invalid: " + ",".join(validation["reason_codes"]))
    record["surface_binding_sha256"] = _record_sha(record, "surface_binding_sha256")
    return record


def validate_runtime_surface_record(record: dict[str, Any], *, state: dict[str, Any] | None = None) -> dict[str, Any]:
    reason_codes: list[str] = []
    provider = str(record.get("provider") or "")
    surface = str(record.get("surface") or "")
    endpoint = record.get("endpoint")
    rollout_mode = str(record.get("rollout_mode") or "")

    if rollout_mode not in {"dry_run", "shadow"}:
        reason_codes.append("surface.runtime_live_rollout_requires_approval")
    if any(mode not in ALLOWED_EGRESS_MODES for mode in record.get("egress_modes") or []):
        reason_codes.append("surface.runtime_direct_egress_denied")
    if (provider, surface) in TERMINAL_SURFACES and record.get("inject_allowed"):
        reason_codes.append("surface.runtime_terminal_injection_denied")
    for root in record.get("workspace_roots") or []:
        if not _path_under_workspace(str(root)):
            reason_codes.append("surface.runtime_workspace_root_outside_ams")
    if endpoint and not _endpoint_is_local(str(endpoint), str(record.get("transport") or "")):
        reason_codes.append("surface.runtime_endpoint_not_local")

    if state is not None:
        surface_ref = record.get("surface_definition_ref") or {}
        definition = (state.get("surface_definitions") or {}).get(surface_ref.get("definition_id"))
        if not definition:
            reason_codes.append(f"surface.runtime_definition_missing:{provider}/{surface}")
        else:
            if definition.get("provider") != provider or definition.get("surface") != surface:
                reason_codes.append(f"surface.runtime_definition_ref_mismatch:{provider}/{surface}")
            if definition.get("status") != "active":
                reason_codes.append(f"surface.runtime_definition_not_active:{provider}/{surface}")
            actual_hash = _record_hash(definition)
            if definition.get("definition_sha256") != actual_hash:
                reason_codes.append(f"surface.runtime_definition_hash_mismatch:{provider}/{surface}")
            if surface_ref.get("definition_sha256") != definition.get("definition_sha256"):
                reason_codes.append(f"surface.runtime_definition_pin_mismatch:{provider}/{surface}")
        for binding_id in record.get("surface_binding_ids") or []:
            binding = (state.get("surface_bindings") or {}).get(binding_id)
            if not binding:
                reason_codes.append(f"surface.runtime_binding_missing:{binding_id}")
            elif binding.get("runtime_surface_id") != record.get("runtime_surface_id"):
                reason_codes.append(f"surface.runtime_binding_backref_mismatch:{binding_id}")

    expected_hash = record.get("runtime_surface_sha256")
    if expected_hash and expected_hash != _record_sha(record, "runtime_surface_sha256"):
        reason_codes.append("surface.runtime_hash_mismatch")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def validate_surface_binding_record(record: dict[str, Any], *, state: dict[str, Any] | None = None) -> dict[str, Any]:
    reason_codes: list[str] = []
    if state is not None:
        runtime_surface = (state.get("runtime_surfaces") or {}).get(record.get("runtime_surface_id"))
        if not runtime_surface:
            reason_codes.append(f"surface.binding_runtime_missing:{record.get('runtime_surface_id')}")
        else:
            if runtime_surface.get("provider") != record.get("provider"):
                reason_codes.append("surface.binding_provider_mismatch")
            if runtime_surface.get("surface") != record.get("surface"):
                reason_codes.append("surface.binding_surface_mismatch")
            runtime_validation = validate_runtime_surface_record(runtime_surface, state=state)
            reason_codes.extend(runtime_validation["reason_codes"])

        session = (state.get("sessions") or {}).get(record.get("session_id"))
        if not session:
            reason_codes.append(f"surface.binding_session_missing:{record.get('session_id')}")
        task_run_id = record.get("task_run_id")
        if task_run_id:
            task_run = (state.get("task_runs") or {}).get(task_run_id)
            if not task_run:
                reason_codes.append(f"surface.binding_task_run_missing:{task_run_id}")
            elif task_run.get("session_id") != record.get("session_id"):
                reason_codes.append("surface.binding_task_run_session_mismatch")
        provider_session_id = record.get("provider_session_id")
        if provider_session_id and session:
            matched = find_provider_session(
                session,
                str(record.get("provider") or ""),
                record.get("surface"),
            )
            if not matched or matched.get("provider_session_id") != provider_session_id:
                reason_codes.append("surface.binding_provider_session_mismatch")

    expected_hash = record.get("surface_binding_sha256")
    if expected_hash and expected_hash != _record_sha(record, "surface_binding_sha256"):
        reason_codes.append("surface.binding_hash_mismatch")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def surface_status(state: dict[str, Any]) -> dict[str, Any]:
    runtime_surfaces = list((state.get("runtime_surfaces") or {}).values())
    surface_bindings = list((state.get("surface_bindings") or {}).values())
    return {
        "runtime_surfaces": len(runtime_surfaces),
        "surface_bindings": len(surface_bindings),
        "surfaces": sorted(
            [
                {
                    "runtime_surface_id": item.get("runtime_surface_id"),
                    "runtime_name": item.get("runtime_name"),
                    "provider": item.get("provider"),
                    "surface": item.get("surface"),
                    "transport": item.get("transport"),
                    "endpoint": item.get("endpoint"),
                    "rollout_mode": item.get("rollout_mode"),
                    "status": item.get("status"),
                    "binding_count": len(item.get("surface_binding_ids") or []),
                    "capture_only": item.get("capture_only"),
                    "inject_allowed": item.get("inject_allowed"),
                }
                for item in runtime_surfaces
            ],
            key=lambda item: str(item.get("runtime_surface_id") or ""),
        ),
        "bindings": sorted(
            [
                {
                    "surface_binding_id": item.get("surface_binding_id"),
                    "runtime_surface_id": item.get("runtime_surface_id"),
                    "session_id": item.get("session_id"),
                    "provider_session_id": item.get("provider_session_id"),
                    "task_run_id": item.get("task_run_id"),
                    "binding_role": item.get("binding_role"),
                    "status": item.get("status"),
                }
                for item in surface_bindings
            ],
            key=lambda item: str(item.get("surface_binding_id") or ""),
        ),
    }


class SurfaceBindingStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def declare_surface(self, **kwargs: Any) -> dict[str, Any]:
        with self.store.locked() as state:
            ensure_default_definitions_in_state(state)
            surface = build_runtime_surface(state, **kwargs)
            state.setdefault("runtime_surfaces", {})[surface["runtime_surface_id"]] = surface
            return deepcopy(surface)

    def bind_surface(self, **kwargs: Any) -> dict[str, Any]:
        with self.store.locked() as state:
            binding = build_surface_binding(state, **kwargs)
            state.setdefault("surface_bindings", {})[binding["surface_binding_id"]] = binding
            runtime_surface = deepcopy(state["runtime_surfaces"][binding["runtime_surface_id"]])
            refs = list(runtime_surface.get("surface_binding_ids") or [])
            if binding["surface_binding_id"] not in refs:
                refs.append(binding["surface_binding_id"])
            runtime_surface["surface_binding_ids"] = refs
            runtime_surface["updated_at"] = binding["created_at"]
            runtime_surface["runtime_surface_sha256"] = _record_sha(
                runtime_surface,
                "runtime_surface_sha256",
            )
            state["runtime_surfaces"][runtime_surface["runtime_surface_id"]] = runtime_surface
            return deepcopy(binding)

    def status(self) -> dict[str, Any]:
        return surface_status(self.store.load())


def _endpoint_is_local(endpoint: str, transport: str) -> bool:
    if transport in {"stdio", "mcp_stdio", "terminal", "tmux", "none"}:
        return "://" not in endpoint
    parsed = urlparse(endpoint)
    if parsed.username or parsed.password or parsed.query:
        return False
    if parsed.scheme not in {"http", "https", "ws", "wss", "unix"}:
        return False
    if parsed.scheme == "unix":
        return True
    return (parsed.hostname or "") in LOCALHOST_NAMES


def _path_under_workspace(path: str) -> bool:
    root = Path(workspace_root()).expanduser().resolve(strict=False)
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True
