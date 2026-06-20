from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import canonical_json, sha256_text, stable_id
from .signed_policy import SignedPolicyConfig, verify_signed_policy
from .store import JsonStore


PACKAGE_SCHEMA_VERSION = "ams.ams_codex.package_manifest.v0"
DEFAULT_PACKAGE_TIME = "2026-06-10T00:00:00Z"


def _manifest_hash(manifest: dict[str, Any]) -> str:
    material = dict(manifest)
    material.pop("manifest_sha256", None)
    return sha256_text(canonical_json(material))


def build_package_manifest(
    state: dict[str, Any],
    *,
    name: str = "local-default-tool-surface-registry",
    version: str = "0.1.0",
    package_mode: str = "shadow_only",
    gate_artifacts: list[dict[str, Any]] | None = None,
    created_at: str = DEFAULT_PACKAGE_TIME,
) -> dict[str, Any]:
    tools = [
        {
            "definition_id": item["definition_id"],
            "name": item["name"],
            "version": item["version"],
            "status": item["status"],
            "definition_sha256": item["definition_sha256"],
        }
        for item in (state.get("tool_definitions") or {}).values()
    ]
    surfaces = [
        {
            "definition_id": item["definition_id"],
            "provider": item["provider"],
            "surface": item["surface"],
            "version": item["version"],
            "mode": item["mode"],
            "status": item["status"],
            "definition_sha256": item["definition_sha256"],
        }
        for item in (state.get("surface_definitions") or {}).values()
    ]
    tools.sort(key=lambda item: (item["name"], item["version"], item["definition_id"]))
    surfaces.sort(key=lambda item: (item["provider"], item["surface"], item["version"], item["definition_id"]))
    gate_artifacts = gate_artifacts if gate_artifacts is not None else [
        {
            "artifact_id": "authority_gate_engine",
            "artifact_type": "gate_engine",
            "mode": "shadow_only",
            "artifact_sha256": None,
            "status": "not_packaged",
        }
    ]
    manifest = {
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "package_manifest_id": stable_id("pkgman", name, version, package_mode, tools, surfaces, gate_artifacts),
        "name": name,
        "version": version,
        "package_mode": package_mode,
        "registry": {
            "tool_definitions": tools,
            "surface_definitions": surfaces,
        },
        "gate_artifacts": gate_artifacts,
        "created_at": created_at,
    }
    manifest["manifest_sha256"] = _manifest_hash(manifest)
    return manifest


def validate_package_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    if manifest.get("schema_version") != PACKAGE_SCHEMA_VERSION:
        reason_codes.append("package.schema_version_invalid")
    if manifest.get("manifest_sha256") != _manifest_hash(manifest):
        reason_codes.append("package.manifest_hash_mismatch")
    package_mode = manifest.get("package_mode")
    if package_mode not in {"shadow_only", "dry_run", "enforced"}:
        reason_codes.append("package.mode_invalid")

    tools = (manifest.get("registry") or {}).get("tool_definitions") or []
    surfaces = (manifest.get("registry") or {}).get("surface_definitions") or []
    seen_tools: set[tuple[str, str]] = set()
    for tool in tools:
        key = (str(tool.get("name")), str(tool.get("version")))
        if key in seen_tools:
            reason_codes.append(f"package.duplicate_tool:{key[0]}:{key[1]}")
        seen_tools.add(key)
        if not str(tool.get("definition_sha256") or "").startswith("sha256:"):
            reason_codes.append(f"package.tool_hash_missing:{tool.get('name')}")
    seen_surfaces: set[tuple[str, str, str]] = set()
    for surface in surfaces:
        key = (str(surface.get("provider")), str(surface.get("surface")), str(surface.get("version")))
        if key in seen_surfaces:
            reason_codes.append(f"package.duplicate_surface:{key[0]}:{key[1]}:{key[2]}")
        seen_surfaces.add(key)
        if not str(surface.get("definition_sha256") or "").startswith("sha256:"):
            reason_codes.append(f"package.surface_hash_missing:{surface.get('provider')}/{surface.get('surface')}")

    artifacts = manifest.get("gate_artifacts") or []
    if package_mode == "enforced":
        verified_artifacts = [
            artifact for artifact in artifacts
            if artifact.get("status") == "packaged"
            and str(artifact.get("artifact_sha256") or "").startswith("sha256:")
        ]
        if not verified_artifacts:
            reason_codes.append("package.enforced_gate_missing_artifact")

    return {"ok": not reason_codes, "reason_codes": reason_codes}


def compare_registry_to_manifest(state: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    manifest_tools = {
        item.get("definition_id"): item
        for item in (manifest.get("registry") or {}).get("tool_definitions") or []
    }
    manifest_surfaces = {
        item.get("definition_id"): item
        for item in (manifest.get("registry") or {}).get("surface_definitions") or []
    }
    state_tools = state.get("tool_definitions") or {}
    state_surfaces = state.get("surface_definitions") or {}

    for definition_id, expected in manifest_tools.items():
        current = state_tools.get(definition_id)
        label = expected.get("name") or definition_id
        if not current:
            reason_codes.append(f"registry.tool_missing:{label}")
            continue
        if current.get("definition_sha256") != expected.get("definition_sha256"):
            reason_codes.append(f"registry.tool_hash_mismatch:{label}")
        if current.get("status") != expected.get("status"):
            reason_codes.append(f"registry.tool_status_mismatch:{label}")
    for definition_id in state_tools:
        if definition_id not in manifest_tools:
            reason_codes.append(f"registry.unmanifested_tool:{state_tools[definition_id].get('name')}")

    for definition_id, expected in manifest_surfaces.items():
        current = state_surfaces.get(definition_id)
        label = f"{expected.get('provider')}/{expected.get('surface')}"
        if not current:
            reason_codes.append(f"registry.surface_missing:{label}")
            continue
        if current.get("definition_sha256") != expected.get("definition_sha256"):
            reason_codes.append(f"registry.surface_hash_mismatch:{label}")
        if current.get("status") != expected.get("status"):
            reason_codes.append(f"registry.surface_status_mismatch:{label}")
    for definition_id in state_surfaces:
        if definition_id not in manifest_surfaces:
            current = state_surfaces[definition_id]
            reason_codes.append(f"registry.unmanifested_surface:{current.get('provider')}/{current.get('surface')}")

    return {"ok": not reason_codes, "reason_codes": reason_codes}


def verify_package_manifest(
    manifest_path: str | Path,
    signature_path: str | Path,
    config: SignedPolicyConfig,
    *,
    store: JsonStore | None = None,
) -> dict[str, Any]:
    manifest_path = Path(manifest_path)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return _deny("package.invalid_json", error=f"{type(exc).__name__}: {exc}")
    if not isinstance(manifest, dict):
        return _deny("package.not_object")

    signature = verify_signed_policy(manifest_path, signature_path, config)
    if not signature.get("allowed"):
        return {
            "allowed": False,
            "status": "deny",
            "reason_code": "package.signature_failed",
            "reason_codes": ["package.signature_failed", str(signature.get("reason_code"))],
            "signature": signature,
        }

    manifest_check = validate_package_manifest(manifest)
    registry_check = {"ok": True, "reason_codes": []}
    if store is not None:
        registry_check = compare_registry_to_manifest(store.load(), manifest)
    reason_codes = list(manifest_check["reason_codes"]) + list(registry_check["reason_codes"])
    allowed = not reason_codes
    return {
        "allowed": allowed,
        "status": "allow" if allowed else "deny",
        "reason_code": "package.verified" if allowed else "package.validation_failed",
        "reason_codes": ["package.verified"] if allowed else reason_codes,
        "manifest_sha256": manifest.get("manifest_sha256"),
        "signature": signature,
        "manifest": {
            "package_manifest_id": manifest.get("package_manifest_id"),
            "name": manifest.get("name"),
            "version": manifest.get("version"),
            "package_mode": manifest.get("package_mode"),
        },
        "registry": registry_check,
    }


def write_package_manifest(store: JsonStore, output_path: str | Path) -> dict[str, Any]:
    manifest = build_package_manifest(store.load())
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(manifest), encoding="utf-8")
    return {
        "output": str(path),
        "manifest_sha256": manifest["manifest_sha256"],
        "tool_definitions": len((manifest.get("registry") or {}).get("tool_definitions") or []),
        "surface_definitions": len((manifest.get("registry") or {}).get("surface_definitions") or []),
    }


def _deny(reason_code: str, **extra: Any) -> dict[str, Any]:
    payload = {"allowed": False, "status": "deny", "reason_code": reason_code, "reason_codes": [reason_code]}
    payload.update(extra)
    return payload
