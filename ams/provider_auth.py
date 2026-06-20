from __future__ import annotations

from copy import deepcopy
import os
import re
from typing import Any, Mapping

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


AUTH_MODES = {"env_api_key", "none"}
STATUSES = {"ready", "blocked"}
LOCAL_PROVIDERS = {"local", "local_ollama", "local_openai_compatible"}
DEFAULT_REQUIRED_ENV_NAMES = {
    "openai": ["OPENAI_API_KEY"],
    "openai_file_search": ["OPENAI_API_KEY"],
}
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


class ProviderAuthPreflightStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        subject_kind: str,
        subject_id: str,
        provider: str,
        operation: str,
        surface: str | None = None,
        model: str | None = None,
        auth_mode: str | None = None,
        required_env_names: list[str] | None = None,
        present_env_names: list[str] | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            record = build_provider_auth_preflight(
                subject_kind=subject_kind,
                subject_id=subject_id,
                provider=provider,
                operation=operation,
                surface=surface,
                model=model,
                auth_mode=auth_mode,
                required_env_names=required_env_names,
                present_env_names=present_env_names,
                environment=environment,
            )
            validation = validate_provider_auth_preflight_record(record)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            preflight_id = record["provider_auth_preflight_id"]
            state.setdefault("provider_auth_preflights", {})[preflight_id] = record
            state.setdefault("indexes", {}).setdefault("provider_auth_preflight_ids", {})[
                preflight_id
            ] = preflight_id
        return deepcopy(record)


def build_provider_auth_preflight(
    *,
    subject_kind: str,
    subject_id: str,
    provider: str,
    operation: str,
    surface: str | None = None,
    model: str | None = None,
    auth_mode: str | None = None,
    required_env_names: list[str] | None = None,
    present_env_names: list[str] | None = None,
    environment: Mapping[str, str] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    required = _unique_env_names(
        required_env_names if required_env_names is not None else DEFAULT_REQUIRED_ENV_NAMES.get(provider, [])
    )
    auth_mode = auth_mode or ("none" if provider in LOCAL_PROVIDERS and not required else "env_api_key")
    if present_env_names is None:
        env = os.environ if environment is None else environment
        present = [name for name in required if name in env]
    else:
        present = _unique_env_names(present_env_names)
    present = [name for name in present if name in required]
    absent = [name for name in required if name not in present]
    status, reason_codes = _status_and_reasons(
        auth_mode=auth_mode,
        required_env_names=required,
        present_env_names=present,
        absent_env_names=absent,
    )
    record = {
        "schema_version": "ams.ams.provider_auth_preflight.v0",
        "provider_auth_preflight_id": stable_id(
            "provauth",
            subject_kind,
            subject_id,
            provider,
            operation,
            surface,
            model,
            auth_mode,
            required,
            present,
            now,
        ),
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "provider": provider,
        "surface": surface,
        "operation": operation,
        "model": model,
        "auth_mode": auth_mode,
        "required_env_names": required,
        "present_env_names": present,
        "absent_env_names": absent,
        "credential_refs": [
            {"kind": "env", "name": name, "present": name in present}
            for name in required
        ],
        "secret_material_stored": False,
        "credential_fingerprints": [],
        "network_probe_allowed": False,
        "provider_call_allowed": False,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["auth_preflight_sha256"] = _hash_without(record, "auth_preflight_sha256")
    return deepcopy(record)


def validate_provider_auth_preflight_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("auth_preflight_sha256")
    if expected_hash and expected_hash != _hash_without(record, "auth_preflight_sha256"):
        reason_codes.append("provider_auth.hash_mismatch")
    if record.get("status") not in STATUSES:
        reason_codes.append("provider_auth.status_invalid")
    if record.get("auth_mode") not in AUTH_MODES:
        reason_codes.append("provider_auth.auth_mode_invalid")
    for key in ("subject_kind", "subject_id", "provider", "operation"):
        if not record.get(key):
            reason_codes.append(f"provider_auth.{key}_missing")
    required = _unique_env_names(record.get("required_env_names") or [])
    present = _unique_env_names(record.get("present_env_names") or [])
    absent = _unique_env_names(record.get("absent_env_names") or [])
    for name in [*required, *present, *absent]:
        if not ENV_NAME_RE.match(str(name)):
            reason_codes.append("provider_auth.env_name_invalid")
    if sorted(present + absent) != sorted(required):
        reason_codes.append("provider_auth.env_partition_mismatch")
    if any(name not in required for name in present):
        reason_codes.append("provider_auth.present_env_not_required")
    expected_refs = [
        {"kind": "env", "name": name, "present": name in present}
        for name in required
    ]
    if record.get("credential_refs") != expected_refs:
        reason_codes.append("provider_auth.credential_refs_mismatch")
    if record.get("secret_material_stored") is not False:
        reason_codes.append("provider_auth.secret_material_stored")
    if record.get("credential_fingerprints") != []:
        reason_codes.append("provider_auth.credential_fingerprints_not_empty")
    for key in ("network_probe_allowed", "provider_call_allowed"):
        if record.get(key) is not False:
            reason_codes.append(f"provider_auth.{key}_not_false")
    expected_status, expected_reasons = _status_and_reasons(
        auth_mode=str(record.get("auth_mode") or ""),
        required_env_names=required,
        present_env_names=present,
        absent_env_names=absent,
    )
    if record.get("status") != expected_status:
        reason_codes.append("provider_auth.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("provider_auth.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def provider_auth_is_ready(record: dict[str, Any] | None) -> bool:
    return bool(record and validate_provider_auth_preflight_record(record)["ok"] and record.get("status") == "ready")


def _status_and_reasons(
    *,
    auth_mode: str,
    required_env_names: list[str],
    present_env_names: list[str],
    absent_env_names: list[str],
) -> tuple[str, list[str]]:
    if auth_mode == "none" or not required_env_names:
        return "ready", ["provider_auth.not_required"]
    if absent_env_names:
        return "blocked", ["provider_auth.required_env_missing"]
    if sorted(present_env_names) == sorted(required_env_names):
        return "ready", ["provider_auth.env_presence_confirmed"]
    return "blocked", ["provider_auth.required_env_missing"]


def _unique_env_names(names: list[str]) -> list[str]:
    return sorted({str(name) for name in names if str(name)})
