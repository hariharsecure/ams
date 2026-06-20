from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .architecture_gate import architecture_scoped_paths, validate_architecture_gate_review_record
from .blast_radius import blast_radius_scoped_paths, validate_blast_radius_review_record
from .models import hash_without as _hash_without, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import path_is_under, repo_root


SCHEMA_VERSION = "ams.ams_codex.source_write_executor_preflight.v0"
STATUSES = {"ready_for_backup_preimage_capture", "blocked"}

NON_WRITE_BOUNDARIES = {
    "source_file_rewritten": False,
    "source_file_deleted": False,
    "source_file_moved": False,
    "source_backup_written": False,
    "rollback_executed": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "raw_source_stored_in_ams_state": False,
    "raw_patch_stored_in_ams_state": False,
    "raw_executor_output_stored_in_ams_state": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "network_call_performed": False,
    "secret_stored": False,
}


class SourceWriteExecutorPreflightStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        doc_action_patch_apply_acceptance_packet_id: str,
        architecture_gate_review_id: str | None = None,
        blast_radius_review_id: str | None = None,
        source_root: str | Path | None = None,
        label: str = "manual-source-write-executor-preflight",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            acceptance = (state.get("doc_action_patch_apply_acceptance_packets") or {}).get(
                doc_action_patch_apply_acceptance_packet_id
            )
            if not isinstance(acceptance, dict):
                raise KeyError(
                    "doc action patch apply acceptance packet not found: "
                    f"{doc_action_patch_apply_acceptance_packet_id}"
                )
            architecture_gate = None
            if architecture_gate_review_id:
                architecture_gate = (state.get("architecture_gate_reviews") or {}).get(
                    architecture_gate_review_id
                )
                if not isinstance(architecture_gate, dict):
                    raise KeyError(f"architecture gate review not found: {architecture_gate_review_id}")
            blast_radius_review = None
            if blast_radius_review_id:
                blast_radius_review = (state.get("blast_radius_reviews") or {}).get(blast_radius_review_id)
                if not isinstance(blast_radius_review, dict):
                    raise KeyError(f"blast radius review not found: {blast_radius_review_id}")
            record = build_source_write_executor_preflight(
                state=state,
                apply_acceptance_packet=acceptance,
                architecture_gate_review=architecture_gate,
                blast_radius_review=blast_radius_review,
                source_root=source_root,
                label=label,
            )
            validation = validate_source_write_executor_preflight_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            preflight_id = record["source_write_executor_preflight_id"]
            state.setdefault("source_write_executor_preflights", {})[preflight_id] = record
            state.setdefault("indexes", {}).setdefault("source_write_executor_preflight_ids", {})[
                preflight_id
            ] = preflight_id
            return deepcopy(record)


def build_source_write_executor_preflight(
    *,
    state: dict[str, Any],
    apply_acceptance_packet: dict[str, Any],
    architecture_gate_review: dict[str, Any] | None = None,
    blast_radius_review: dict[str, Any] | None = None,
    source_root: str | Path | None = None,
    label: str = "manual-source-write-executor-preflight",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root_value = source_root or apply_acceptance_packet.get("source_root") or repo_root()
    root = Path(root_value).expanduser().resolve(strict=False)
    accepted_action = deepcopy(apply_acceptance_packet.get("accepted_apply_action") or {})
    source_path = str(accepted_action.get("source_path") or "")
    current_source_ref = _source_ref(root, source_path)
    preimage = _preimage_requirements(
        accepted_action=accepted_action,
        current_source_ref=current_source_ref,
    )
    architecture_proof = _architecture_proof(
        state=state,
        source_path=source_path,
        apply_acceptance_packet=apply_acceptance_packet,
        architecture_gate_review=architecture_gate_review,
    )
    blast_radius_proof = _blast_radius_proof(
        state=state,
        source_path=source_path,
        apply_acceptance_packet=apply_acceptance_packet,
        blast_radius_review=blast_radius_review,
    )
    required_gates = _required_gates(
        apply_acceptance_packet=apply_acceptance_packet,
        accepted_action=accepted_action,
        preimage=preimage,
        architecture_proof=architecture_proof,
        blast_radius_proof=blast_radius_proof,
    )
    status = _status(required_gates)
    ready = status == "ready_for_backup_preimage_capture"
    record = {
        "schema_version": SCHEMA_VERSION,
        "source_write_executor_preflight_id": stable_id(
            "srcwritepreflight",
            label,
            apply_acceptance_packet.get("doc_action_patch_apply_acceptance_packet_id"),
            apply_acceptance_packet.get("doc_action_patch_apply_acceptance_packet_sha256"),
            source_path,
            current_source_ref,
            architecture_proof,
            blast_radius_proof,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "doc_action_patch_apply_acceptance_packet_id": apply_acceptance_packet.get(
            "doc_action_patch_apply_acceptance_packet_id"
        ),
        "doc_action_patch_apply_acceptance_packet_sha256": apply_acceptance_packet.get(
            "doc_action_patch_apply_acceptance_packet_sha256"
        ),
        "source_path": source_path,
        "accepted_apply_action": accepted_action,
        "current_source_ref": current_source_ref,
        "preimage_requirements": preimage,
        "architecture_gate_proof": architecture_proof,
        "blast_radius_proof": blast_radius_proof,
        "required_gates": required_gates,
        "preflight_policy": {
            "preflight_only": True,
            "requires_apply_acceptance_packet": True,
            "requires_source_preimage_hash": True,
            "requires_source_backup_before_write": True,
            "requires_post_write_replay": True,
            "requires_architecture_gate_when_scoped": True,
            "requires_blast_radius_when_scoped": True,
            "source_write_allowed_by_preflight": False,
        },
        "ready_for_backup_preimage_capture": ready,
        "apply_allowed": False,
        "live_execution_allowed": False,
        "source_file_write_allowed": False,
        "source_file_move_allowed": False,
        "source_file_delete_allowed": False,
        "source_backup_write_allowed": False,
        "archive_create_allowed": False,
        "generated_surface_rewrite_allowed": False,
        "provider_call_allowed": False,
        "network_call_allowed": False,
        "preflight_actions": _preflight_actions(preimage, architecture_proof, blast_radius_proof) if ready else [],
        "backup_actions": [],
        "source_write_actions": [],
        "post_write_replay_actions": [],
        "live_boundaries": dict(NON_WRITE_BOUNDARIES),
        "status": status,
        "reason_codes": _reason_codes(required_gates, status),
        "created_at": now,
    }
    record["source_write_executor_preflight_sha256"] = _hash_without(
        record,
        "source_write_executor_preflight_sha256",
    )
    return deepcopy(record)


def validate_source_write_executor_preflight_record(
    record: dict[str, Any],
    *,
    state: dict[str, Any],
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "source_write_executor_preflight.schema.json",
            record,
            location="source_write_executor_preflight",
        )
    except SchemaValidationError:
        reason_codes.append("source_write_executor_preflight.schema_invalid")
    if record.get("source_write_executor_preflight_sha256") != _hash_without(
        record,
        "source_write_executor_preflight_sha256",
    ):
        reason_codes.append("source_write_executor_preflight.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("source_write_executor_preflight.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("source_write_executor_preflight.status_invalid")
    acceptance_id = record.get("doc_action_patch_apply_acceptance_packet_id")
    acceptance = (state.get("doc_action_patch_apply_acceptance_packets") or {}).get(acceptance_id)
    if not isinstance(acceptance, dict):
        reason_codes.append("source_write_executor_preflight.apply_acceptance_missing")
    elif acceptance.get("doc_action_patch_apply_acceptance_packet_sha256") != record.get(
        "doc_action_patch_apply_acceptance_packet_sha256"
    ):
        reason_codes.append("source_write_executor_preflight.apply_acceptance_hash_mismatch")
    rebuilt = build_source_write_executor_preflight(
        state=state,
        apply_acceptance_packet=acceptance or {},
        architecture_gate_review=_record_ref(
            state,
            "architecture_gate_reviews",
            record.get("architecture_gate_proof", {}).get("architecture_gate_review_id"),
        ),
        blast_radius_review=_record_ref(
            state,
            "blast_radius_reviews",
            record.get("blast_radius_proof", {}).get("blast_radius_review_id"),
        ),
        source_root=record.get("source_root"),
        label=record.get("label") or "manual-source-write-executor-preflight",
        now=record.get("created_at"),
    )
    for key in (
        "source_path",
        "current_source_ref",
        "preimage_requirements",
        "architecture_gate_proof",
        "blast_radius_proof",
        "required_gates",
        "status",
        "reason_codes",
        "ready_for_backup_preimage_capture",
        "preflight_actions",
    ):
        if record.get(key) != rebuilt.get(key):
            reason_codes.append(f"source_write_executor_preflight.{key}_mismatch")
    _validate_authority(record, reason_codes)
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _required_gates(
    *,
    apply_acceptance_packet: dict[str, Any],
    accepted_action: dict[str, Any],
    preimage: dict[str, Any],
    architecture_proof: dict[str, Any],
    blast_radius_proof: dict[str, Any],
) -> dict[str, bool]:
    acceptance_hash = apply_acceptance_packet.get("doc_action_patch_apply_acceptance_packet_sha256")
    return {
        "apply_acceptance_present": bool(apply_acceptance_packet.get("doc_action_patch_apply_acceptance_packet_id")),
        "apply_acceptance_hash_current": bool(acceptance_hash)
        and acceptance_hash == _hash_without(
            apply_acceptance_packet,
            "doc_action_patch_apply_acceptance_packet_sha256",
        ),
        "accepted_for_backup_preimage_review": apply_acceptance_packet.get(
            "accepted_for_backup_preimage_review"
        )
        is True,
        "acceptance_grants_no_write_authority": _acceptance_grants_no_write_authority(apply_acceptance_packet),
        "accepted_action_present": bool(accepted_action.get("source_path")),
        "source_exists": preimage.get("current_source_ref", {}).get("exists") is True,
        "source_under_root": preimage.get("current_source_ref", {}).get("under_source_root") is True,
        "source_hash_matches_acceptance": preimage.get("source_hash_matches_acceptance") is True,
        "backup_required_before_write": preimage.get("backup_required_before_write") is True,
        "backup_not_yet_written": preimage.get("backup_written") is False,
        "post_write_replay_required": preimage.get("post_write_replay_required") is True,
        "post_write_replay_not_yet_run": preimage.get("post_write_replay_performed") is False,
        "architecture_gate_satisfied": architecture_proof.get("satisfied") is True,
        "blast_radius_satisfied": blast_radius_proof.get("satisfied") is True,
        "preflight_grants_no_write_authority": True,
    }


def _architecture_proof(
    *,
    state: dict[str, Any],
    source_path: str,
    apply_acceptance_packet: dict[str, Any],
    architecture_gate_review: dict[str, Any] | None,
) -> dict[str, Any]:
    scoped_paths = architecture_scoped_paths([source_path])
    if not scoped_paths:
        return {"required": False, "satisfied": True, "reason_code": "architecture_gate.not_required"}
    if not architecture_gate_review:
        return {
            "required": True,
            "satisfied": False,
            "reason_code": "source_write_preflight.architecture_gate_required",
            "scoped_paths": scoped_paths,
        }
    validation = validate_architecture_gate_review_record(architecture_gate_review, state=state)
    subject_kind = "doc_action_patch_apply_acceptance_packet"
    subject_id = apply_acceptance_packet.get("doc_action_patch_apply_acceptance_packet_id")
    subject_ok = (
        architecture_gate_review.get("subject_kind") == subject_kind
        and architecture_gate_review.get("subject_id") == subject_id
    )
    scope_ok = sorted(architecture_gate_review.get("scoped_paths") or []) == scoped_paths
    decision_ok = architecture_gate_review.get("decision") == "allow"
    return {
        "required": True,
        "satisfied": validation["ok"] and subject_ok and scope_ok and decision_ok,
        "reason_code": "architecture_gate.reviewed" if validation["ok"] and subject_ok and scope_ok else "source_write_preflight.architecture_gate_invalid",
        "architecture_gate_review_id": architecture_gate_review.get("architecture_gate_review_id"),
        "gate_sha256": architecture_gate_review.get("gate_sha256"),
        "decision": architecture_gate_review.get("decision"),
        "scoped_paths": scoped_paths,
    }


def _blast_radius_proof(
    *,
    state: dict[str, Any],
    source_path: str,
    apply_acceptance_packet: dict[str, Any],
    blast_radius_review: dict[str, Any] | None,
) -> dict[str, Any]:
    scoped_paths = blast_radius_scoped_paths([source_path])
    if not scoped_paths:
        return {"required": False, "satisfied": True, "reason_code": "blast_radius.not_required"}
    if not blast_radius_review:
        return {
            "required": True,
            "satisfied": False,
            "reason_code": "source_write_preflight.blast_radius_required",
            "scoped_paths": scoped_paths,
        }
    validation = validate_blast_radius_review_record(blast_radius_review, state=state)
    subject_kind = "doc_action_patch_apply_acceptance_packet"
    subject_id = apply_acceptance_packet.get("doc_action_patch_apply_acceptance_packet_id")
    subject_ok = (
        blast_radius_review.get("subject_kind") == subject_kind
        and blast_radius_review.get("subject_id") == subject_id
    )
    scope_ok = sorted(blast_radius_review.get("scoped_paths") or []) == scoped_paths
    decision_ok = blast_radius_review.get("decision") == "allow"
    return {
        "required": True,
        "satisfied": validation["ok"] and subject_ok and scope_ok and decision_ok,
        "reason_code": "blast_radius.reviewed" if validation["ok"] and subject_ok and scope_ok else "source_write_preflight.blast_radius_invalid",
        "blast_radius_review_id": blast_radius_review.get("blast_radius_review_id"),
        "blast_radius_review_sha256": blast_radius_review.get("blast_radius_review_sha256"),
        "decision": blast_radius_review.get("decision"),
        "scoped_paths": scoped_paths,
    }


def _preimage_requirements(*, accepted_action: dict[str, Any], current_source_ref: dict[str, Any]) -> dict[str, Any]:
    accepted_ref = deepcopy(accepted_action.get("current_source_ref") or accepted_action.get("source_ref") or {})
    return {
        "source_path": accepted_action.get("source_path"),
        "accepted_source_ref": accepted_ref,
        "current_source_ref": current_source_ref,
        "source_hash_matches_acceptance": _source_refs_match(accepted_ref, current_source_ref),
        "backup_required_before_write": True,
        "backup_written": False,
        "backup_path": "",
        "backup_sha256": None,
        "post_write_replay_required": True,
        "post_write_replay_performed": False,
        "raw_source_stored": False,
    }


def _preflight_actions(
    preimage: dict[str, Any],
    architecture_proof: dict[str, Any],
    blast_radius_proof: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        {
            "action": "capture_backup_and_preimage_before_source_write",
            "source_path": preimage.get("source_path"),
            "current_source_sha256": (preimage.get("current_source_ref") or {}).get("sha256"),
            "backup_required_before_write": True,
            "post_write_replay_required": True,
            "architecture_gate_required": architecture_proof.get("required") is True,
            "blast_radius_required": blast_radius_proof.get("required") is True,
        }
    ]


def _source_ref(root: Path, source_path: str) -> dict[str, Any]:
    source = (root / source_path).resolve(strict=False)
    exists = source.is_file()
    return {
        "path": source_path,
        "absolute_path": str(source),
        "exists": exists,
        "under_source_root": path_is_under(source, root),
        "sha256": _file_sha256(source) if exists else None,
        "size_bytes": source.stat().st_size if exists else 0,
    }


def _source_refs_match(expected: dict[str, Any], current: dict[str, Any]) -> bool:
    return (
        bool(expected)
        and expected.get("path") == current.get("path")
        and expected.get("exists") is True
        and current.get("exists") is True
        and expected.get("sha256") == current.get("sha256")
        and expected.get("size_bytes") == current.get("size_bytes")
    )


def _acceptance_grants_no_write_authority(packet: dict[str, Any]) -> bool:
    return (
        packet.get("apply_allowed") is False
        and packet.get("live_execution_allowed") is False
        and packet.get("source_file_write_allowed") is False
        and packet.get("source_file_move_allowed") is False
        and packet.get("source_file_delete_allowed") is False
        and packet.get("source_backup_write_allowed") is False
        and packet.get("source_write_actions") == []
        and packet.get("backup_actions") == []
    )


def _validate_authority(record: dict[str, Any], reason_codes: list[str]) -> None:
    for key in (
        "apply_allowed",
        "live_execution_allowed",
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "source_backup_write_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "provider_call_allowed",
        "network_call_allowed",
    ):
        if record.get(key) is not False:
            reason_codes.append(f"source_write_executor_preflight.{key}_not_false")
    for key in ("backup_actions", "source_write_actions", "post_write_replay_actions"):
        if record.get(key) != []:
            reason_codes.append(f"source_write_executor_preflight.{key}_not_empty")
    for key, expected in NON_WRITE_BOUNDARIES.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"source_write_executor_preflight.{key}_boundary_mismatch")


def _status(required_gates: dict[str, bool]) -> str:
    return "ready_for_backup_preimage_capture" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "ready_for_backup_preimage_capture":
        return ["source_write_executor_preflight.ready_for_backup_preimage_capture"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"source_write_executor_preflight.gate_failed:{key}" for key in missing] or [
        "source_write_executor_preflight.blocked"
    ]


def _record_ref(state: dict[str, Any], collection: str, record_id: str | None) -> dict[str, Any] | None:
    if not record_id:
        return None
    record = (state.get(collection) or {}).get(record_id)
    return record if isinstance(record, dict) else None


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
