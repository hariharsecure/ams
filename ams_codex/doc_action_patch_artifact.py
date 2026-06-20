from __future__ import annotations

from copy import deepcopy
import difflib
import hashlib
from pathlib import Path
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import path_is_under, repo_root


SCHEMA_VERSION = "ams.ams_codex.doc_action_patch_artifact_receipt.v0"
STATUSES = {"artifact_ready", "blocked"}
DEFAULT_ARTIFACT_ROOT = Path.home() / ".ams" / "artifacts" / "doc_action_patch_artifacts"

LIVE_BOUNDARIES = {
    "patch_artifact_written": False,
    "source_file_rewritten": False,
    "source_file_deleted": False,
    "source_file_moved": False,
    "archive_created": False,
    "generated_surface_rewritten": False,
    "raw_patch_stored_in_ams_state": False,
    "raw_source_markdown_stored_in_ams_state": False,
    "raw_readback_stored_in_ams_state": False,
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "network_call_performed": False,
    "secret_stored": False,
}


class DocActionPatchArtifactReceiptStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        doc_action_patch_readback_receipt_id: str,
        source_root: str | Path | None = None,
        artifact_root: str | Path | None = None,
        label: str = "manual-doc-action-patch-artifact",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            readback = (state.get("doc_action_patch_readback_receipts") or {}).get(
                doc_action_patch_readback_receipt_id
            )
            if not readback:
                raise KeyError(f"doc action patch readback receipt not found: {doc_action_patch_readback_receipt_id}")
            patch_preview = (state.get("doc_action_patch_previews") or {}).get(
                readback.get("doc_action_patch_preview_id")
            )
            if not patch_preview:
                raise KeyError(f"doc action patch preview not found: {readback.get('doc_action_patch_preview_id')}")
            approval_packet = (state.get("doc_action_operator_approval_packets") or {}).get(
                patch_preview.get("doc_action_operator_approval_packet_id")
            )
            if not approval_packet:
                raise KeyError(
                    "doc action operator approval packet not found: "
                    f"{patch_preview.get('doc_action_operator_approval_packet_id')}"
                )
            execution_plan = (state.get("doc_action_execution_plans") or {}).get(
                patch_preview.get("doc_action_execution_plan_id")
            )
            if not execution_plan:
                raise KeyError(f"doc action execution plan not found: {patch_preview.get('doc_action_execution_plan_id')}")
            record = build_doc_action_patch_artifact_receipt(
                readback_receipt=readback,
                patch_preview=patch_preview,
                approval_packet=approval_packet,
                execution_plan=execution_plan,
                source_root=source_root,
                artifact_root=artifact_root,
                label=label,
            )
            receipt_id = record["doc_action_patch_artifact_receipt_id"]
            state.setdefault("doc_action_patch_artifact_receipts", {})[receipt_id] = record
            state.setdefault("indexes", {}).setdefault("doc_action_patch_artifact_receipt_ids", {})[
                receipt_id
            ] = receipt_id
            return deepcopy(record)


def build_doc_action_patch_artifact_receipt(
    *,
    readback_receipt: dict[str, Any],
    patch_preview: dict[str, Any],
    approval_packet: dict[str, Any],
    execution_plan: dict[str, Any],
    source_root: str | Path | None = None,
    artifact_root: str | Path | None = None,
    label: str = "manual-doc-action-patch-artifact",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False) if source_root else repo_root()
    out_root = Path(artifact_root).expanduser().resolve(strict=False) if artifact_root else DEFAULT_ARTIFACT_ROOT
    planned_id = stable_id(
        "docpatchartifact",
        label,
        readback_receipt.get("doc_action_patch_readback_receipt_id"),
        readback_receipt.get("doc_action_patch_readback_receipt_sha256"),
        patch_preview.get("doc_action_patch_preview_id"),
        patch_preview.get("doc_action_patch_preview_sha256"),
        now,
    )
    artifact_dir = out_root / planned_id
    artifact_root_allowed = not path_is_under(out_root, root) and out_root != root
    artifacts = (
        _write_artifacts(root, artifact_dir, patch_preview)
        if artifact_root_allowed
        else []
    )
    artifact_summary = _artifact_summary(artifacts)
    required_gates = _required_gates(
        readback_receipt=readback_receipt,
        patch_preview=patch_preview,
        approval_packet=approval_packet,
        execution_plan=execution_plan,
        artifact_root_allowed=artifact_root_allowed,
        artifacts=artifacts,
    )
    status = _status(required_gates)
    reason_codes = _reason_codes(required_gates, status)
    record = {
        "schema_version": SCHEMA_VERSION,
        "doc_action_patch_artifact_receipt_id": planned_id,
        "label": label,
        "source_root": str(root),
        "artifact_root": str(out_root),
        "artifact_dir": str(artifact_dir),
        "doc_action_patch_readback_receipt_id": readback_receipt.get("doc_action_patch_readback_receipt_id"),
        "doc_action_patch_readback_receipt_sha256": readback_receipt.get(
            "doc_action_patch_readback_receipt_sha256"
        ),
        "doc_action_patch_preview_id": patch_preview.get("doc_action_patch_preview_id"),
        "doc_action_patch_preview_sha256": patch_preview.get("doc_action_patch_preview_sha256"),
        "doc_action_operator_approval_packet_id": patch_preview.get("doc_action_operator_approval_packet_id"),
        "doc_action_operator_approval_packet_sha256": patch_preview.get(
            "doc_action_operator_approval_packet_sha256"
        ),
        "doc_action_execution_plan_id": patch_preview.get("doc_action_execution_plan_id"),
        "doc_action_execution_plan_sha256": patch_preview.get("doc_action_execution_plan_sha256"),
        "source_doc_retirement_plan_id": patch_preview.get("source_doc_retirement_plan_id"),
        "source_doc_retirement_plan_sha256": patch_preview.get("source_doc_retirement_plan_sha256"),
        "artifact_policy": {
            "requires_readback_receipt": True,
            "source_hash_recheck_required": True,
            "artifact_root_must_be_outside_source_root": True,
            "patch_artifact_write_allowed": True,
            "source_file_write_allowed": False,
            "source_file_move_allowed": False,
            "source_file_delete_allowed": False,
            "archive_create_allowed": False,
            "generated_surface_rewrite_allowed": False,
            "raw_patch_stored_in_ams_state": False,
            "raw_source_markdown_stored_in_ams_state": False,
            "raw_readback_stored_in_ams_state": False,
            "executor_required_for_source_writes": True,
        },
        "live_boundaries": {**LIVE_BOUNDARIES, "patch_artifact_written": bool(artifacts)},
        "artifacts": artifacts,
        "artifact_summary": artifact_summary,
        "required_gates": required_gates,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["doc_action_patch_artifact_receipt_sha256"] = _hash_without(
        record,
        "doc_action_patch_artifact_receipt_sha256",
    )
    return deepcopy(record)


def validate_doc_action_patch_artifact_receipt_record(
    record: dict[str, Any],
    *,
    readback_receipt: dict[str, Any] | None = None,
    patch_preview: dict[str, Any] | None = None,
    approval_packet: dict[str, Any] | None = None,
    execution_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record(
            "doc_action_patch_artifact_receipt.schema.json",
            record,
            location="doc_action_patch_artifact_receipt",
        )
    except SchemaValidationError:
        reason_codes.append("doc_action_patch_artifact.schema_invalid")
    expected_hash = record.get("doc_action_patch_artifact_receipt_sha256")
    if expected_hash and expected_hash != _hash_without(record, "doc_action_patch_artifact_receipt_sha256"):
        reason_codes.append("doc_action_patch_artifact.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("doc_action_patch_artifact.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("doc_action_patch_artifact.status_invalid")
    _validate_policy_and_boundaries(record, reason_codes)
    artifacts = record.get("artifacts") or []
    expected_summary = _artifact_summary(artifacts)
    if record.get("artifact_summary") != expected_summary:
        reason_codes.append("doc_action_patch_artifact.artifact_summary_mismatch")
    _validate_artifacts(record, artifacts, reason_codes)
    if readback_receipt is None:
        reason_codes.append("doc_action_patch_artifact.readback_receipt_missing")
    else:
        if record.get("doc_action_patch_readback_receipt_sha256") != readback_receipt.get(
            "doc_action_patch_readback_receipt_sha256"
        ):
            reason_codes.append("doc_action_patch_artifact.readback_receipt_hash_mismatch")
        if readback_receipt.get("status") != "readback_verified":
            reason_codes.append("doc_action_patch_artifact.readback_receipt_not_verified")
        if readback_receipt.get("doc_action_patch_readback_receipt_sha256") != _hash_without(
            readback_receipt,
            "doc_action_patch_readback_receipt_sha256",
        ):
            reason_codes.append("doc_action_patch_artifact.readback_receipt_hash_not_current")
    if patch_preview is not None:
        for key in (
            "doc_action_patch_preview_id",
            "doc_action_patch_preview_sha256",
            "doc_action_operator_approval_packet_id",
            "doc_action_operator_approval_packet_sha256",
            "doc_action_execution_plan_id",
            "doc_action_execution_plan_sha256",
            "source_doc_retirement_plan_id",
            "source_doc_retirement_plan_sha256",
        ):
            if record.get(key) != patch_preview.get(key):
                reason_codes.append(f"doc_action_patch_artifact.{key}_mismatch")
        expected_action_ids = sorted(preview.get("action_id") for preview in patch_preview.get("patch_previews") or [])
        actual_action_ids = sorted(artifact.get("action_id") for artifact in artifacts)
        if artifacts and actual_action_ids != expected_action_ids:
            reason_codes.append("doc_action_patch_artifact.patch_action_set_mismatch")
    artifact_root_allowed = _artifact_root_allowed(record)
    expected_gates = _required_gates(
        readback_receipt=readback_receipt or {},
        patch_preview=patch_preview or {},
        approval_packet=approval_packet or {},
        execution_plan=execution_plan or {},
        artifact_root_allowed=artifact_root_allowed,
        artifacts=artifacts,
    )
    if record.get("required_gates") != expected_gates:
        reason_codes.append("doc_action_patch_artifact.required_gates_mismatch")
    expected_status = _status(expected_gates)
    if record.get("status") != expected_status:
        reason_codes.append("doc_action_patch_artifact.status_mismatch")
    expected_reasons = _reason_codes(expected_gates, expected_status)
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("doc_action_patch_artifact.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _write_artifacts(root: Path, artifact_dir: Path, patch_preview: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    artifact_dir.mkdir(parents=True, exist_ok=True)
    for index, preview in enumerate(patch_preview.get("patch_previews") or [], start=1):
        if not isinstance(preview, dict):
            continue
        source_path = str(preview.get("source_path") or "")
        source_file = (root / source_path.strip("/")).resolve(strict=False)
        if not path_is_under(source_file, root) or not source_file.is_file():
            continue
        original = source_file.read_text(encoding="utf-8")
        rendered = _render_candidate_content(original, preview)
        patch_text = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                rendered.splitlines(keepends=True),
                fromfile=f"a/{source_path}",
                tofile=f"b/{source_path}",
            )
        )
        if not patch_text:
            patch_text = _no_op_patch_text(source_path, preview)
        artifact_path = artifact_dir / f"{index:02d}_{_safe_name(source_path)}.patch"
        artifact_path.write_text(patch_text, encoding="utf-8")
        artifact_ref = _artifact_ref(
            root=root,
            artifact_path=artifact_path,
            preview=preview,
            source_ref=_source_ref(root, source_path),
        )
        artifacts.append(artifact_ref)
    return artifacts


def _render_candidate_content(original: str, preview: dict[str, Any]) -> str:
    source_path = str(preview.get("source_path") or "")
    target = str(preview.get("target_surface") or "")
    operation = str(preview.get("planned_operation") or "")
    if operation == "split_archive_preview":
        return (
            f"# {Path(source_path).stem.replace('_', ' ').title()}\n\n"
            "Status: orientation surface after approved doc retirement\n\n"
            f"Historical detail should move to `{target}` only after a separate live execution approval.\n"
            "This MILESTONE-60 artifact is review evidence, not an applied change.\n"
        )
    if operation == "replace_with_generated_surface_preview":
        return (
            "# Generated Status Replacement Preview\n\n"
            f"Approved executor should replace this file from `{target}` after rechecking source hashes.\n"
            "This MILESTONE-60 artifact is review evidence, not an applied change.\n"
        )
    if operation == "trim_orientation_preview":
        lines = original.splitlines()
        kept = "\n".join(lines[:180]).rstrip()
        return (
            kept
            + "\n\n## Generated References\n\n"
            "- Current state: `GENERATED_STATUS.md`\n"
            "- New-session handoff: `NEW_CODEX_SESSION.md`\n"
            "- Milestone index: `MAP.md`\n"
            "\n"
        )
    if operation == "metadata_patch_preview":
        return original.rstrip() + "\n\n---\nstatus: active\nupdated: 2026-06-13\n---\n"
    if operation == "section_patch_preview":
        return original.rstrip() + "\n\n## Status\n\nPending operator-approved documentation repair.\n"
    return original.rstrip() + "\n\n<!-- Pending manual review patch after approval. -->\n"


def _no_op_patch_text(source_path: str, preview: dict[str, Any]) -> str:
    material = {
        "source_path": source_path,
        "planned_operation": preview.get("planned_operation"),
        "target_surface": preview.get("target_surface"),
        "note": "No textual diff produced; executor must review manually.",
    }
    return "# no-op patch preview\n" + canonical_json(material) + "\n"


def _artifact_ref(
    *,
    root: Path,
    artifact_path: Path,
    preview: dict[str, Any],
    source_ref: dict[str, Any],
) -> dict[str, Any]:
    text = artifact_path.read_text(encoding="utf-8")
    encoded = text.encode("utf-8")
    return {
        "action_id": preview.get("action_id"),
        "source_path": preview.get("source_path"),
        "target_surface": preview.get("target_surface"),
        "planned_operation": preview.get("planned_operation"),
        "patch_kind": preview.get("patch_kind"),
        "source_ref": source_ref,
        "source_hash_matches_patch_preview": source_ref.get("sha256")
        == ((preview.get("current_source_ref") or {}).get("sha256")),
        "artifact_path": str(artifact_path),
        "artifact_path_under_source_root": path_is_under(artifact_path, root),
        "artifact_exists": artifact_path.is_file(),
        "artifact_sha256": _file_sha256(artifact_path),
        "artifact_line_count": len(text.splitlines()),
        "artifact_size_bytes": len(encoded),
        "patch_artifact_written": True,
        "raw_patch_stored_in_ams_state": False,
        "raw_source_markdown_stored_in_ams_state": False,
        "source_file_rewritten": False,
        "source_file_deleted": False,
        "source_file_moved": False,
        "archive_created": False,
        "generated_surface_rewritten": False,
    }


def _validate_policy_and_boundaries(record: dict[str, Any], reason_codes: list[str]) -> None:
    policy = record.get("artifact_policy") or {}
    for key in (
        "requires_readback_receipt",
        "source_hash_recheck_required",
        "artifact_root_must_be_outside_source_root",
        "patch_artifact_write_allowed",
        "executor_required_for_source_writes",
    ):
        if policy.get(key) is not True:
            reason_codes.append(f"doc_action_patch_artifact.policy_{key}_not_true")
    for key in (
        "source_file_write_allowed",
        "source_file_move_allowed",
        "source_file_delete_allowed",
        "archive_create_allowed",
        "generated_surface_rewrite_allowed",
        "raw_patch_stored_in_ams_state",
        "raw_source_markdown_stored_in_ams_state",
        "raw_readback_stored_in_ams_state",
    ):
        if policy.get(key) is not False:
            reason_codes.append(f"doc_action_patch_artifact.policy_{key}_not_false")
    live = record.get("live_boundaries") or {}
    if live.get("patch_artifact_written") is not bool(record.get("artifacts") or []):
        reason_codes.append("doc_action_patch_artifact.patch_artifact_written_boundary_mismatch")
    for key, expected in LIVE_BOUNDARIES.items():
        if key == "patch_artifact_written":
            continue
        if live.get(key) is not expected:
            reason_codes.append(f"doc_action_patch_artifact.{key}_mismatch")


def _validate_artifacts(record: dict[str, Any], artifacts: list[dict[str, Any]], reason_codes: list[str]) -> None:
    root = Path(str(record.get("source_root") or "")).expanduser().resolve(strict=False)
    for artifact in artifacts:
        path = Path(str(artifact.get("artifact_path") or "")).expanduser().resolve(strict=False)
        if artifact.get("artifact_path_under_source_root") is not False:
            reason_codes.append(f"doc_action_patch_artifact.artifact_path_under_source_root:{artifact.get('action_id')}")
        if not path.is_file():
            reason_codes.append(f"doc_action_patch_artifact.artifact_missing:{artifact.get('action_id')}")
            continue
        if artifact.get("artifact_sha256") != _file_sha256(path):
            reason_codes.append(f"doc_action_patch_artifact.artifact_hash_mismatch:{artifact.get('action_id')}")
        text = path.read_text(encoding="utf-8")
        if artifact.get("artifact_line_count") != len(text.splitlines()):
            reason_codes.append(f"doc_action_patch_artifact.artifact_line_count_mismatch:{artifact.get('action_id')}")
        if artifact.get("artifact_size_bytes") != len(text.encode("utf-8")):
            reason_codes.append(f"doc_action_patch_artifact.artifact_size_bytes_mismatch:{artifact.get('action_id')}")
        source_ref = artifact.get("source_ref") or {}
        current_source_ref = _source_ref(root, str(artifact.get("source_path") or ""))
        for field in ("path", "exists", "under_source_root", "sha256", "line_count", "size_bytes", "raw_content_stored"):
            if source_ref.get(field) != current_source_ref.get(field):
                reason_codes.append(
                    f"doc_action_patch_artifact.source_ref_{field}_mismatch:{artifact.get('action_id')}"
                )
        for key in (
            "raw_patch_stored_in_ams_state",
            "raw_source_markdown_stored_in_ams_state",
            "source_file_rewritten",
            "source_file_deleted",
            "source_file_moved",
            "archive_created",
            "generated_surface_rewritten",
        ):
            if artifact.get(key) is not False:
                reason_codes.append(f"doc_action_patch_artifact.artifact_{key}_not_false:{artifact.get('action_id')}")
        if artifact.get("patch_artifact_written") is not True:
            reason_codes.append(f"doc_action_patch_artifact.patch_artifact_written_not_true:{artifact.get('action_id')}")


def _required_gates(
    *,
    readback_receipt: dict[str, Any],
    patch_preview: dict[str, Any],
    approval_packet: dict[str, Any],
    execution_plan: dict[str, Any],
    artifact_root_allowed: bool,
    artifacts: list[dict[str, Any]],
) -> dict[str, bool]:
    readback_hash_current = (
        bool(readback_receipt)
        and readback_receipt.get("doc_action_patch_readback_receipt_sha256")
        == _hash_without(readback_receipt, "doc_action_patch_readback_receipt_sha256")
    )
    return {
        "readback_receipt_present": bool(readback_receipt.get("doc_action_patch_readback_receipt_id")),
        "readback_receipt_verified": readback_receipt.get("status") == "readback_verified",
        "readback_receipt_hash_current": readback_hash_current,
        "artifact_root_outside_source_root": artifact_root_allowed,
        "patch_artifacts_written": bool(artifacts),
        "source_hashes_match_patch_preview": bool(artifacts)
        and all(artifact.get("source_hash_matches_patch_preview") is True for artifact in artifacts),
        "artifact_paths_outside_source_root": bool(artifacts)
        and all(artifact.get("artifact_path_under_source_root") is False for artifact in artifacts),
        "artifact_hashes_present": bool(artifacts)
        and all(str(artifact.get("artifact_sha256") or "").startswith("sha256:") for artifact in artifacts),
        "raw_patch_not_stored_in_ams_state": all(
            artifact.get("raw_patch_stored_in_ams_state") is False for artifact in artifacts
        ),
        "source_files_not_modified": all(
            artifact.get("source_file_rewritten") is False
            and artifact.get("source_file_deleted") is False
            and artifact.get("source_file_moved") is False
            for artifact in artifacts
        ),
        "generated_surfaces_not_rewritten": all(
            artifact.get("generated_surface_rewritten") is False for artifact in artifacts
        ),
    }


def _artifact_summary(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    hashes = sorted(str(artifact.get("artifact_sha256") or "") for artifact in artifacts)
    return {
        "artifact_count": len(artifacts),
        "source_hash_match_count": sum(
            1 for artifact in artifacts if artifact.get("source_hash_matches_patch_preview") is True
        ),
        "source_hash_mismatch_count": sum(
            1 for artifact in artifacts if artifact.get("source_hash_matches_patch_preview") is False
        ),
        "artifact_set_sha256": sha256_text(canonical_json(hashes)),
        "total_size_bytes": sum(int(artifact.get("artifact_size_bytes") or 0) for artifact in artifacts),
        "patch_artifact_written": bool(artifacts),
        "raw_patch_stored_in_ams_state": False,
        "raw_source_markdown_stored_in_ams_state": False,
        "source_files_modified": False,
    }


def _status(required_gates: dict[str, bool]) -> str:
    return "artifact_ready" if required_gates and all(required_gates.values()) else "blocked"


def _reason_codes(required_gates: dict[str, bool], status: str) -> list[str]:
    if status == "artifact_ready":
        return ["doc_action_patch_artifact.artifact_ready"]
    missing = [key for key, value in sorted(required_gates.items()) if value is not True]
    return [f"doc_action_patch_artifact.gate_failed:{key}" for key in missing] or [
        "doc_action_patch_artifact.blocked"
    ]


def _artifact_root_allowed(record: dict[str, Any]) -> bool:
    root = Path(str(record.get("source_root") or "")).expanduser().resolve(strict=False)
    artifact_root = Path(str(record.get("artifact_root") or "")).expanduser().resolve(strict=False)
    return artifact_root != root and not path_is_under(artifact_root, root)


def _source_ref(root: Path, relative_path: str) -> dict[str, Any]:
    safe_rel = relative_path.strip("/")
    path = (root / safe_rel).resolve(strict=False)
    under_root = path_is_under(path, root)
    is_file = under_root and path.is_file()
    size_bytes = path.stat().st_size if is_file else None
    sha256 = _file_sha256(path) if is_file else None
    line_count = len(path.read_text(encoding="utf-8").splitlines()) if is_file else None
    return {
        "path": relative_path,
        "exists": bool(is_file),
        "under_source_root": bool(under_root),
        "sha256": sha256,
        "line_count": line_count,
        "size_bytes": size_bytes,
        "raw_content_stored": False,
    }


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_name(source_path: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in source_path)
    return safe.strip("._") or "source"
