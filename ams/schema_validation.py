from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from .workspace import repo_root


class SchemaValidationError(ValueError):
    pass


STORE_COLLECTION_SCHEMAS = {
    "sessions": "session_registry.schema.json",
    "contexts": "attention_context.schema.json",
    "checkpoints": "summary_checkpoint.schema.json",
    "task_runs": "task_run.schema.json",
    "run_events": "run_event.schema.json",
    "ams_events": "ams_event.schema.json",
    "admission_reviews": "admission_review.schema.json",
    "resource_policies": "resource_policy.schema.json",
    "resource_claims": "resource_claim.schema.json",
    "resource_telemetry_samples": "resource_telemetry.schema.json",
    "resource_enforcement_trials": "resource_enforcement_trial.schema.json",
    "shareability_bundles": "shareability_bundle.schema.json",
    "shareability_receiver_trials": "shareability_receiver_trial.schema.json",
    "tool_definitions": "tool_definition.schema.json",
    "surface_definitions": "surface_definition.schema.json",
    "runtime_surfaces": "runtime_surface.schema.json",
    "surface_bindings": "surface_binding.schema.json",
    "surface_promises": "surface_promise.schema.json",
    "shadow_launch_plans": "shadow_launch_plan.schema.json",
    "shadow_runner_transactions": "shadow_runner_transaction.schema.json",
    "attention_signals": "attention_signal.schema.json",
    "manager_interventions": "manager_intervention.schema.json",
    "manager_intervention_deliveries": "manager_intervention_delivery.schema.json",
    "manager_intervention_settlements": "manager_intervention_settlement.schema.json",
    "architecture_audits": "architecture_audit.schema.json",
    "architecture_gate_reviews": "architecture_gate_review.schema.json",
    "rag_index_plans": "rag_index_plan.schema.json",
    "downloaded_artifact_quarantines": "downloaded_artifact_quarantine.schema.json",
    "rag_embedding_jobs": "rag_embedding_job.schema.json",
    "provider_auth_preflights": "provider_auth_preflight.schema.json",
    "rag_embedding_receipts": "rag_embedding_receipt.schema.json",
    "rag_retrieval_queries": "rag_retrieval_query.schema.json",
    "rag_local_vector_trials": "rag_local_vector_trial.schema.json",
    "agent_memory_trials": "agent_memory_trial.schema.json",
    "memory_claims": "memory_claim.schema.json",
    "memory_promotion_reviews": "memory_promotion_review.schema.json",
    "memory_supersession_records": "memory_supersession_record.schema.json",
    "memory_conflict_records": "memory_conflict_record.schema.json",
    "real_agent_trials": "real_agent_trial.schema.json",
    "real_agent_system_trials": "real_agent_system_trial.schema.json",
    "provider_results": "provider_result.schema.json",
    "incident_packets": "incident_packet.schema.json",
    "outbox_items": "outbox_item.schema.json",
    "outbox_receipts": "outbox_receipt.schema.json",
    "store_backup_drills": "store_backup_drill.schema.json",
    "runner_dry_run_parities": "runner_dry_run_parity.schema.json",
    "shadow_approval_packets": "shadow_approval_packet.schema.json",
    "discord_source_packets": "discord_source_packet.schema.json",
    "discord_canary_send_plans": "discord_canary_send_plan.schema.json",
    "discord_canary_receipts": "discord_canary_receipt.schema.json",
    "terminal_source_packets": "terminal_source_packet.schema.json",
    "conformance_packs": "conformance_pack.schema.json",
    "markdown_audits": "markdown_audit.schema.json",
    "readiness_reviews": "readiness_review.schema.json",
    "doc_retirement_plans": "doc_retirement_plan.schema.json",
    "doc_action_execution_plans": "doc_action_execution_plan.schema.json",
    "doc_action_operator_approval_packets": "doc_action_operator_approval_packet.schema.json",
    "doc_action_patch_previews": "doc_action_patch_preview.schema.json",
    "doc_action_patch_readback_receipts": "doc_action_patch_readback_receipt.schema.json",
    "doc_action_patch_artifact_receipts": "doc_action_patch_artifact_receipt.schema.json",
    "doc_action_patch_artifact_approval_packets": "doc_action_patch_artifact_approval_packet.schema.json",
    "doc_action_patch_dry_run_plans": "doc_action_patch_dry_run_plan.schema.json",
    "doc_action_patch_dry_run_readback_receipts": "doc_action_patch_dry_run_readback_receipt.schema.json",
    "doc_action_patch_live_execution_approval_packets": "doc_action_patch_live_execution_approval_packet.schema.json",
    "doc_action_patch_executor_preflights": "doc_action_patch_executor_preflight.schema.json",
    "doc_action_patch_apply_boundary_packets": "doc_action_patch_apply_boundary_packet.schema.json",
    "doc_action_patch_apply_acceptance_packets": "doc_action_patch_apply_acceptance_packet.schema.json",
    "source_write_executor_preflights": "source_write_executor_preflight.schema.json",
    "source_write_backup_preimage_receipts": "source_write_backup_preimage_receipt.schema.json",
    "source_write_executor_leases": "source_write_executor_lease.schema.json",
    "generated_status_snapshots": "generated_status_snapshot.schema.json",
    "session_start_briefs": "session_start_brief.schema.json",
    "markdown_authority_indexes": "markdown_authority_index.schema.json",
    "markdown_authority_entries": "markdown_authority_entry.schema.json",
    "codebase_spider_graph_snapshots": "codebase_spider_graph_snapshot.schema.json",
    "codebase_graph_nodes": "codebase_graph_node.schema.json",
    "codebase_graph_edges": "codebase_graph_edge.schema.json",
    "codebase_graph_query_receipts": "codebase_graph_query_receipt.schema.json",
    "blast_radius_reviews": "blast_radius_review.schema.json",
    "work_mode_decisions": "work_mode_decision.schema.json",
    "simulation_sweeps": "simulation_sweep.schema.json",
    "ams_emulation_trials": "ams_emulation_trial.schema.json",
    "semantic_oracle_reviews": "semantic_oracle_review.schema.json",
    "semantic_hook_records": "semantic_hook_record.schema.json",
    "semantic_hook_runs": "semantic_hook_run.schema.json",
    "semantic_hook_install_plans": "semantic_hook_install_plan.schema.json",
    "semantic_hook_approval_bindings": "semantic_hook_approval_binding.schema.json",
    "semantic_hook_target_snapshots": "semantic_hook_target_snapshot.schema.json",
    "semantic_hook_install_transactions": "semantic_hook_install_transaction.schema.json",
    "semantic_hook_operator_approval_packets": "semantic_hook_operator_approval_packet.schema.json",
    "semantic_hook_operator_readback_receipts": "semantic_hook_operator_readback_receipt.schema.json",
}


@lru_cache(maxsize=None)
def load_schema(filename: str) -> dict[str, Any]:
    path = repo_root() / "schemas" / filename
    with path.open("r", encoding="utf-8") as fh:
        schema = json.load(fh)
    if not isinstance(schema, dict):
        raise SchemaValidationError(f"schema is not an object: {path}")
    return schema


def validate_record(schema_filename: str, record: dict[str, Any], *, location: str = "record") -> None:
    errors: list[str] = []
    _validate_value(record, load_schema(schema_filename), location, errors)
    if errors:
        preview = "; ".join(errors[:8])
        if len(errors) > 8:
            preview += f"; ... {len(errors) - 8} more"
        raise SchemaValidationError(preview)


def validate_state_records(state: dict[str, Any]) -> None:
    for collection, schema_filename in STORE_COLLECTION_SCHEMAS.items():
        records = state.get(collection) or {}
        if not isinstance(records, dict):
            raise SchemaValidationError(f"{collection}: expected object")
        for record_id, record in records.items():
            if not isinstance(record, dict):
                raise SchemaValidationError(f"{collection}.{record_id}: expected object record")
            validate_record(schema_filename, record, location=f"{collection}.{record_id}")


def _validate_value(
    value: Any,
    schema: dict[str, Any],
    path: str,
    errors: list[str],
    root_schema: dict[str, Any] | None = None,
) -> None:
    root_schema = root_schema or schema
    if "$ref" in schema:
        target = _resolve_ref(root_schema, str(schema["$ref"]), path, errors)
        if target is None:
            return
        merged = dict(target)
        merged.update({key: val for key, val in schema.items() if key != "$ref"})
        schema = merged
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
        return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value {value!r} not in enum")
        return

    expected_type = schema.get("type")
    if expected_type is not None and not _matches_type(value, expected_type):
        errors.append(f"{path}: expected type {expected_type!r}")
        return

    if isinstance(value, dict):
        _validate_object(value, schema, path, errors, root_schema)
    elif isinstance(value, list):
        _validate_array(value, schema, path, errors, root_schema)
    elif isinstance(value, str):
        _validate_string(value, schema, path, errors)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        _validate_number(value, schema, path, errors)


def _validate_object(
    value: dict[str, Any],
    schema: dict[str, Any],
    path: str,
    errors: list[str],
    root_schema: dict[str, Any],
) -> None:
    properties = schema.get("properties") or {}
    for key in schema.get("required") or []:
        if key not in value:
            errors.append(f"{path}: missing required property {key!r}")

    additional = schema.get("additionalProperties", True)
    if additional is False:
        for key in value:
            if key not in properties:
                errors.append(f"{path}.{key}: additional property not allowed")
    elif isinstance(additional, dict):
        for key in value:
            if key not in properties:
                _validate_value(value[key], additional, f"{path}.{key}", errors, root_schema)

    for key, child_schema in properties.items():
        if key in value:
            _validate_value(value[key], child_schema, f"{path}.{key}", errors, root_schema)


def _validate_array(
    value: list[Any],
    schema: dict[str, Any],
    path: str,
    errors: list[str],
    root_schema: dict[str, Any],
) -> None:
    if "minItems" in schema and len(value) < int(schema["minItems"]):
        errors.append(f"{path}: expected at least {schema['minItems']} items")
    if schema.get("uniqueItems"):
        seen: set[str] = set()
        for item in value:
            marker = json.dumps(item, sort_keys=True, separators=(",", ":"))
            if marker in seen:
                errors.append(f"{path}: duplicate item {item!r}")
                break
            seen.add(marker)
    item_schema = schema.get("items")
    if isinstance(item_schema, dict):
        for index, item in enumerate(value):
            _validate_value(item, item_schema, f"{path}[{index}]", errors, root_schema)


def _resolve_ref(
    root_schema: dict[str, Any],
    ref: str,
    path: str,
    errors: list[str],
) -> dict[str, Any] | None:
    if not ref.startswith("#/"):
        errors.append(f"{path}: unsupported ref {ref!r}")
        return None
    target: Any = root_schema
    for raw_part in ref[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or part not in target:
            errors.append(f"{path}: unresolved ref {ref!r}")
            return None
        target = target[part]
    if not isinstance(target, dict):
        errors.append(f"{path}: ref {ref!r} is not an object schema")
        return None
    return target


def _validate_string(value: str, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    if "minLength" in schema and len(value) < int(schema["minLength"]):
        errors.append(f"{path}: shorter than minLength {schema['minLength']}")
    if "maxLength" in schema and len(value) > int(schema["maxLength"]):
        errors.append(f"{path}: longer than maxLength {schema['maxLength']}")
    pattern = schema.get("pattern")
    if pattern and not re.search(str(pattern), value):
        errors.append(f"{path}: does not match pattern {pattern!r}")


def _validate_number(value: int | float, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    if "minimum" in schema and value < schema["minimum"]:
        errors.append(f"{path}: below minimum {schema['minimum']}")
    if "maximum" in schema and value > schema["maximum"]:
        errors.append(f"{path}: above maximum {schema['maximum']}")


def _matches_type(value: Any, expected: str | list[str]) -> bool:
    if isinstance(expected, list):
        return any(_matches_type(value, item) for item in expected)
    if expected == "null":
        return value is None
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    return True
