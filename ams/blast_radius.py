from __future__ import annotations

from copy import deepcopy
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from .architecture_audit import build_architecture_audit
from .codebase_spider_graph import (
    build_codebase_graph_query_receipt,
    build_codebase_spider_graph,
    latest_codebase_spider_graph_snapshot,
    validate_codebase_graph_query_receipt_record,
    validate_codebase_spider_graph_snapshot_record,
)
from .models import hash_without as _hash_without, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore


SCHEMA_VERSION = "ams.ams.blast_radius_review.v0"
SOURCE_CHANGE_PATTERNS = (
    "ams/*.py",
    "schemas/*.json",
)
DECISIONS = {"allow", "defer", "deny"}
QUERY_KINDS = ("impact_slice", "related_tests", "stale_graph_check")


class BlastRadiusReviewStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        subject_kind: str,
        subject_id: str,
        paths: list[str],
        change_intent: str = "source_change",
        package_name: str = "ams",
        graph_snapshot_id: str | None = None,
        ensure_graph: bool = True,
        depth: int = 2,
        max_impact_paths: int = 80,
        label: str = "manual-blast-radius-review",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            root = Path(source_root).expanduser().resolve(strict=False)
            snapshot = _snapshot_for_review(
                state,
                source_root=root,
                package_name=package_name,
                graph_snapshot_id=graph_snapshot_id,
                ensure_graph=ensure_graph,
                label=label,
            )
            query_receipts = []
            if snapshot:
                for query_kind in QUERY_KINDS:
                    receipt = build_codebase_graph_query_receipt(
                        state=state,
                        source_root=root,
                        query_kind=query_kind,
                        paths=paths,
                        depth=depth,
                        snapshot_id=snapshot["codebase_spider_graph_snapshot_id"],
                        label=f"{label}:{query_kind}",
                    )
                    query_id = receipt["codebase_graph_query_receipt_id"]
                    state.setdefault("codebase_graph_query_receipts", {})[query_id] = receipt
                    state.setdefault("indexes", {}).setdefault("codebase_graph_query_receipt_ids", {})[
                        query_id
                    ] = query_id
                    query_receipts.append(receipt)

            record = build_blast_radius_review(
                state=state,
                source_root=root,
                subject_kind=subject_kind,
                subject_id=subject_id,
                paths=paths,
                change_intent=change_intent,
                package_name=package_name,
                snapshot=snapshot,
                query_receipts=query_receipts,
                depth=depth,
                max_impact_paths=max_impact_paths,
                label=label,
            )
            validation = validate_blast_radius_review_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            review_id = record["blast_radius_review_id"]
            state.setdefault("blast_radius_reviews", {})[review_id] = record
            state.setdefault("indexes", {}).setdefault("blast_radius_review_ids", {})[review_id] = review_id
            return deepcopy(record)


def build_blast_radius_review(
    *,
    state: dict[str, Any],
    source_root: str | Path,
    subject_kind: str,
    subject_id: str,
    paths: list[str],
    change_intent: str = "source_change",
    package_name: str = "ams",
    snapshot: dict[str, Any] | None = None,
    query_receipts: list[dict[str, Any]] | None = None,
    depth: int = 2,
    max_impact_paths: int = 80,
    label: str = "manual-blast-radius-review",
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False)
    normalized_paths, rejected_paths = _normalize_query_paths(paths)
    scoped_paths = blast_radius_scoped_paths(normalized_paths)
    required = bool(scoped_paths)
    queries = list(query_receipts or [])
    query_refs = [
        {
            "query_kind": query["query_kind"],
            "codebase_graph_query_receipt_id": query["codebase_graph_query_receipt_id"],
            "codebase_graph_query_receipt_sha256": query["codebase_graph_query_receipt_sha256"],
            "status": query["status"],
            "graph_fresh": query["graph_fresh"],
        }
        for query in queries
    ]
    graph_ref = None
    if snapshot:
        graph_ref = {
            "codebase_spider_graph_snapshot_id": snapshot["codebase_spider_graph_snapshot_id"],
            "codebase_spider_graph_snapshot_sha256": snapshot["codebase_spider_graph_snapshot_sha256"],
            "source_snapshot_sha256": snapshot["source_snapshot_sha256"],
            "status": snapshot["status"],
        }
    query_validations = _query_validations(queries, state)
    impact_summary = _impact_summary(
        paths=normalized_paths,
        rejected_paths=rejected_paths,
        query_receipts=queries,
        max_impact_paths=max_impact_paths,
    )
    decision, reason_codes = _decision_and_reasons(
        required=required,
        graph_ref=graph_ref,
        query_receipts=queries,
        query_validations=query_validations,
        impact_summary=impact_summary,
    )
    record = {
        "schema_version": SCHEMA_VERSION,
        "blast_radius_review_id": stable_id(
            "blast",
            subject_kind,
            subject_id,
            normalized_paths,
            graph_ref,
            query_refs,
            decision,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "package_name": package_name,
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "change_intent": change_intent,
        "paths": normalized_paths,
        "scoped_paths": scoped_paths,
        "required": required,
        "graph_snapshot_ref": graph_ref,
        "query_refs": query_refs,
        "impact_summary": impact_summary,
        "decision": decision,
        "reason_codes": reason_codes,
        "raw_source_stored": False,
        "created_at": now,
    }
    record["blast_radius_review_sha256"] = _hash_without(record, "blast_radius_review_sha256")
    return deepcopy(record)


def validate_blast_radius_review_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("blast_radius_review.schema.json", record, location="blast_radius_review")
    except SchemaValidationError:
        reason_codes.append("blast_radius.schema_invalid")
    if record.get("blast_radius_review_sha256") != _hash_without(record, "blast_radius_review_sha256"):
        reason_codes.append("blast_radius.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("blast_radius.schema_version_invalid")
    if record.get("decision") not in DECISIONS:
        reason_codes.append("blast_radius.decision_invalid")
    if record.get("raw_source_stored") is not False:
        reason_codes.append("blast_radius.raw_source_stored_not_false")
    paths = list(record.get("paths") or [])
    scoped_paths = blast_radius_scoped_paths(paths)
    if sorted(record.get("scoped_paths") or []) != scoped_paths:
        reason_codes.append("blast_radius.scoped_paths_mismatch")
    if bool(record.get("required")) != bool(scoped_paths):
        reason_codes.append("blast_radius.required_mismatch")

    graph_ref = record.get("graph_snapshot_ref")
    snapshot = None
    if graph_ref:
        snapshot = (state.get("codebase_spider_graph_snapshots") or {}).get(
            graph_ref.get("codebase_spider_graph_snapshot_id")
        )
        if not snapshot:
            reason_codes.append("blast_radius.graph_snapshot_missing")
        else:
            if snapshot.get("codebase_spider_graph_snapshot_sha256") != graph_ref.get(
                "codebase_spider_graph_snapshot_sha256"
            ):
                reason_codes.append("blast_radius.graph_snapshot_hash_mismatch")
            validation = validate_codebase_spider_graph_snapshot_record(snapshot, state=state)
            if not validation["ok"]:
                reason_codes.append("blast_radius.graph_snapshot_invalid")

    query_receipts: list[dict[str, Any]] = []
    for ref in record.get("query_refs") or []:
        query = (state.get("codebase_graph_query_receipts") or {}).get(ref.get("codebase_graph_query_receipt_id"))
        if not query:
            reason_codes.append("blast_radius.query_missing")
            continue
        if query.get("query_kind") != ref.get("query_kind"):
            reason_codes.append("blast_radius.query_kind_mismatch")
        if query.get("codebase_graph_query_receipt_sha256") != ref.get("codebase_graph_query_receipt_sha256"):
            reason_codes.append("blast_radius.query_hash_mismatch")
        if query.get("status") != ref.get("status"):
            reason_codes.append("blast_radius.query_status_mismatch")
        if query.get("graph_fresh") != ref.get("graph_fresh"):
            reason_codes.append("blast_radius.query_freshness_mismatch")
        query_receipts.append(query)
        validation = validate_codebase_graph_query_receipt_record(query, state=state)
        if not validation["ok"]:
            reason_codes.append("blast_radius.query_invalid")

    expected_summary = _impact_summary(
        paths=paths,
        rejected_paths=list((record.get("impact_summary") or {}).get("rejected_paths") or []),
        query_receipts=query_receipts,
        max_impact_paths=int((record.get("impact_summary") or {}).get("max_impact_paths") or 0),
    )
    if record.get("impact_summary") != expected_summary:
        reason_codes.append("blast_radius.impact_summary_mismatch")

    expected_decision, expected_reasons = _decision_and_reasons(
        required=bool(scoped_paths),
        graph_ref=graph_ref,
        query_receipts=query_receipts,
        query_validations=_query_validations(query_receipts, state),
        impact_summary=expected_summary,
    )
    if record.get("decision") != expected_decision:
        reason_codes.append("blast_radius.decision_mismatch")
    if record.get("reason_codes") != expected_reasons:
        reason_codes.append("blast_radius.reason_codes_mismatch")
        for expected in expected_reasons:
            if expected not in (record.get("reason_codes") or []):
                reason_codes.append(expected)
    if record.get("decision") == "allow" and expected_decision != "allow":
        reason_codes.append("blast_radius.false_allow")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def blast_radius_result_for_request(
    state: dict[str, Any],
    *,
    task_run_id: str,
    request: dict[str, Any],
) -> dict[str, Any]:
    action = str(request.get("action") or "")
    if action not in {"write", "policy_change", "execute"}:
        return {"ok": True, "required": False, "reason_code": "blast_radius.not_required"}
    paths, rejected_paths = _normalize_query_paths(request.get("paths") or [])
    if rejected_paths:
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.blast_radius_unsafe_path",
            "rejected_paths": rejected_paths,
        }
    scoped_paths = blast_radius_scoped_paths(paths)
    if not scoped_paths:
        return {"ok": True, "required": False, "reason_code": "blast_radius.not_required"}
    review_id = request.get("blast_radius_review_id")
    if not review_id:
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.blast_radius_review_required",
            "scoped_paths": scoped_paths,
        }
    review = (state.get("blast_radius_reviews") or {}).get(review_id)
    if not isinstance(review, dict):
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.blast_radius_review_missing",
            "blast_radius_review_id": review_id,
            "scoped_paths": scoped_paths,
        }
    validation = validate_blast_radius_review_record(review, state=state)
    if not validation["ok"]:
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.blast_radius_review_invalid",
            "blast_radius_review_id": review_id,
            "reason_codes": validation["reason_codes"],
            "scoped_paths": scoped_paths,
        }
    if review.get("subject_kind") != "task_run" or review.get("subject_id") != task_run_id:
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.blast_radius_review_subject_mismatch",
            "blast_radius_review_id": review_id,
            "scoped_paths": scoped_paths,
        }
    if sorted(review.get("scoped_paths") or []) != scoped_paths:
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.blast_radius_review_scope_mismatch",
            "blast_radius_review_id": review_id,
            "scoped_paths": scoped_paths,
        }
    if review.get("decision") == "deny":
        return {
            "ok": False,
            "required": True,
            "reason_code": "dispatch.blast_radius_review_denied",
            "blast_radius_review_id": review_id,
            "scoped_paths": scoped_paths,
            "blast_radius_reason_codes": list(review.get("reason_codes") or []),
        }
    return {
        "ok": True,
        "required": True,
        "reason_code": "blast_radius.reviewed",
        "blast_radius_review_id": review_id,
        "decision": review.get("decision"),
        "scoped_paths": scoped_paths,
        "related_tests": list((review.get("impact_summary") or {}).get("related_tests") or []),
    }


def blast_radius_scoped_paths(paths: list[str]) -> list[str]:
    scoped = []
    for path in paths:
        rel = _normalize_path(path)
        if rel and any(fnmatch(rel, pattern) for pattern in SOURCE_CHANGE_PATTERNS):
            scoped.append(rel)
    return sorted(set(scoped))


def _snapshot_for_review(
    state: dict[str, Any],
    *,
    source_root: Path,
    package_name: str,
    graph_snapshot_id: str | None,
    ensure_graph: bool,
    label: str,
) -> dict[str, Any] | None:
    if graph_snapshot_id:
        snapshot = (state.get("codebase_spider_graph_snapshots") or {}).get(graph_snapshot_id)
        if not isinstance(snapshot, dict):
            raise KeyError(f"unknown codebase_spider_graph_snapshot_id: {graph_snapshot_id}")
        return snapshot
    snapshot = latest_codebase_spider_graph_snapshot(state, source_root=source_root)
    if snapshot or not ensure_graph:
        return snapshot
    candidate_audit = build_architecture_audit(source_root=source_root, package_name=package_name)
    audit_id = candidate_audit["architecture_audit_id"]
    stored_audit = state.setdefault("architecture_audits", {}).get(audit_id)
    if isinstance(stored_audit, dict):
        audit = stored_audit
    else:
        audit = candidate_audit
        state.setdefault("architecture_audits", {})[audit_id] = audit
        state.setdefault("indexes", {}).setdefault("architecture_audit_ids", {})[audit_id] = audit_id

    record_set = build_codebase_spider_graph(
        source_root=source_root,
        package_name=package_name,
        label=f"{label}:graph",
        architecture_audit=audit,
    )
    for node in record_set["nodes"]:
        node_id = node["codebase_graph_node_id"]
        state.setdefault("codebase_graph_nodes", {})[node_id] = node
        state.setdefault("indexes", {}).setdefault("codebase_graph_node_ids", {})[node_id] = node_id
    for edge in record_set["edges"]:
        edge_id = edge["codebase_graph_edge_id"]
        state.setdefault("codebase_graph_edges", {})[edge_id] = edge
        state.setdefault("indexes", {}).setdefault("codebase_graph_edge_ids", {})[edge_id] = edge_id
    snapshot = record_set["snapshot"]
    snapshot_id = snapshot["codebase_spider_graph_snapshot_id"]
    state.setdefault("codebase_spider_graph_snapshots", {})[snapshot_id] = snapshot
    state.setdefault("indexes", {}).setdefault("codebase_spider_graph_snapshot_ids", {})[
        snapshot_id
    ] = snapshot_id
    return snapshot


def _impact_summary(
    *,
    paths: list[str],
    rejected_paths: list[dict[str, str]],
    query_receipts: list[dict[str, Any]],
    max_impact_paths: int,
) -> dict[str, Any]:
    impact = next((query for query in query_receipts if query.get("query_kind") == "impact_slice"), None)
    related = next((query for query in query_receipts if query.get("query_kind") == "related_tests"), None)
    stale = next((query for query in query_receipts if query.get("query_kind") == "stale_graph_check"), None)
    impact_paths = list(((impact or {}).get("result") or {}).get("impact_paths") or paths)
    related_tests = list(((related or {}).get("result") or {}).get("related_tests") or [])
    stale_paths = list(((stale or {}).get("result") or {}).get("stale_paths") or [])
    if stale:
        rejected_paths = list(((stale.get("query") or {}).get("rejected_paths") or rejected_paths))
    impact_paths = sorted(set(str(path) for path in impact_paths))
    related_tests = sorted(set(str(path) for path in related_tests))
    stale_paths = sorted(
        [{"path": str(item.get("path") or ""), "reason": str(item.get("reason") or "")} for item in stale_paths],
        key=lambda row: (row["path"], row["reason"]),
    )
    rejected_paths = sorted(
        [{"path": str(item.get("path") or ""), "reason": str(item.get("reason") or "")} for item in rejected_paths],
        key=lambda row: (row["path"], row["reason"]),
    )
    return {
        "input_paths": sorted(set(paths)),
        "impact_paths": impact_paths,
        "impact_count": len(impact_paths),
        "related_tests": related_tests,
        "related_test_count": len(related_tests),
        "stale_paths": stale_paths,
        "rejected_paths": rejected_paths,
        "max_impact_paths": int(max_impact_paths),
        "impact_over_limit": len(impact_paths) > int(max_impact_paths),
        "raw_source_stored": False,
    }


def _decision_and_reasons(
    *,
    required: bool,
    graph_ref: dict[str, Any] | None,
    query_receipts: list[dict[str, Any]],
    query_validations: list[dict[str, Any]],
    impact_summary: dict[str, Any],
) -> tuple[str, list[str]]:
    reasons = []
    if not required:
        if impact_summary.get("rejected_paths"):
            return "defer", ["blast_radius.unsafe_path"]
        return "allow", ["blast_radius.not_required"]
    if not graph_ref:
        reasons.append("blast_radius.graph_required")
    query_kinds = {query.get("query_kind") for query in query_receipts}
    for query_kind in QUERY_KINDS:
        if query_kind not in query_kinds:
            reasons.append(f"blast_radius.query_required:{query_kind}")
    if any(not validation["ok"] for validation in query_validations):
        reasons.append("blast_radius.query_invalid")
    if any(query.get("graph_fresh") is not True for query in query_receipts):
        reasons.append("blast_radius.graph_query_stale")
    if impact_summary.get("rejected_paths"):
        reasons.append("blast_radius.unsafe_path")
    if impact_summary.get("stale_paths"):
        reasons.append("blast_radius.stale_paths")
    if impact_summary.get("impact_over_limit"):
        reasons.append("blast_radius.impact_over_limit")
    if not impact_summary.get("related_tests"):
        reasons.append("blast_radius.related_tests_missing")
    if reasons:
        return "defer", sorted(set(reasons))
    return "allow", ["blast_radius.reviewed"]


def _query_validations(query_receipts: list[dict[str, Any]], state: dict[str, Any]) -> list[dict[str, Any]]:
    return [validate_codebase_graph_query_receipt_record(query, state=state) for query in query_receipts]


def _normalize_query_paths(paths: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    normalized: set[str] = set()
    rejected: list[dict[str, str]] = []
    for raw in paths:
        raw_path = str(raw)
        item = _normalize_path(raw_path)
        if item:
            normalized.add(item)
        elif raw_path:
            rejected.append({"path": raw_path, "reason": "unsafe_path"})
    return sorted(normalized), sorted(rejected, key=lambda row: row["path"])


def _normalize_path(path: str) -> str:
    candidate = Path(str(path))
    if candidate.is_absolute():
        return ""
    parts = []
    for part in candidate.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            return ""
        parts.append(part)
    return Path(*parts).as_posix() if parts else ""
