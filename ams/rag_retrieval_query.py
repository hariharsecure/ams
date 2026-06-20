from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .rag_embedding_receipt import validate_rag_embedding_receipt_record
from .rag_payload import contains_forbidden_payload_key
from .store import JsonStore


RETRIEVAL_MODES = {"planned_only", "simulated_refs", "external_observed"}
QUERY_STATUSES = {"blocked", "ready_for_operator_review"}
DEFAULT_TAINT_LABELS = ["project", "hash_refs"]


class RAGRetrievalQueryStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        rag_embedding_receipt_id: str,
        query_sha256: str,
        query_length: int,
        query_ref: str | None = None,
        retrieval_mode: str = "simulated_refs",
        top_k: int = 5,
        taint_labels: list[str] | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            receipt = (state.get("rag_embedding_receipts") or {}).get(rag_embedding_receipt_id)
            if not isinstance(receipt, dict):
                raise KeyError(f"unknown rag_embedding_receipt_id: {rag_embedding_receipt_id}")
            record = build_rag_retrieval_query(
                receipt=receipt,
                state=state,
                query_sha256=query_sha256,
                query_length=query_length,
                query_ref=query_ref,
                retrieval_mode=retrieval_mode,
                top_k=top_k,
                taint_labels=taint_labels,
            )
            validation = validate_rag_retrieval_query_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            query_id = record["rag_retrieval_query_id"]
            state.setdefault("rag_retrieval_queries", {})[query_id] = record
            state.setdefault("indexes", {}).setdefault("rag_retrieval_query_ids", {})[query_id] = query_id
        return deepcopy(record)


def build_rag_retrieval_query(
    *,
    receipt: dict[str, Any],
    state: dict[str, Any],
    query_sha256: str,
    query_length: int,
    query_ref: str | None = None,
    retrieval_mode: str = "simulated_refs",
    top_k: int = 5,
    taint_labels: list[str] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    top_k = max(0, int(top_k or 0))
    labels = _normalize_labels(taint_labels)
    source_refs = _source_refs(
        receipt=receipt,
        query_sha256=query_sha256,
        retrieval_mode=retrieval_mode,
        top_k=top_k,
        taint_labels=labels,
    )
    status, reason_codes = _status_and_reasons(
        receipt=receipt,
        state=state,
        retrieval_mode=retrieval_mode,
        taint_labels=labels,
    )
    record = {
        "schema_version": "ams.ams.rag_retrieval_query.v0",
        "rag_retrieval_query_id": stable_id(
            "ragquery",
            receipt.get("rag_embedding_receipt_id"),
            receipt.get("receipt_sha256"),
            query_sha256,
            query_length,
            query_ref,
            retrieval_mode,
            top_k,
            labels,
            now,
        ),
        "rag_embedding_receipt_id": receipt.get("rag_embedding_receipt_id"),
        "rag_embedding_receipt_sha256": receipt.get("receipt_sha256"),
        "rag_embedding_job_id": receipt.get("rag_embedding_job_id"),
        "rag_embedding_job_sha256": receipt.get("rag_embedding_job_sha256"),
        "rag_index_plan_id": receipt.get("rag_index_plan_id"),
        "rag_index_plan_sha256": receipt.get("rag_index_plan_sha256"),
        "collection": receipt.get("collection"),
        "query_sha256": query_sha256,
        "query_length": int(query_length or 0),
        "query_ref": query_ref,
        "query_text_stored": False,
        "raw_corpus_stored": False,
        "retrieval_mode": retrieval_mode,
        "retrieval_provider": receipt.get("vector_store_provider"),
        "top_k": top_k,
        "taint_labels": labels,
        "source_refs": source_refs,
        "source_ref_count": len(source_refs),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["retrieval_query_sha256"] = _hash_without(record, "retrieval_query_sha256")
    return deepcopy(record)


def validate_rag_retrieval_query_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("retrieval_query_sha256")
    if expected_hash and expected_hash != _hash_without(record, "retrieval_query_sha256"):
        reason_codes.append("rag_retrieval_query.hash_mismatch")
    if record.get("retrieval_mode") not in RETRIEVAL_MODES:
        reason_codes.append("rag_retrieval_query.mode_invalid")
    if record.get("status") not in QUERY_STATUSES:
        reason_codes.append("rag_retrieval_query.status_invalid")
    if not str(record.get("query_sha256") or "").startswith("sha256:"):
        reason_codes.append("rag_retrieval_query.query_hash_missing")
    if int(record.get("query_length") or 0) < 0:
        reason_codes.append("rag_retrieval_query.query_length_invalid")
    for key in ("query_text_stored", "raw_corpus_stored"):
        if record.get(key) is not False:
            reason_codes.append(f"rag_retrieval_query.{key}_not_false")
    labels = _normalize_labels(record.get("taint_labels") or [])
    if "hash_refs" not in labels:
        reason_codes.append("rag_retrieval_query.hash_refs_taint_required")
    receipt = (state.get("rag_embedding_receipts") or {}).get(record.get("rag_embedding_receipt_id"))
    if not isinstance(receipt, dict):
        reason_codes.append("rag_retrieval_query.receipt_missing")
        receipt = {}
    else:
        receipt_validation = validate_rag_embedding_receipt_record(receipt, state=state)
        if not receipt_validation["ok"]:
            reason_codes.append("rag_retrieval_query.receipt_invalid")
        if record.get("rag_embedding_receipt_sha256") != receipt.get("receipt_sha256"):
            reason_codes.append("rag_retrieval_query.receipt_hash_mismatch")
        for field in (
            "rag_embedding_job_id",
            "rag_embedding_job_sha256",
            "rag_index_plan_id",
            "rag_index_plan_sha256",
            "collection",
        ):
            if record.get(field) != receipt.get(field):
                reason_codes.append(f"rag_retrieval_query.{field}_mismatch")
        if record.get("retrieval_provider") != receipt.get("vector_store_provider"):
            reason_codes.append("rag_retrieval_query.retrieval_provider_mismatch")
    if contains_forbidden_payload_key(record.get("source_refs")):
        reason_codes.append("rag_retrieval_query.raw_or_vector_payload_stored")
    expected_refs = _source_refs(
        receipt=receipt,
        query_sha256=str(record.get("query_sha256") or ""),
        retrieval_mode=str(record.get("retrieval_mode") or ""),
        top_k=int(record.get("top_k") or 0),
        taint_labels=labels,
    )
    if record.get("source_refs") != expected_refs:
        reason_codes.append("rag_retrieval_query.source_refs_mismatch")
    if record.get("source_ref_count") != len(record.get("source_refs") or []):
        reason_codes.append("rag_retrieval_query.source_ref_count_mismatch")
    expected_status, expected_reasons = _status_and_reasons(
        receipt=receipt,
        state=state,
        retrieval_mode=str(record.get("retrieval_mode") or ""),
        taint_labels=labels,
    )
    if record.get("status") != expected_status:
        reason_codes.append("rag_retrieval_query.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("rag_retrieval_query.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _source_refs(
    *,
    receipt: dict[str, Any],
    query_sha256: str,
    retrieval_mode: str,
    top_k: int,
    taint_labels: list[str],
) -> list[dict[str, Any]]:
    if retrieval_mode == "planned_only" or receipt.get("status") != "recorded":
        return []
    if retrieval_mode == "simulated_refs" and int((receipt.get("totals") or {}).get("simulated_vectors") or 0) <= 0:
        return []
    if retrieval_mode == "external_observed" and int((receipt.get("totals") or {}).get("observed_vector_writes") or 0) <= 0:
        return []
    candidates = []
    for vector_receipt in receipt.get("vector_receipts") or []:
        vector_ref_id = str(vector_receipt.get("vector_ref_id") or "")
        rank_key = sha256_text(canonical_json([query_sha256, vector_ref_id]))
        candidates.append((rank_key, vector_receipt))
    refs: list[dict[str, Any]] = []
    for rank, (_, vector_receipt) in enumerate(sorted(candidates, key=lambda item: item[0])[:top_k], start=1):
        vector_ref_id = str(vector_receipt.get("vector_ref_id") or "")
        refs.append(
            {
                "retrieval_source_ref_id": stable_id("ragsrc", receipt.get("rag_embedding_receipt_id"), query_sha256, vector_ref_id, rank),
                "rank": rank,
                "chunk_id": vector_receipt.get("chunk_id"),
                "source_path": vector_receipt.get("source_path"),
                "chunk_sha256": vector_receipt.get("chunk_sha256"),
                "vector_ref_id": vector_ref_id,
                "vector_receipt_status": vector_receipt.get("receipt_status"),
                "score_ref_sha256": sha256_text(canonical_json(["score-ref", query_sha256, vector_ref_id, rank])),
                "taint_labels": list(taint_labels),
                "content_stored": False,
            }
        )
    return refs


def _status_and_reasons(
    *,
    receipt: dict[str, Any],
    state: dict[str, Any],
    retrieval_mode: str,
    taint_labels: list[str],
) -> tuple[str, list[str]]:
    if "hash_refs" not in taint_labels:
        return "blocked", ["rag_retrieval_query.hash_refs_taint_required"]
    receipt_validation = validate_rag_embedding_receipt_record(receipt, state=state) if receipt else {"ok": False}
    if not receipt or not receipt_validation["ok"]:
        return "blocked", ["rag_retrieval_query.receipt_invalid"]
    if receipt.get("status") != "recorded":
        return "blocked", ["rag_retrieval_query.receipt_not_recorded"]
    if retrieval_mode == "planned_only":
        return "blocked", ["rag_retrieval_query.planned_only_no_retrieval"]
    if retrieval_mode == "simulated_refs":
        if int((receipt.get("totals") or {}).get("simulated_vectors") or 0) <= 0:
            return "blocked", ["rag_retrieval_query.simulated_vectors_required"]
        return "ready_for_operator_review", ["rag_retrieval_query.simulated_refs_ready"]
    if retrieval_mode == "external_observed":
        if int((receipt.get("totals") or {}).get("observed_vector_writes") or 0) <= 0:
            return "blocked", ["rag_retrieval_query.observed_vector_writes_required"]
        return "ready_for_operator_review", ["rag_retrieval_query.external_refs_ready"]
    return "blocked", ["rag_retrieval_query.mode_invalid"]


def _normalize_labels(labels: list[str] | None) -> list[str]:
    return sorted({str(label) for label in (labels or DEFAULT_TAINT_LABELS) if str(label)})
