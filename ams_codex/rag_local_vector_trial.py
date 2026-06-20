from __future__ import annotations

from copy import deepcopy
import hashlib
import math
from pathlib import Path
import re
from typing import Any

from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .rag_index_plan import validate_rag_index_plan_record
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore


SCHEMA_VERSION = "ams.ams_codex.rag_local_vector_trial.v0"
BOUNDARIES = {
    "network_call_performed": False,
    "provider_call_performed": False,
    "embedding_api_call_performed": False,
    "vector_store_write_performed": False,
    "raw_content_stored": False,
    "query_text_stored": False,
    "embedding_payload_stored": False,
    "vector_payload_stored": False,
    "downloaded_artifact_ingested": False,
    "secret_stored": False,
}
FEATURE_BUCKETS = 4096


class RAGLocalVectorTrialStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        rag_index_plan_id: str,
        query_text: str,
        label: str = "manual-rag-local-vector-trial",
        top_k: int = 5,
        taint_labels: list[str] | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            plan = (state.get("rag_index_plans") or {}).get(rag_index_plan_id)
            if not isinstance(plan, dict):
                raise KeyError(f"unknown rag_index_plan_id: {rag_index_plan_id}")
            record = build_rag_local_vector_trial(
                plan=plan,
                query_text=query_text,
                label=label,
                top_k=top_k,
                taint_labels=taint_labels,
            )
            validation = validate_rag_local_vector_trial_record(record, state=state)
            if not validation["ok"]:
                raise ValueError("; ".join(validation["reason_codes"]))
            trial_id = record["rag_local_vector_trial_id"]
            state.setdefault("rag_local_vector_trials", {})[trial_id] = record
            state.setdefault("indexes", {}).setdefault("rag_local_vector_trial_ids", {})[trial_id] = trial_id
            return deepcopy(record)


def build_rag_local_vector_trial(
    *,
    plan: dict[str, Any],
    query_text: str,
    label: str = "manual-rag-local-vector-trial",
    top_k: int = 5,
    taint_labels: list[str] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    top_k = max(0, int(top_k or 0))
    query_hash = sha256_text(query_text)
    labels = sorted({str(label) for label in (taint_labels or ["local_vector_trial", "hash_refs"]) if str(label)})
    plan_validation = validate_rag_index_plan_record(plan)
    chunk_evidence = _chunk_evidence(plan)
    source_refs = _ranked_source_refs(
        plan=plan,
        chunk_evidence=chunk_evidence,
        query_text=query_text,
        query_hash=query_hash,
        top_k=top_k,
        taint_labels=labels,
    )
    gates = _required_gates(
        plan_validation_ok=plan_validation["ok"],
        chunk_evidence=chunk_evidence,
        source_refs=source_refs,
        top_k=top_k,
        taint_labels=labels,
    )
    status = _status(gates)
    reason_codes = _reason_codes(status, gates)
    record = {
        "schema_version": SCHEMA_VERSION,
        "rag_local_vector_trial_id": stable_id(
            "raglocalvec",
            label,
            plan.get("rag_index_plan_id"),
            plan.get("plan_sha256"),
            query_hash,
            top_k,
            labels,
            now,
        ),
        "label": label,
        "rag_index_plan_id": plan.get("rag_index_plan_id"),
        "rag_index_plan_sha256": plan.get("plan_sha256"),
        "collection": plan.get("collection"),
        "top_k": top_k,
        "taint_labels": labels,
        "query": {
            "query_sha256": query_hash,
            "query_length": len(query_text),
            "query_text_stored": False,
        },
        "local_adapter": {
            "kind": "in_memory_hash_feature_vector",
            "feature_buckets": FEATURE_BUCKETS,
            "feature_payload_stored": False,
            "vector_payload_stored": False,
            "persistent_index_written": False,
            "hnsw_backend_used": False,
            "hnsw_compatible_contract": True,
        },
        "source_verification": {
            "source_root": plan.get("source_root"),
            "plan_valid": plan_validation["ok"],
            "plan_validation_reason_codes": plan_validation["reason_codes"],
            "chunk_count": len(plan.get("chunks") or []),
            "verified_chunk_count": sum(1 for item in chunk_evidence if item.get("verified")),
            "file_mismatch_count": sum(1 for item in chunk_evidence if not item.get("file_hash_matches")),
            "chunk_mismatch_count": sum(1 for item in chunk_evidence if not item.get("chunk_hash_matches")),
            "raw_content_stored": False,
        },
        "source_refs": source_refs,
        "source_ref_count": len(source_refs),
        "required_gates": gates,
        "boundaries": dict(BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["rag_local_vector_trial_sha256"] = _hash_without(record, "rag_local_vector_trial_sha256")
    return deepcopy(record)


def validate_rag_local_vector_trial_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("rag_local_vector_trial.schema.json", record, location="rag_local_vector_trial")
    except SchemaValidationError:
        reason_codes.append("rag_local_vector_trial.schema_invalid")
    expected_hash = record.get("rag_local_vector_trial_sha256")
    if expected_hash and expected_hash != _hash_without(record, "rag_local_vector_trial_sha256"):
        reason_codes.append("rag_local_vector_trial.hash_mismatch")
    plan = (state.get("rag_index_plans") or {}).get(record.get("rag_index_plan_id"))
    if not isinstance(plan, dict):
        reason_codes.append("rag_local_vector_trial.plan_missing")
    elif record.get("rag_index_plan_sha256") != plan.get("plan_sha256"):
        reason_codes.append("rag_local_vector_trial.plan_hash_mismatch")
    for key, expected in BOUNDARIES.items():
        if (record.get("boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"rag_local_vector_trial.{key}_not_false")
    if int(record.get("source_ref_count") or 0) != len(record.get("source_refs") or []):
        reason_codes.append("rag_local_vector_trial.source_ref_count_mismatch")
    for source_ref in record.get("source_refs") or []:
        for forbidden in ("text", "content", "raw", "raw_content", "embedding", "vector", "tokens", "features"):
            if forbidden in source_ref:
                reason_codes.append("rag_local_vector_trial.raw_or_vector_payload_stored")
    gates = _required_gates_from_record(record)
    if record.get("required_gates") != gates:
        reason_codes.append("rag_local_vector_trial.required_gates_mismatch")
    expected_status = _status(gates)
    expected_reasons = _reason_codes(expected_status, gates)
    if record.get("status") != expected_status:
        reason_codes.append("rag_local_vector_trial.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("rag_local_vector_trial.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _chunk_evidence(plan: dict[str, Any]) -> list[dict[str, Any]]:
    root = Path(str(plan.get("source_root") or "")).expanduser().resolve(strict=False)
    source_files = {item.get("path"): item for item in plan.get("source_files") or [] if isinstance(item, dict)}
    rows: list[dict[str, Any]] = []
    for chunk in plan.get("chunks") or []:
        rel = str(chunk.get("source_path") or "")
        source = source_files.get(rel) or {}
        path = (root / rel).resolve(strict=False)
        path_allowed = _path_under_root(path, root)
        raw = (
            path.read_bytes()
            if path_allowed and path.exists() and path.is_file() and not path.is_symlink()
            else b""
        )
        file_sha = "sha256:" + hashlib.sha256(raw).hexdigest()
        text = raw.decode("utf-8", errors="replace")
        start = int(chunk.get("char_start") or 0)
        end = int(chunk.get("char_end") or start)
        chunk_text = text[start:end]
        chunk_sha = sha256_text(chunk_text)
        file_hash_matches = (
            path_allowed
            and path.exists()
            and path.is_file()
            and not path.is_symlink()
            and file_sha == source.get("sha256")
        )
        chunk_hash_matches = chunk_sha == chunk.get("chunk_sha256")
        feature_set = _features(chunk_text)
        rows.append(
            {
                "chunk_id": chunk.get("chunk_id"),
                "source_path": rel,
                "chunk_sha256": chunk.get("chunk_sha256"),
                "file_hash_matches": file_hash_matches,
                "chunk_hash_matches": chunk_hash_matches,
                "verified": file_hash_matches and chunk_hash_matches,
                "feature_ref_sha256": sha256_text(
                    canonical_json(["features", chunk.get("chunk_id"), sorted(feature_set)])
                ),
                "_features": feature_set,
            }
        )
    return rows


def _ranked_source_refs(
    *,
    plan: dict[str, Any],
    chunk_evidence: list[dict[str, Any]],
    query_text: str,
    query_hash: str,
    top_k: int,
    taint_labels: list[str],
) -> list[dict[str, Any]]:
    query_features = _features(query_text)
    scored = []
    for item in chunk_evidence:
        if not item.get("verified"):
            continue
        chunk_features = set(item.get("_features") or [])
        overlap = len(query_features.intersection(chunk_features))
        denom = math.sqrt(max(1, len(query_features)) * max(1, len(chunk_features)))
        score_bucket = int((overlap / denom) * 1_000_000)
        rank_key = sha256_text(canonical_json([query_hash, item.get("chunk_id"), score_bucket]))
        scored.append(((-score_bucket, rank_key), item, score_bucket))
    refs = []
    for rank, (_, item, score_bucket) in enumerate(sorted(scored, key=lambda row: row[0])[:top_k], start=1):
        chunk_id = str(item.get("chunk_id") or "")
        refs.append(
            {
                "retrieval_source_ref_id": stable_id(
                    "raglocalref",
                    plan.get("rag_index_plan_id"),
                    query_hash,
                    chunk_id,
                    rank,
                ),
                "rank": rank,
                "chunk_id": chunk_id,
                "source_path": item.get("source_path"),
                "chunk_sha256": item.get("chunk_sha256"),
                "feature_ref_sha256": item.get("feature_ref_sha256"),
                "score_ref_sha256": sha256_text(canonical_json(["score", query_hash, chunk_id, score_bucket, rank])),
                "taint_labels": list(taint_labels),
                "content_stored": False,
                "embedding_stored": False,
                "vector_stored": False,
            }
        )
    return refs


def _required_gates(
    *,
    plan_validation_ok: bool,
    chunk_evidence: list[dict[str, Any]],
    source_refs: list[dict[str, Any]],
    top_k: int,
    taint_labels: list[str],
) -> dict[str, bool]:
    return {
        "plan_valid": plan_validation_ok,
        "chunks_verified": bool(chunk_evidence) and all(bool(item.get("verified")) for item in chunk_evidence),
        "source_refs_present": bool(source_refs) if top_k > 0 else True,
        "top_k_respected": len(source_refs) <= top_k,
        "hash_refs_taint_present": "hash_refs" in taint_labels,
        "raw_content_not_stored": True,
        "query_text_not_stored": True,
        "embedding_payload_not_stored": True,
        "vector_payload_not_stored": True,
        "network_not_used": True,
    }


def _required_gates_from_record(record: dict[str, Any]) -> dict[str, bool]:
    source = record.get("source_verification") or {}
    query = record.get("query") or {}
    adapter = record.get("local_adapter") or {}
    refs = record.get("source_refs") or []
    top_rank = max([int(ref.get("rank") or 0) for ref in refs] or [0])
    labels = set(record.get("taint_labels") or [])
    labels.update(label for ref in refs for label in (ref.get("taint_labels") or []))
    boundaries = record.get("boundaries") or {}
    return {
        "plan_valid": source.get("plan_valid") is True,
        "chunks_verified": int(source.get("chunk_count") or 0) > 0
        and source.get("verified_chunk_count") == source.get("chunk_count")
        and source.get("file_mismatch_count") == 0
        and source.get("chunk_mismatch_count") == 0,
        "source_refs_present": int(record.get("source_ref_count") or 0) > 0
        if int(record.get("top_k") or 0) > 0
        else True,
        "top_k_respected": int(record.get("source_ref_count") or 0) <= int(record.get("top_k") or 0)
        and top_rank <= int(record.get("top_k") or 0),
        "hash_refs_taint_present": "hash_refs" in labels,
        "raw_content_not_stored": source.get("raw_content_stored") is False and boundaries.get("raw_content_stored") is False,
        "query_text_not_stored": query.get("query_text_stored") is False and boundaries.get("query_text_stored") is False,
        "embedding_payload_not_stored": adapter.get("feature_payload_stored") is False
        and boundaries.get("embedding_payload_stored") is False,
        "vector_payload_not_stored": adapter.get("vector_payload_stored") is False
        and boundaries.get("vector_payload_stored") is False,
        "network_not_used": boundaries.get("network_call_performed") is False,
    }


def _status(gates: dict[str, bool]) -> str:
    if not gates.get("plan_valid"):
        return "deny"
    return "allow" if all(gates.values()) else "defer"


def _reason_codes(status: str, gates: dict[str, bool]) -> list[str]:
    if status == "allow":
        return ["rag_local_vector_trial.allow"]
    return sorted(f"rag_local_vector_trial.{key}_missing" for key, ok in gates.items() if not ok)


def _features(text: str) -> set[int]:
    tokens = re.findall(r"[A-Za-z0-9_]{2,}", text.lower())
    return {int(sha256_text(token)[7:15], 16) % FEATURE_BUCKETS for token in tokens}


def _path_under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
