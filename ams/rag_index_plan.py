from __future__ import annotations

from copy import deepcopy
from fnmatch import fnmatch
import hashlib
import mimetypes
from pathlib import Path
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


DEFAULT_ALLOWED_GLOBS = [
    "*.md",
    "ams/*.py",
    "schemas/*.json",
    "examples/*.json",
]

DEFAULT_DENIED_GLOBS = [
    ".git",
    ".git/**",
    ".ams_sim",
    ".ams_sim/**",
    ".pytest_cache",
    ".pytest_cache/**",
    "__pycache__",
    "**/__pycache__/**",
    "*.pyc",
    ".DS_Store",
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "*.pem",
    "*.key",
    "**/*.pem",
    "**/*.key",
    "*token*",
    "*secret*",
    "**/*token*",
    "**/*secret*",
]

EMBEDDING_PROVIDERS = {"none", "openai", "local"}
VECTOR_STORE_PROVIDERS = {"none", "openai_file_search", "local"}


class RAGIndexPlanStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        collection: str = "ams_codebase_docs",
        allowed_globs: list[str] | None = None,
        denied_globs: list[str] | None = None,
        max_file_bytes: int = 1_000_000,
        max_total_bytes: int = 5_000_000,
        chunk_chars: int = 2400,
        embedding_provider: str = "none",
        embedding_model: str | None = None,
        embedding_dimensions: int | None = None,
        vector_store_provider: str = "none",
    ) -> dict[str, Any]:
        record = build_rag_index_plan(
            source_root=source_root,
            collection=collection,
            allowed_globs=allowed_globs,
            denied_globs=denied_globs,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            chunk_chars=chunk_chars,
            embedding_provider=embedding_provider,
            embedding_model=embedding_model,
            embedding_dimensions=embedding_dimensions,
            vector_store_provider=vector_store_provider,
        )
        with self.store.locked() as state:
            plan_id = record["rag_index_plan_id"]
            state.setdefault("rag_index_plans", {})[plan_id] = record
            state.setdefault("indexes", {}).setdefault("rag_index_plan_ids", {})[plan_id] = plan_id
            return deepcopy(record)


def build_rag_index_plan(
    *,
    source_root: str | Path,
    collection: str = "ams_codebase_docs",
    allowed_globs: list[str] | None = None,
    denied_globs: list[str] | None = None,
    max_file_bytes: int = 1_000_000,
    max_total_bytes: int = 5_000_000,
    chunk_chars: int = 2400,
    embedding_provider: str = "none",
    embedding_model: str | None = None,
    embedding_dimensions: int | None = None,
    vector_store_provider: str = "none",
    now: str | None = None,
) -> dict[str, Any]:
    root = Path(source_root).expanduser().resolve(strict=False)
    now = now or utc_now()
    allowed = allowed_globs or list(DEFAULT_ALLOWED_GLOBS)
    denied = denied_globs or list(DEFAULT_DENIED_GLOBS)
    embedding_provider = embedding_provider if embedding_provider in EMBEDDING_PROVIDERS else "none"
    vector_store_provider = vector_store_provider if vector_store_provider in VECTOR_STORE_PROVIDERS else "none"
    source_files: list[dict[str, Any]] = []
    skipped_files: list[dict[str, Any]] = []
    chunks: list[dict[str, Any]] = []
    consumed = 0

    for path in _candidate_files(root):
        rel = _safe_rel(path, root)
        if rel is None:
            continue
        if _matches_any(rel, denied) or not _matches_any(rel, allowed):
            continue
        if path.is_symlink():
            skipped_files.append({"path": rel, "reason": "symlink_denied"})
            continue
        raw = path.read_bytes()
        size = len(raw)
        if size > max_file_bytes:
            skipped_files.append({"path": rel, "reason": "max_file_bytes", "size_bytes": size})
            continue
        if consumed + size > max_total_bytes:
            skipped_files.append({"path": rel, "reason": "max_total_bytes", "size_bytes": size})
            continue
        consumed += size
        text = raw.decode("utf-8", errors="replace")
        file_sha = _sha256_bytes(raw)
        file_chunks = _chunk_refs(
            source_root=str(root),
            rel_path=rel,
            text=text,
            file_sha256=file_sha,
            chunk_chars=chunk_chars,
        )
        chunks.extend(file_chunks)
        source_files.append(
            {
                "path": rel,
                "sha256": file_sha,
                "size_bytes": size,
                "media_type": mimetypes.guess_type(rel)[0] or "text/plain",
                "chunk_count": len(file_chunks),
            }
        )

    source_snapshot_sha256 = _snapshot_hash(source_files, skipped_files)
    record = {
        "schema_version": "ams.ams.rag_index_plan.v0",
        "rag_index_plan_id": stable_id(
            "ragidx",
            str(root),
            collection,
            source_snapshot_sha256,
            embedding_provider,
            embedding_model,
            vector_store_provider,
            chunk_chars,
        ),
        "source_root": str(root),
        "collection": collection,
        "source_policy": {
            "allowed_globs": allowed,
            "denied_globs": denied,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes,
            "follow_symlinks": False,
            "downloaded_files_allowed": False,
            "raw_content_stored": False,
            "network_required": False,
        },
        "embedding": {
            "provider": embedding_provider,
            "model": embedding_model,
            "dimensions": embedding_dimensions,
            "status": "not_requested" if embedding_provider == "none" else "planned",
        },
        "vector_store": {
            "provider": vector_store_provider,
            "name": collection,
            "external_store_id": None,
            "status": "not_created",
        },
        "source_snapshot_sha256": source_snapshot_sha256,
        "source_files": source_files,
        "skipped_files": skipped_files,
        "chunks": chunks,
        "downloaded_artifacts": [],
        "status": "planned",
        "reason_codes": _reason_codes(embedding_provider, vector_store_provider),
        "created_at": now,
    }
    record["plan_sha256"] = _hash_without(record, "plan_sha256")
    return deepcopy(record)


def validate_rag_index_plan_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("plan_sha256")
    if expected_hash and expected_hash != _hash_without(record, "plan_sha256"):
        reason_codes.append("rag_index_plan.hash_mismatch")
    policy = record.get("source_policy") or {}
    for key in ("follow_symlinks", "downloaded_files_allowed", "raw_content_stored", "network_required"):
        if policy.get(key) is not False:
            reason_codes.append(f"rag_index_plan.policy_{key}_not_false")
    if record.get("downloaded_artifacts") != []:
        reason_codes.append("rag_index_plan.downloaded_artifacts_not_empty")
    if record.get("source_snapshot_sha256") != _snapshot_hash(
        record.get("source_files") or [],
        record.get("skipped_files") or [],
    ):
        reason_codes.append("rag_index_plan.source_snapshot_hash_mismatch")
    source_by_path = {}
    for item in record.get("source_files") or []:
        if not isinstance(item, dict):
            reason_codes.append("rag_index_plan.source_file_not_object")
            continue
        source_by_path[item.get("path")] = item
    chunks_by_path: dict[str, int] = {}
    forbidden_chunk_keys = {"text", "content", "raw", "raw_content"}
    for chunk in record.get("chunks") or []:
        if not isinstance(chunk, dict):
            reason_codes.append("rag_index_plan.chunk_not_object")
            continue
        if forbidden_chunk_keys.intersection(chunk):
            reason_codes.append("rag_index_plan.raw_chunk_content_stored")
        source_path = chunk.get("source_path")
        if source_path not in source_by_path:
            reason_codes.append("rag_index_plan.chunk_source_missing")
        if not str(chunk.get("chunk_sha256") or "").startswith("sha256:"):
            reason_codes.append("rag_index_plan.chunk_hash_missing")
        if chunk.get("embedding_status") not in {"not_embedded", "planned", "skipped"}:
            reason_codes.append("rag_index_plan.chunk_embedding_status_invalid")
        chunks_by_path[str(source_path)] = chunks_by_path.get(str(source_path), 0) + 1
    for path, source in source_by_path.items():
        if chunks_by_path.get(str(path), 0) != int(source.get("chunk_count", 0) or 0):
            reason_codes.append("rag_index_plan.source_chunk_count_mismatch")
    embedding = record.get("embedding") or {}
    if embedding.get("provider") not in EMBEDDING_PROVIDERS:
        reason_codes.append("rag_index_plan.embedding_provider_invalid")
    if embedding.get("provider") == "none" and embedding.get("status") != "not_requested":
        reason_codes.append("rag_index_plan.embedding_none_status_invalid")
    if embedding.get("provider") != "none" and embedding.get("status") != "planned":
        reason_codes.append("rag_index_plan.embedding_planned_status_invalid")
    vector_store = record.get("vector_store") or {}
    if vector_store.get("provider") not in VECTOR_STORE_PROVIDERS:
        reason_codes.append("rag_index_plan.vector_store_provider_invalid")
    if vector_store.get("external_store_id") is not None:
        reason_codes.append("rag_index_plan.external_store_id_present")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def _candidate_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file() or path.is_symlink())


def _safe_rel(path: Path, root: Path) -> str | None:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return None


def _matches_any(rel_path: str, patterns: list[str]) -> bool:
    return any(fnmatch(rel_path, pattern) for pattern in patterns)


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _chunk_refs(
    *,
    source_root: str,
    rel_path: str,
    text: str,
    file_sha256: str,
    chunk_chars: int,
) -> list[dict[str, Any]]:
    size = max(1, int(chunk_chars or 1))
    refs = []
    if not text:
        text = ""
    for index, start in enumerate(range(0, max(1, len(text)), size)):
        end = min(len(text), start + size)
        chunk_text = text[start:end]
        chunk_sha = sha256_text(chunk_text)
        refs.append(
            {
                "chunk_id": stable_id("ragchunk", source_root, rel_path, file_sha256, index, chunk_sha),
                "source_path": rel_path,
                "chunk_index": index,
                "char_start": start,
                "char_end": end,
                "chunk_sha256": chunk_sha,
                "embedding_status": "not_embedded",
            }
        )
    return refs


def _reason_codes(embedding_provider: str, vector_store_provider: str) -> list[str]:
    codes = ["rag.local_only", "rag.raw_content_not_stored", "rag.downloads_denied"]
    if embedding_provider == "none":
        codes.append("rag.embeddings_not_created")
    else:
        codes.append(f"rag.embedding_provider_planned:{embedding_provider}")
    if vector_store_provider == "none":
        codes.append("rag.vector_store_not_created")
    else:
        codes.append(f"rag.vector_store_provider_planned:{vector_store_provider}")
    return codes


def _snapshot_hash(source_files: list[dict[str, Any]], skipped_files: list[dict[str, Any]]) -> str:
    normalized_sources = []
    for item in source_files:
        if not isinstance(item, dict):
            normalized_sources.append({"invalid": repr(item)})
            continue
        normalized_sources.append(
            {
                "path": item.get("path"),
                "size_bytes": item.get("size_bytes"),
                "sha256": item.get("sha256"),
                "chunk_count": item.get("chunk_count"),
            }
        )
    normalized_skipped = [
        item if isinstance(item, dict) else {"invalid": repr(item)}
        for item in skipped_files
    ]
    material = {
        "source_files": sorted(
            normalized_sources,
            key=lambda row: str(row.get("path") or row.get("invalid") or ""),
        ),
        "skipped_files": sorted(
            normalized_skipped,
            key=lambda row: str(row.get("path") or row.get("invalid") or ""),
        ),
    }
    return sha256_text(canonical_json(material))
