from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .architecture_audit import build_architecture_audit, validate_architecture_audit_record
from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore


SNAPSHOT_SCHEMA_VERSION = "ams.ams.codebase_spider_graph_snapshot.v0"
NODE_SCHEMA_VERSION = "ams.ams.codebase_graph_node.v0"
EDGE_SCHEMA_VERSION = "ams.ams.codebase_graph_edge.v0"
QUERY_SCHEMA_VERSION = "ams.ams.codebase_graph_query_receipt.v0"

STATUSES = {"allow", "defer", "deny"}
QUERY_KINDS = {"impact_slice", "related_tests", "stale_graph_check"}
EDGE_TYPES = {"imports", "imported_by", "tests", "tested_by"}


class CodebaseSpiderGraphStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        package_name: str = "ams",
        label: str = "manual-codebase-spider-graph",
        architecture_audit_id: str | None = None,
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            audit = None
            if architecture_audit_id:
                audit = (state.get("architecture_audits") or {}).get(architecture_audit_id)
                if not isinstance(audit, dict):
                    raise KeyError(f"unknown architecture_audit_id: {architecture_audit_id}")
            if audit is None:
                candidate = build_architecture_audit(source_root=source_root, package_name=package_name)
                audit_id = candidate["architecture_audit_id"]
                stored_audit = state.setdefault("architecture_audits", {}).get(audit_id)
                if isinstance(stored_audit, dict):
                    audit = stored_audit
                else:
                    audit = candidate
                    state.setdefault("architecture_audits", {})[audit_id] = audit
                    state.setdefault("indexes", {}).setdefault("architecture_audit_ids", {})[audit_id] = audit_id
            record_set = build_codebase_spider_graph(
                source_root=source_root,
                package_name=package_name,
                label=label,
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
            return deepcopy(record_set)


class CodebaseGraphQueryStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        query_kind: str,
        paths: list[str],
        depth: int = 1,
        snapshot_id: str | None = None,
        label: str = "manual-codebase-graph-query",
    ) -> dict[str, Any]:
        with self.store.locked() as state:
            receipt = build_codebase_graph_query_receipt(
                state=state,
                source_root=source_root,
                query_kind=query_kind,
                paths=paths,
                depth=depth,
                snapshot_id=snapshot_id,
                label=label,
            )
            receipt_id = receipt["codebase_graph_query_receipt_id"]
            state.setdefault("codebase_graph_query_receipts", {})[receipt_id] = receipt
            state.setdefault("indexes", {}).setdefault("codebase_graph_query_receipt_ids", {})[
                receipt_id
            ] = receipt_id
            return deepcopy(receipt)


def build_codebase_spider_graph(
    *,
    source_root: str | Path,
    package_name: str = "ams",
    label: str = "manual-codebase-spider-graph",
    architecture_audit: dict[str, Any] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False)
    audit = architecture_audit or build_architecture_audit(source_root=root, package_name=package_name, now=now)
    source_snapshot = _graph_source_snapshot(audit.get("file_summaries") or [])
    snapshot_id = stable_id("cbgraph", str(root), package_name, source_snapshot, label, now)
    nodes = _nodes_from_audit(audit, snapshot_id=snapshot_id, source_root=str(root), label=label, now=now)
    nodes.extend(_test_nodes(root, snapshot_id=snapshot_id, source_root=str(root), label=label, package_name=package_name, now=now))
    nodes_by_path = {node["path"]: node for node in nodes}
    edges = _edges_from_audit(audit, nodes_by_path, snapshot_id=snapshot_id, source_root=str(root), label=label, now=now)
    edges.extend(
        _test_edges(
            nodes_by_path,
            package_name=package_name,
            snapshot_id=snapshot_id,
            source_root=str(root),
            label=label,
            now=now,
        )
    )
    nodes = sorted(nodes, key=lambda node: node["path"])
    edges = sorted(edges, key=lambda edge: (edge["from_path"], edge["edge_type"], edge["to_path"]))
    node_refs = [
        {
            "path": node["path"],
            "codebase_graph_node_id": node["codebase_graph_node_id"],
            "codebase_graph_node_sha256": node["codebase_graph_node_sha256"],
        }
        for node in nodes
    ]
    edge_refs = [
        {
            "codebase_graph_edge_id": edge["codebase_graph_edge_id"],
            "codebase_graph_edge_sha256": edge["codebase_graph_edge_sha256"],
            "edge_type": edge["edge_type"],
        }
        for edge in edges
    ]
    graph_summary = {
        "file_nodes": len([node for node in nodes if node["node_type"] == "file"]),
        "test_nodes": len([node for node in nodes if node["node_type"] == "test_file"]),
        "import_edges": len([edge for edge in edges if edge["edge_type"] == "imports"]),
        "test_edges": len([edge for edge in edges if edge["edge_type"] == "tests"]),
        "reverse_edges": len([edge for edge in edges if edge["edge_type"] in {"imported_by", "tested_by"}]),
        "raw_source_stored": False,
    }
    reason_codes = _snapshot_reason_codes(nodes=nodes, edges=edges, architecture_audit=audit)
    status = "allow" if reason_codes == ["codebase_spider_graph.allow"] else "defer"
    snapshot = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "codebase_spider_graph_snapshot_id": snapshot_id,
        "label": label,
        "source_root": str(root),
        "package_name": package_name,
        "analyzer": {
            "engine": "python_ast",
            "phase": "static_python",
            "network_required": False,
            "raw_source_stored": False,
        },
        "architecture_audit_ref": {
            "architecture_audit_id": audit["architecture_audit_id"],
            "architecture_audit_sha256": audit["architecture_audit_sha256"],
            "status": audit["status"],
        },
        "source_snapshot_sha256": _snapshot_hash(nodes),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "node_refs": node_refs,
        "edge_refs": edge_refs,
        "graph_summary": graph_summary,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    snapshot["codebase_spider_graph_snapshot_sha256"] = _hash_without(
        snapshot,
        "codebase_spider_graph_snapshot_sha256",
    )
    return {"snapshot": deepcopy(snapshot), "nodes": deepcopy(nodes), "edges": deepcopy(edges), "architecture_audit": deepcopy(audit)}


def build_codebase_graph_query_receipt(
    *,
    state: dict[str, Any],
    source_root: str | Path,
    query_kind: str,
    paths: list[str],
    depth: int = 1,
    snapshot_id: str | None = None,
    label: str = "manual-codebase-graph-query",
    now: str | None = None,
) -> dict[str, Any]:
    if query_kind not in QUERY_KINDS:
        raise ValueError(f"unsupported query_kind: {query_kind}")
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False)
    snapshot = _snapshot_for_query(state, snapshot_id=snapshot_id, source_root=str(root))
    if not snapshot:
        raise KeyError("no codebase spider graph snapshot available")
    normalized_paths, rejected_paths = _normalize_query_paths(paths)
    depth = max(0, min(int(depth), 8))
    nodes = _snapshot_nodes(state, snapshot)
    edges = _snapshot_edges(state, snapshot)
    stale_paths = rejected_paths + _stale_paths(
        root,
        nodes,
        normalized_paths if normalized_paths else [node["path"] for node in nodes],
    )
    graph_fresh = not stale_paths
    if query_kind == "impact_slice":
        result = _impact_slice(normalized_paths, edges, depth=depth)
    elif query_kind == "related_tests":
        result = _related_tests(normalized_paths, edges)
    else:
        result = {"stale_paths": stale_paths, "checked_paths": normalized_paths or [node["path"] for node in nodes]}
    result["raw_source_stored"] = False
    reason_codes = ["codebase_graph_query.allow"] if graph_fresh else ["codebase_graph_query.graph_stale"]
    status = "allow" if graph_fresh else "defer"
    receipt = {
        "schema_version": QUERY_SCHEMA_VERSION,
        "codebase_graph_query_receipt_id": stable_id(
            "cbgquery",
            snapshot["codebase_spider_graph_snapshot_id"],
            query_kind,
            normalized_paths,
            depth,
            result,
            now,
        ),
        "label": label,
        "source_root": str(root),
        "snapshot_id": snapshot["codebase_spider_graph_snapshot_id"],
        "snapshot_sha256": snapshot["codebase_spider_graph_snapshot_sha256"],
        "query_kind": query_kind,
        "query": {
            "paths": normalized_paths,
            "depth": depth,
            "rejected_paths": rejected_paths,
        },
        "result": result,
        "graph_fresh": graph_fresh,
        "status": status,
        "reason_codes": reason_codes,
        "raw_source_stored": False,
        "created_at": now,
    }
    receipt["codebase_graph_query_receipt_sha256"] = _hash_without(
        receipt,
        "codebase_graph_query_receipt_sha256",
    )
    return deepcopy(receipt)


def validate_codebase_graph_node_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("codebase_graph_node.schema.json", record, location="codebase_graph_node")
    except SchemaValidationError:
        reason_codes.append("codebase_graph_node.schema_invalid")
    if record.get("codebase_graph_node_sha256") != _hash_without(record, "codebase_graph_node_sha256"):
        reason_codes.append("codebase_graph_node.hash_mismatch")
    if record.get("schema_version") != NODE_SCHEMA_VERSION:
        reason_codes.append("codebase_graph_node.schema_version_invalid")
    if record.get("raw_content_stored") is not False:
        reason_codes.append("codebase_graph_node.raw_content_stored_not_false")
    if not str(record.get("source_sha256") or "").startswith("sha256:"):
        reason_codes.append("codebase_graph_node.source_hash_missing")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def validate_codebase_graph_edge_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("codebase_graph_edge.schema.json", record, location="codebase_graph_edge")
    except SchemaValidationError:
        reason_codes.append("codebase_graph_edge.schema_invalid")
    if record.get("codebase_graph_edge_sha256") != _hash_without(record, "codebase_graph_edge_sha256"):
        reason_codes.append("codebase_graph_edge.hash_mismatch")
    if record.get("schema_version") != EDGE_SCHEMA_VERSION:
        reason_codes.append("codebase_graph_edge.schema_version_invalid")
    if record.get("edge_type") not in EDGE_TYPES:
        reason_codes.append("codebase_graph_edge.edge_type_invalid")
    if record.get("raw_content_stored") is not False:
        reason_codes.append("codebase_graph_edge.raw_content_stored_not_false")
    nodes = state.get("codebase_graph_nodes") or {}
    from_node = nodes.get(record.get("from_node_id"))
    to_node = nodes.get(record.get("to_node_id"))
    if not from_node:
        reason_codes.append("codebase_graph_edge.from_node_missing")
    elif from_node.get("path") != record.get("from_path"):
        reason_codes.append("codebase_graph_edge.from_path_mismatch")
    if not to_node:
        reason_codes.append("codebase_graph_edge.to_node_missing")
    elif to_node.get("path") != record.get("to_path"):
        reason_codes.append("codebase_graph_edge.to_path_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def validate_codebase_spider_graph_snapshot_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("codebase_spider_graph_snapshot.schema.json", record, location="codebase_spider_graph_snapshot")
    except SchemaValidationError:
        reason_codes.append("codebase_spider_graph.schema_invalid")
    if record.get("codebase_spider_graph_snapshot_sha256") != _hash_without(
        record,
        "codebase_spider_graph_snapshot_sha256",
    ):
        reason_codes.append("codebase_spider_graph.hash_mismatch")
    if record.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        reason_codes.append("codebase_spider_graph.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("codebase_spider_graph.status_invalid")
    analyzer = record.get("analyzer") or {}
    if analyzer.get("network_required") is not False or analyzer.get("raw_source_stored") is not False:
        reason_codes.append("codebase_spider_graph.live_or_raw_boundary_crossed")
    audit_ref = record.get("architecture_audit_ref") or {}
    audit = (state.get("architecture_audits") or {}).get(audit_ref.get("architecture_audit_id"))
    if not audit:
        reason_codes.append("codebase_spider_graph.architecture_audit_missing")
    else:
        if audit.get("architecture_audit_sha256") != audit_ref.get("architecture_audit_sha256"):
            reason_codes.append("codebase_spider_graph.architecture_audit_hash_mismatch")
        audit_validation = validate_architecture_audit_record(audit)
        if not audit_validation["ok"]:
            reason_codes.append("codebase_spider_graph.architecture_audit_invalid")
    nodes = _snapshot_nodes(state, record)
    edges = _snapshot_edges(state, record)
    if record.get("node_count") != len(nodes):
        reason_codes.append("codebase_spider_graph.node_count_mismatch")
    if record.get("edge_count") != len(edges):
        reason_codes.append("codebase_spider_graph.edge_count_mismatch")
    if nodes and record.get("source_snapshot_sha256") != _snapshot_hash(nodes):
        reason_codes.append("codebase_spider_graph.source_snapshot_mismatch")
    for ref in record.get("node_refs") or []:
        node = (state.get("codebase_graph_nodes") or {}).get(ref.get("codebase_graph_node_id"))
        if not node:
            reason_codes.append("codebase_spider_graph.node_missing")
            continue
        if node.get("path") != ref.get("path"):
            reason_codes.append("codebase_spider_graph.node_path_mismatch")
        if node.get("codebase_graph_node_sha256") != ref.get("codebase_graph_node_sha256"):
            reason_codes.append("codebase_spider_graph.node_hash_mismatch")
        validation = validate_codebase_graph_node_record(node)
        if not validation["ok"]:
            reason_codes.extend(validation["reason_codes"])
    for ref in record.get("edge_refs") or []:
        edge = (state.get("codebase_graph_edges") or {}).get(ref.get("codebase_graph_edge_id"))
        if not edge:
            reason_codes.append("codebase_spider_graph.edge_missing")
            continue
        if edge.get("codebase_graph_edge_sha256") != ref.get("codebase_graph_edge_sha256"):
            reason_codes.append("codebase_spider_graph.edge_hash_mismatch")
        if edge.get("edge_type") != ref.get("edge_type"):
            reason_codes.append("codebase_spider_graph.edge_type_mismatch")
        validation = validate_codebase_graph_edge_record(edge, state=state)
        if not validation["ok"]:
            reason_codes.extend(validation["reason_codes"])
    expected_reasons = _snapshot_reason_codes(nodes=nodes, edges=edges, architecture_audit=audit)
    if record.get("reason_codes") != expected_reasons:
        reason_codes.append("codebase_spider_graph.reason_codes_mismatch")
        for expected in expected_reasons:
            if expected not in (record.get("reason_codes") or []):
                reason_codes.append(expected)
    if record.get("status") == "allow" and record.get("reason_codes") != ["codebase_spider_graph.allow"]:
        reason_codes.append("codebase_spider_graph.allow_reason_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def validate_codebase_graph_query_receipt_record(record: dict[str, Any], *, state: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("codebase_graph_query_receipt.schema.json", record, location="codebase_graph_query_receipt")
    except SchemaValidationError:
        reason_codes.append("codebase_graph_query.schema_invalid")
    if record.get("codebase_graph_query_receipt_sha256") != _hash_without(
        record,
        "codebase_graph_query_receipt_sha256",
    ):
        reason_codes.append("codebase_graph_query.hash_mismatch")
    if record.get("schema_version") != QUERY_SCHEMA_VERSION:
        reason_codes.append("codebase_graph_query.schema_version_invalid")
    if record.get("query_kind") not in QUERY_KINDS:
        reason_codes.append("codebase_graph_query.kind_invalid")
    if record.get("raw_source_stored") is not False:
        reason_codes.append("codebase_graph_query.raw_source_stored_not_false")
    snapshot = (state.get("codebase_spider_graph_snapshots") or {}).get(record.get("snapshot_id"))
    expected_graph_fresh = record.get("graph_fresh")
    expected_result = None
    if not snapshot:
        reason_codes.append("codebase_graph_query.snapshot_missing")
    elif snapshot.get("codebase_spider_graph_snapshot_sha256") != record.get("snapshot_sha256"):
        reason_codes.append("codebase_graph_query.snapshot_hash_mismatch")
    else:
        paths, rejected_paths = _normalize_query_paths((record.get("query") or {}).get("paths") or [])
        if paths != ((record.get("query") or {}).get("paths") or []):
            reason_codes.append("codebase_graph_query.path_not_normalized")
        stored_rejected = (record.get("query") or {}).get("rejected_paths") or []
        depth = int((record.get("query") or {}).get("depth") or 0)
        nodes = _snapshot_nodes(state, snapshot)
        edges = _snapshot_edges(state, snapshot)
        stale_paths = stored_rejected + _stale_paths(
            Path(str(record.get("source_root") or ".")).expanduser().resolve(strict=False),
            nodes,
            paths if paths else [node["path"] for node in nodes],
        )
        expected_graph_fresh = not stale_paths
        if record.get("query_kind") == "impact_slice":
            expected_result = _impact_slice(paths, edges, depth=depth)
        elif record.get("query_kind") == "related_tests":
            expected_result = _related_tests(paths, edges)
        elif record.get("query_kind") == "stale_graph_check":
            expected_result = {"stale_paths": stale_paths, "checked_paths": paths or [node["path"] for node in nodes]}
        if expected_result is not None:
            expected_result["raw_source_stored"] = False
            if record.get("result") != expected_result:
                reason_codes.append("codebase_graph_query.result_mismatch")
        if record.get("graph_fresh") != expected_graph_fresh:
            reason_codes.append("codebase_graph_query.graph_fresh_mismatch")
    if record.get("graph_fresh") is False and record.get("status") == "allow":
        reason_codes.append("codebase_graph_query.graph_stale_allow")
    expected_status = "allow" if expected_graph_fresh is True else "defer"
    expected_reasons = ["codebase_graph_query.allow"] if expected_graph_fresh is True else [
        "codebase_graph_query.graph_stale"
    ]
    if record.get("status") != expected_status:
        reason_codes.append("codebase_graph_query.status_mismatch")
    if record.get("reason_codes") != expected_reasons:
        reason_codes.append("codebase_graph_query.reason_codes_mismatch")
    if (record.get("result") or {}).get("raw_source_stored") is not False:
        reason_codes.append("codebase_graph_query.result_raw_source_stored")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def latest_codebase_spider_graph_snapshot(
    state: dict[str, Any],
    *,
    source_root: str | Path | None = None,
) -> dict[str, Any] | None:
    root = str(Path(source_root).expanduser().resolve(strict=False)) if source_root else None
    candidates = []
    for record in (state.get("codebase_spider_graph_snapshots") or {}).values():
        if root and record.get("source_root") != root:
            continue
        candidates.append(record)
    return max(candidates, key=lambda row: str(row.get("created_at") or "")) if candidates else None


def _nodes_from_audit(
    audit: dict[str, Any],
    *,
    snapshot_id: str,
    source_root: str,
    label: str,
    now: str,
) -> list[dict[str, Any]]:
    nodes = []
    for summary in audit.get("file_summaries") or []:
        node = {
            "schema_version": NODE_SCHEMA_VERSION,
            "codebase_graph_node_id": stable_id("cbnode", snapshot_id, summary["path"], summary["sha256"]),
            "label": label,
            "source_root": source_root,
            "snapshot_id": snapshot_id,
            "path": summary["path"],
            "node_type": "file",
            "module": summary.get("module"),
            "area": summary.get("area"),
            "source_sha256": summary["sha256"],
            "line_count": int(summary.get("line_count", 0) or 0),
            "size_bytes": int(summary.get("size_bytes", 0) or 0),
            "raw_content_stored": False,
            "created_at": now,
        }
        node["codebase_graph_node_sha256"] = _hash_without(node, "codebase_graph_node_sha256")
        nodes.append(node)
    return nodes


def _test_nodes(
    root: Path,
    *,
    snapshot_id: str,
    source_root: str,
    label: str,
    package_name: str,
    now: str,
) -> list[dict[str, Any]]:
    tests_dir = root / "tests"
    nodes = []
    if not tests_dir.exists():
        return nodes
    for path in sorted(tests_dir.rglob("test_*.py")):
        if not path.is_file() or path.is_symlink():
            continue
        raw = path.read_bytes()
        rel = path.resolve(strict=False).relative_to(root).as_posix()
        node = {
            "schema_version": NODE_SCHEMA_VERSION,
            "codebase_graph_node_id": stable_id("cbnode", snapshot_id, rel, _sha256_bytes(raw)),
            "label": label,
            "source_root": source_root,
            "snapshot_id": snapshot_id,
            "path": rel,
            "node_type": "test_file",
            "module": _test_module(rel),
            "area": "tests",
            "source_sha256": _sha256_bytes(raw),
            "line_count": len(raw.decode("utf-8", errors="replace").splitlines()),
            "size_bytes": len(raw),
            "raw_content_stored": False,
            "created_at": now,
        }
        node["codebase_graph_node_sha256"] = _hash_without(node, "codebase_graph_node_sha256")
        nodes.append(node)
    return nodes


def _edges_from_audit(
    audit: dict[str, Any],
    nodes_by_path: dict[str, dict[str, Any]],
    *,
    snapshot_id: str,
    source_root: str,
    label: str,
    now: str,
) -> list[dict[str, Any]]:
    edges = []
    for edge in audit.get("import_edges") or []:
        from_node = nodes_by_path.get(edge["from_path"])
        to_node = nodes_by_path.get(edge["to_path"])
        if not from_node or not to_node:
            continue
        edges.append(
            _edge(
                snapshot_id=snapshot_id,
                source_root=source_root,
                label=label,
                from_node=from_node,
                to_node=to_node,
                edge_type="imports",
                confidence=1.0,
                evidence={"kind": "python_ast_import", "detail": edge["import"]},
                now=now,
            )
        )
        edges.append(
            _edge(
                snapshot_id=snapshot_id,
                source_root=source_root,
                label=label,
                from_node=to_node,
                to_node=from_node,
                edge_type="imported_by",
                confidence=1.0,
                evidence={"kind": "python_ast_import_reverse", "detail": edge["import"]},
                now=now,
            )
        )
    return edges


def _test_edges(
    nodes_by_path: dict[str, dict[str, Any]],
    *,
    package_name: str,
    snapshot_id: str,
    source_root: str,
    label: str,
    now: str,
) -> list[dict[str, Any]]:
    edges = []
    for test_node in [node for node in nodes_by_path.values() if node["node_type"] == "test_file"]:
        for source_path in _candidate_sources_for_test(test_node["path"], package_name=package_name):
            source_node = nodes_by_path.get(source_path)
            if not source_node:
                continue
            edges.append(
                _edge(
                    snapshot_id=snapshot_id,
                    source_root=source_root,
                    label=label,
                    from_node=test_node,
                    to_node=source_node,
                    edge_type="tests",
                    confidence=0.8,
                    evidence={"kind": "test_filename_convention", "detail": test_node["path"]},
                    now=now,
                )
            )
            edges.append(
                _edge(
                    snapshot_id=snapshot_id,
                    source_root=source_root,
                    label=label,
                    from_node=source_node,
                    to_node=test_node,
                    edge_type="tested_by",
                    confidence=0.8,
                    evidence={"kind": "test_filename_convention_reverse", "detail": test_node["path"]},
                    now=now,
                )
            )
    return edges


def _edge(
    *,
    snapshot_id: str,
    source_root: str,
    label: str,
    from_node: dict[str, Any],
    to_node: dict[str, Any],
    edge_type: str,
    confidence: float,
    evidence: dict[str, str],
    now: str,
) -> dict[str, Any]:
    record = {
        "schema_version": EDGE_SCHEMA_VERSION,
        "codebase_graph_edge_id": stable_id(
            "cbedge",
            snapshot_id,
            from_node["path"],
            edge_type,
            to_node["path"],
            evidence,
        ),
        "label": label,
        "source_root": source_root,
        "snapshot_id": snapshot_id,
        "from_node_id": from_node["codebase_graph_node_id"],
        "from_path": from_node["path"],
        "to_node_id": to_node["codebase_graph_node_id"],
        "to_path": to_node["path"],
        "edge_type": edge_type,
        "confidence": confidence,
        "evidence": evidence,
        "raw_content_stored": False,
        "created_at": now,
    }
    record["codebase_graph_edge_sha256"] = _hash_without(record, "codebase_graph_edge_sha256")
    return record


def _snapshot_reason_codes(
    *,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    architecture_audit: dict[str, Any] | None,
) -> list[str]:
    reasons: list[str] = []
    if not nodes:
        reasons.append("codebase_spider_graph.no_nodes")
    if architecture_audit and architecture_audit.get("parse_errors"):
        reasons.append("codebase_spider_graph.audit_parse_errors")
    if architecture_audit and architecture_audit.get("status") == "deny":
        reasons.append("codebase_spider_graph.audit_denied")
    missing = _missing_reverse_edges(edges)
    if missing:
        reasons.append("codebase_spider_graph.reverse_edge_missing")
    if any(edge.get("raw_content_stored") is not False for edge in edges):
        reasons.append("codebase_spider_graph.edge_raw_content_stored")
    if any(node.get("raw_content_stored") is not False for node in nodes):
        reasons.append("codebase_spider_graph.node_raw_content_stored")
    return sorted(set(reasons)) or ["codebase_spider_graph.allow"]


def _missing_reverse_edges(edges: list[dict[str, Any]]) -> list[dict[str, str]]:
    edge_keys = {
        (edge.get("from_path"), edge.get("edge_type"), edge.get("to_path"))
        for edge in edges
    }
    missing = []
    reverse = {"imports": "imported_by", "tests": "tested_by"}
    for edge in edges:
        edge_type = edge.get("edge_type")
        if edge_type not in reverse:
            continue
        expected = (edge.get("to_path"), reverse[edge_type], edge.get("from_path"))
        if expected not in edge_keys:
            missing.append(
                {
                    "from_path": str(edge.get("from_path") or ""),
                    "to_path": str(edge.get("to_path") or ""),
                    "edge_type": str(edge_type),
                }
            )
    return missing


def _snapshot_for_query(
    state: dict[str, Any],
    *,
    snapshot_id: str | None,
    source_root: str,
) -> dict[str, Any] | None:
    if snapshot_id:
        return (state.get("codebase_spider_graph_snapshots") or {}).get(snapshot_id)
    return latest_codebase_spider_graph_snapshot(state, source_root=source_root)


def _snapshot_nodes(state: dict[str, Any], snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = []
    for ref in snapshot.get("node_refs") or []:
        node = (state.get("codebase_graph_nodes") or {}).get(ref.get("codebase_graph_node_id"))
        if isinstance(node, dict):
            nodes.append(node)
    return nodes


def _snapshot_edges(state: dict[str, Any], snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    edges = []
    for ref in snapshot.get("edge_refs") or []:
        edge = (state.get("codebase_graph_edges") or {}).get(ref.get("codebase_graph_edge_id"))
        if isinstance(edge, dict):
            edges.append(edge)
    return edges


def _impact_slice(paths: list[str], edges: list[dict[str, Any]], *, depth: int) -> dict[str, Any]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    tests: set[str] = set()
    for edge in edges:
        if edge.get("edge_type") in {"imported_by", "tested_by"}:
            adjacency[str(edge.get("from_path"))].add(str(edge.get("to_path")))
        if edge.get("edge_type") == "tested_by" and edge.get("from_path") in paths:
            tests.add(str(edge.get("to_path")))
    seen = set(paths)
    queue = deque((path, 0) for path in paths)
    while queue:
        path, level = queue.popleft()
        if level >= depth:
            continue
        for target in sorted(adjacency.get(path) or []):
            if target in seen:
                continue
            seen.add(target)
            queue.append((target, level + 1))
            if target.startswith("tests/"):
                tests.add(target)
    return {
        "input_paths": sorted(paths),
        "impact_paths": sorted(seen),
        "related_tests": sorted(tests),
        "depth": depth,
    }


def _related_tests(paths: list[str], edges: list[dict[str, Any]]) -> dict[str, Any]:
    tests: set[str] = set()
    for edge in edges:
        if edge.get("edge_type") == "tested_by" and edge.get("from_path") in paths:
            tests.add(str(edge.get("to_path")))
    return {
        "input_paths": sorted(paths),
        "related_tests": sorted(tests),
    }


def _stale_paths(root: Path, nodes: list[dict[str, Any]], paths: list[str]) -> list[dict[str, Any]]:
    by_path = {node["path"]: node for node in nodes}
    stale = []
    for path in sorted(set(paths)):
        node = by_path.get(path)
        if not node:
            stale.append({"path": path, "reason": "not_in_graph"})
            continue
        current = _current_file_hash(root, path)
        if current is None:
            stale.append({"path": path, "reason": "missing_on_disk"})
        elif current != node.get("source_sha256"):
            stale.append({"path": path, "reason": "hash_mismatch"})
    return stale


def _candidate_sources_for_test(test_path: str, *, package_name: str) -> list[str]:
    stem = Path(test_path).stem
    if not stem.startswith("test_"):
        return []
    target = stem.removeprefix("test_")
    candidates = {
        f"{package_name}/{target}.py",
        f"{package_name}/{target.replace('_test', '')}.py",
    }
    if target.endswith("_governance"):
        candidates.add(f"{package_name}/{target}.py")
    return sorted(candidates)


def _test_module(rel: str) -> str:
    path = Path(rel).with_suffix("")
    return ".".join(path.parts)


def _graph_source_snapshot(file_summaries: list[dict[str, Any]]) -> str:
    material = [
        {
            "path": summary.get("path"),
            "sha256": summary.get("sha256"),
            "size_bytes": summary.get("size_bytes"),
        }
        for summary in file_summaries
    ]
    return sha256_text(canonical_json(sorted(material, key=lambda row: str(row.get("path") or ""))))


def _snapshot_hash(nodes: list[dict[str, Any]]) -> str:
    material = [
        {
            "path": node.get("path"),
            "source_sha256": node.get("source_sha256"),
            "line_count": node.get("line_count"),
            "size_bytes": node.get("size_bytes"),
            "node_type": node.get("node_type"),
        }
        for node in sorted(nodes, key=lambda row: str(row.get("path") or ""))
    ]
    return sha256_text(canonical_json(material))


def _current_file_hash(root: Path, rel: str) -> str | None:
    normalized = _normalize_path(rel)
    if not normalized:
        return None
    path = (root / normalized).resolve(strict=False)
    try:
        path.relative_to(root)
    except ValueError:
        return None
    if not path.exists() or not path.is_file() or path.is_symlink():
        return None
    return _sha256_bytes(path.read_bytes())


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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
