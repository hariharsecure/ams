from __future__ import annotations

import ast
from collections import defaultdict
from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


STATUSES = {"allow", "defer", "deny"}


class ArchitectureAuditStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path,
        package_name: str = "ams_codex",
    ) -> dict[str, Any]:
        record = build_architecture_audit(source_root=source_root, package_name=package_name)
        with self.store.locked() as state:
            audit_id = record["architecture_audit_id"]
            state.setdefault("architecture_audits", {})[audit_id] = record
            state.setdefault("indexes", {}).setdefault("architecture_audit_ids", {})[audit_id] = audit_id
            return deepcopy(record)


def build_architecture_audit(
    *,
    source_root: str | Path,
    package_name: str = "ams_codex",
    now: str | None = None,
) -> dict[str, Any]:
    root = Path(source_root).expanduser().resolve(strict=False)
    package_dir = root / package_name.replace(".", "/")
    now = now or utc_now()
    files = _python_files(package_dir)
    summaries: list[dict[str, Any]] = []
    parse_errors: list[dict[str, str]] = []
    module_to_path: dict[str, str] = {}
    parsed: dict[str, ast.AST] = {}
    texts: dict[str, str] = {}

    for path in files:
        rel = _rel(path, root)
        module = _module_name(rel)
        module_to_path[module] = rel
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        texts[rel] = text
        try:
            parsed[rel] = ast.parse(text, filename=rel)
        except SyntaxError as exc:
            parse_errors.append({"path": rel, "error": str(exc)})
        summaries.append(
            {
                "path": rel,
                "module": module,
                "area": _area_for(rel),
                "line_count": len(text.splitlines()),
                "size_bytes": len(raw),
                "sha256": _sha256_bytes(raw),
            }
        )

    import_edges = _import_edges(parsed, module_to_path, package_name)
    cycles = _cycles([summary["path"] for summary in summaries], import_edges)
    duplicate_functions = _duplicate_function_bodies(parsed)
    metrics = _metrics(summaries, import_edges, cycles, duplicate_functions)
    status, reason_codes = _status_and_reasons(parse_errors, cycles, duplicate_functions, metrics)
    source_snapshot_sha256 = _snapshot_hash(summaries)
    record = {
        "schema_version": "ams.ams_codex.architecture_audit.v0",
        "architecture_audit_id": stable_id(
            "archaudit",
            str(root),
            package_name,
            source_snapshot_sha256,
            metrics,
        ),
        "source_root": str(root),
        "package_name": package_name,
        "analyzer": {
            "engine": "python_ast",
            "tree_sitter_ready": False,
            "network_required": False,
        },
        "file_count": len(summaries),
        "line_count": int(sum(summary["line_count"] for summary in summaries)),
        "source_snapshot_sha256": source_snapshot_sha256,
        "file_summaries": summaries,
        "import_edges": import_edges,
        "cycles": cycles,
        "duplicate_function_bodies": duplicate_functions,
        "parse_errors": parse_errors,
        "metrics": metrics,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["architecture_audit_sha256"] = _hash_without(record, "architecture_audit_sha256")
    return deepcopy(record)


def validate_architecture_audit_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    expected_hash = record.get("architecture_audit_sha256")
    if expected_hash and expected_hash != _hash_without(record, "architecture_audit_sha256"):
        reason_codes.append("architecture_audit.hash_mismatch")
    if record.get("status") not in STATUSES:
        reason_codes.append("architecture_audit.status_invalid")
    analyzer = record.get("analyzer") or {}
    if analyzer.get("network_required") is not False:
        reason_codes.append("architecture_audit.network_required")
    if record.get("source_snapshot_sha256") != _snapshot_hash(record.get("file_summaries") or []):
        reason_codes.append("architecture_audit.source_snapshot_hash_mismatch")
    summaries = record.get("file_summaries") or []
    paths = {summary.get("path") for summary in summaries if isinstance(summary, dict)}
    if len(paths) != len([summary for summary in summaries if isinstance(summary, dict)]):
        reason_codes.append("architecture_audit.file_summary_duplicate_path")
    for edge in record.get("import_edges") or []:
        if not isinstance(edge, dict):
            reason_codes.append("architecture_audit.edge_not_object")
            continue
        if edge.get("from_path") not in paths:
            reason_codes.append("architecture_audit.edge_from_missing")
        if edge.get("to_path") not in paths:
            reason_codes.append("architecture_audit.edge_to_missing")
    for cycle in record.get("cycles") or []:
        if not isinstance(cycle, dict):
            reason_codes.append("architecture_audit.cycle_not_object")
            continue
        members = cycle.get("members") or []
        if len(members) < 2:
            reason_codes.append("architecture_audit.cycle_too_small")
        if any(member not in paths for member in members):
            reason_codes.append("architecture_audit.cycle_member_missing")
    for group in record.get("duplicate_function_bodies") or []:
        if not isinstance(group, dict):
            reason_codes.append("architecture_audit.duplicate_group_not_object")
            continue
        occurrences = group.get("occurrences") or []
        if int(group.get("occurrence_count", 0) or 0) != len(occurrences):
            reason_codes.append("architecture_audit.duplicate_count_mismatch")
        if len(occurrences) < 2:
            reason_codes.append("architecture_audit.duplicate_group_too_small")
        for occurrence in occurrences:
            if not isinstance(occurrence, dict):
                reason_codes.append("architecture_audit.duplicate_occurrence_not_object")
                continue
            if occurrence.get("path") not in paths:
                reason_codes.append("architecture_audit.duplicate_path_missing")
    if record.get("cycles") and record.get("status") == "allow":
        reason_codes.append("architecture_audit.allow_with_cycles")
    if record.get("parse_errors") and record.get("status") == "allow":
        reason_codes.append("architecture_audit.allow_with_parse_errors")
    return {"ok": not reason_codes, "reason_codes": reason_codes}


def _python_files(package_dir: Path) -> list[Path]:
    if not package_dir.exists():
        return []
    return sorted(
        path
        for path in package_dir.rglob("*.py")
        if path.is_file() and "__pycache__" not in path.parts
    )


def _rel(path: Path, root: Path) -> str:
    return path.resolve(strict=False).relative_to(root).as_posix()


def _module_name(rel_path: str) -> str:
    path = Path(rel_path)
    parts = list(path.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _area_for(rel_path: str) -> str:
    stem = Path(rel_path).stem
    if stem == "__init__":
        return "__init__"
    return stem.split("_", 1)[0]


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _import_edges(
    parsed: dict[str, ast.AST],
    module_to_path: dict[str, str],
    package_name: str,
) -> list[dict[str, str]]:
    edges: set[tuple[str, str, str]] = set()
    for rel, tree in parsed.items():
        current_module = _module_name(rel)
        for node in ast.walk(tree):
            for target_module in _targets_for_node(node, current_module, package_name):
                target_path = module_to_path.get(target_module)
                if target_path and target_path != rel:
                    edges.add((rel, target_path, target_module))
    return [
        {"from_path": from_path, "to_path": to_path, "import": module}
        for from_path, to_path, module in sorted(edges)
    ]


def _targets_for_node(node: ast.AST, current_module: str, package_name: str) -> list[str]:
    if isinstance(node, ast.Import):
        return [
            alias.name
            for alias in node.names
            if alias.name == package_name or alias.name.startswith(package_name + ".")
        ]
    if not isinstance(node, ast.ImportFrom):
        return []
    base = _resolve_import_from_base(node, current_module)
    if base == package_name:
        return [
            f"{package_name}.{alias.name}"
            for alias in node.names
            if alias.name != "*"
        ]
    if base.startswith(package_name + "."):
        return [base]
    return []


def _resolve_import_from_base(node: ast.ImportFrom, current_module: str) -> str:
    if node.level:
        parts = current_module.split(".")
        base_parts = parts[: max(1, len(parts) - node.level)]
        if node.module:
            base_parts.extend(node.module.split("."))
        return ".".join(part for part in base_parts if part)
    return node.module or ""


def _cycles(nodes: list[str], edges: list[dict[str, str]]) -> list[dict[str, Any]]:
    graph: dict[str, list[str]] = {node: [] for node in nodes}
    for edge in edges:
        graph.setdefault(edge["from_path"], []).append(edge["to_path"])
        graph.setdefault(edge["to_path"], [])

    index = 0
    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    groups: list[list[str]] = []

    def strongconnect(node: str) -> None:
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in graph.get(node, []):
            if target not in indexes:
                strongconnect(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[target])
        if lowlinks[node] == indexes[node]:
            group: list[str] = []
            while stack:
                item = stack.pop()
                on_stack.remove(item)
                group.append(item)
                if item == node:
                    break
            if len(group) > 1:
                groups.append(sorted(group))

    for node in sorted(graph):
        if node not in indexes:
            strongconnect(node)
    return [{"members": group, "size": len(group)} for group in sorted(groups, key=lambda row: (len(row), row))]


def _duplicate_function_bodies(parsed: dict[str, ast.AST]) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rel, tree in parsed.items():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if len(getattr(node, "body", []) or []) < 2:
                continue
            normalized = deepcopy(node)
            normalized.name = "_"
            digest = sha256_text(ast.dump(normalized, include_attributes=False))
            buckets[digest].append(
                {
                    "path": rel,
                    "function": node.name,
                    "line": int(getattr(node, "lineno", 0) or 0),
                }
            )
    groups = []
    for digest, occurrences in sorted(buckets.items()):
        if len(occurrences) < 2:
            continue
        groups.append(
            {
                "function_body_sha256": digest,
                "occurrence_count": len(occurrences),
                "occurrences": sorted(occurrences, key=lambda row: (row["path"], row["line"], row["function"])),
            }
        )
    return groups[:20]


def _metrics(
    summaries: list[dict[str, Any]],
    import_edges: list[dict[str, str]],
    cycles: list[dict[str, Any]],
    duplicate_functions: list[dict[str, Any]],
) -> dict[str, Any]:
    total_lines = sum(int(summary.get("line_count", 0) or 0) for summary in summaries)
    largest_lines = max([int(summary.get("line_count", 0) or 0) for summary in summaries] or [0])
    same_area_edges = 0
    area_by_path = {summary["path"]: summary["area"] for summary in summaries}
    for edge in import_edges:
        if area_by_path.get(edge["from_path"]) == area_by_path.get(edge["to_path"]):
            same_area_edges += 1
    return {
        "modularity": {
            "internal_edges": len(import_edges),
            "same_area_edges": same_area_edges,
            "same_area_edge_ratio": round(same_area_edges / len(import_edges), 4) if import_edges else 1.0,
        },
        "acyclicity": {
            "cycle_count": len(cycles),
            "cyclic_file_count": len({member for cycle in cycles for member in cycle.get("members", [])}),
        },
        "depth": {
            "max_import_depth": _max_import_depth([summary["path"] for summary in summaries], import_edges, cycles),
        },
        "equality": {
            "largest_file_line_count": largest_lines,
            "largest_file_line_share": round(largest_lines / total_lines, 4) if total_lines else 0.0,
        },
        "redundancy": {
            "duplicate_function_group_count": len(duplicate_functions),
            "duplicate_function_occurrence_count": sum(
                int(group.get("occurrence_count", 0) or 0) for group in duplicate_functions
            ),
        },
    }


def _max_import_depth(nodes: list[str], edges: list[dict[str, str]], cycles: list[dict[str, Any]]) -> int:
    cycle_members = {member for cycle in cycles for member in cycle.get("members", [])}
    graph: dict[str, list[str]] = {node: [] for node in nodes if node not in cycle_members}
    for edge in edges:
        if edge["from_path"] in cycle_members or edge["to_path"] in cycle_members:
            continue
        graph.setdefault(edge["from_path"], []).append(edge["to_path"])
        graph.setdefault(edge["to_path"], [])
    memo: dict[str, int] = {}

    def depth(node: str) -> int:
        if node in memo:
            return memo[node]
        memo[node] = 0
        children = graph.get(node) or []
        if children:
            memo[node] = 1 + max(depth(child) for child in children)
        return memo[node]

    return max([depth(node) for node in graph] or [0])


def _status_and_reasons(
    parse_errors: list[dict[str, str]],
    cycles: list[dict[str, Any]],
    duplicate_functions: list[dict[str, Any]],
    metrics: dict[str, Any],
) -> tuple[str, list[str]]:
    reason_codes: list[str] = []
    status = "allow"
    if parse_errors:
        reason_codes.append("architecture.parse_errors")
        status = "deny"
    if cycles:
        reason_codes.append("architecture.import_cycle")
        status = "deny"
    max_depth = int(((metrics.get("depth") or {}).get("max_import_depth") or 0))
    if max_depth > 12:
        reason_codes.append("architecture.depth_excessive")
        status = "deny"
    elif max_depth > 8:
        reason_codes.append("architecture.depth_high")
        if status == "allow":
            status = "defer"
    share = float(((metrics.get("equality") or {}).get("largest_file_line_share") or 0.0))
    if share >= 0.40:
        reason_codes.append("architecture.largest_file_share_high")
        if status == "allow":
            status = "defer"
    locality = float(((metrics.get("modularity") or {}).get("same_area_edge_ratio") or 0.0))
    internal_edges = int(((metrics.get("modularity") or {}).get("internal_edges") or 0))
    if internal_edges >= 5 and locality < 0.20:
        reason_codes.append("architecture.low_area_locality")
        if status == "allow":
            status = "defer"
    if duplicate_functions:
        reason_codes.append("architecture.duplicate_function_body")
        if status == "allow":
            status = "defer"
    if not reason_codes:
        reason_codes.append("architecture.audit_clean")
    return status, reason_codes


def _snapshot_hash(summaries: list[dict[str, Any]]) -> str:
    normalized = []
    for summary in summaries:
        if not isinstance(summary, dict):
            normalized.append({"invalid": repr(summary)})
            continue
        normalized.append(
            {
                "path": summary.get("path"),
                "size_bytes": summary.get("size_bytes"),
                "sha256": summary.get("sha256"),
            }
        )
    material = sorted(normalized, key=lambda row: str(row.get("path") or row.get("invalid") or ""))
    return sha256_text(canonical_json(material))
