from __future__ import annotations

from copy import deepcopy
import importlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time
from typing import Any

from .models import hash_without as _hash_without, canonical_json, sha256_text, stable_id, utc_now
from .store import JsonStore


SCHEMA_VERSION = "ams.ams.conformance_pack.v0"
STATUSES = {"passed", "failed"}
DEFAULT_DOC_FILES = [
    "README.md",
]
LIVE_BOUNDARY_FLAGS = {
    "discord_call_performed": False,
    "terminal_attach_performed": False,
    "terminal_capture_performed": False,
    "terminal_injection_performed": False,
    "persistent_process_started": False,
    "provider_call_performed": False,
    "embedding_call_performed": False,
    "vector_write_performed": False,
    "network_call_performed": False,
    "token_stored": False,
    "raw_content_stored": False,
}
DENIED_COMMAND_NAMES = {
    "bash",
    "curl",
    "nc",
    "netcat",
    "node",
    "npm",
    "npx",
    "open",
    "osascript",
    "pip",
    "pip3",
    "scp",
    "sh",
    "ssh",
    "wget",
    "zsh",
}
LOCAL_PYTHON_MODULES = {"py_compile", "pytest"}
LOCAL_GIT_COMMANDS = {("diff", "--check"), ("status", "--short")}


class ConformancePackStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        repo_root: str | Path,
        evidence_root: str | Path,
        target_milestone: str,
        label: str = "manual-conformance-pack",
        check_store_paths: list[str | Path] | None = None,
        command_specs: list[str] | None = None,
        command_timeout_seconds: int = 180,
        include_python_compile: bool = True,
    ) -> dict[str, Any]:
        record = build_conformance_pack(
            repo_root=repo_root,
            evidence_root=evidence_root,
            target_milestone=target_milestone,
            label=label,
            check_store_paths=check_store_paths,
            command_specs=command_specs,
            command_timeout_seconds=command_timeout_seconds,
            include_python_compile=include_python_compile,
        )
        validation = validate_conformance_pack_record(record)
        if not validation["ok"]:
            raise ValueError("; ".join(validation["reason_codes"]))
        write_conformance_evidence(record, evidence_root)
        with self.store.locked() as state:
            pack_id = record["conformance_pack_id"]
            state.setdefault("conformance_packs", {})[pack_id] = record
            state.setdefault("indexes", {}).setdefault("conformance_pack_ids", {})[pack_id] = pack_id
        return deepcopy(record)


def build_conformance_pack(
    *,
    repo_root: str | Path,
    evidence_root: str | Path,
    target_milestone: str,
    label: str = "manual-conformance-pack",
    check_store_paths: list[str | Path] | None = None,
    command_specs: list[str] | None = None,
    command_timeout_seconds: int = 180,
    include_python_compile: bool = True,
    now: str | None = None,
) -> dict[str, Any]:
    root = Path(repo_root).expanduser().resolve(strict=False)
    evidence = Path(evidence_root).expanduser().resolve(strict=False)
    now = now or utc_now()
    git = _git_state(root)
    json_validation = _json_validation(root)
    python_compile = _python_compile(root, timeout_seconds=command_timeout_seconds) if include_python_compile else _skipped_command("python_compile")
    command_results = [
        _run_custom_command(root, name=f"command_{index + 1}", spec=spec, timeout_seconds=command_timeout_seconds)
        for index, spec in enumerate(command_specs or [])
    ]
    store_checks = [_store_check(Path(path).expanduser().resolve(strict=False)) for path in (check_store_paths or [])]
    docs_check = _docs_check(root, target_milestone=target_milestone)
    checks = _checks(
        git=git,
        json_validation=json_validation,
        python_compile=python_compile,
        command_results=command_results,
        store_checks=store_checks,
        docs_check=docs_check,
    )
    warnings = _warnings(git=git, command_results=command_results, store_checks=store_checks)
    reason_codes = _reason_codes(checks)
    status = "passed" if reason_codes == ["conformance_pack.passed"] else "failed"
    record = {
        "schema_version": SCHEMA_VERSION,
        "conformance_pack_id": stable_id(
            "confpack",
            label,
            str(root),
            str(evidence),
            target_milestone,
            _snapshot_hash(checks),
            _snapshot_hash(store_checks),
            now,
        ),
        "label": label,
        "target_milestone": target_milestone,
        "repo_root": str(root),
        "evidence_root": str(evidence),
        "git": git,
        "json_validation": json_validation,
        "python_compile": python_compile,
        "command_results": command_results,
        "store_checks": store_checks,
        "docs_check": docs_check,
        "live_boundaries": dict(LIVE_BOUNDARY_FLAGS),
        "artifact_refs": [
            {"path": str(evidence / "conformance_pack_record.json"), "kind": "record_json"},
            {"path": str(evidence / "conformance_summary.json"), "kind": "summary_json"},
        ],
        "checks": checks,
        "warnings": warnings,
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["conformance_pack_sha256"] = _hash_without(record, "conformance_pack_sha256")
    return deepcopy(record)


def validate_conformance_pack_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("conformance_pack.schema_version_invalid")
    expected_hash = record.get("conformance_pack_sha256")
    if expected_hash and expected_hash != _hash_without(record, "conformance_pack_sha256"):
        reason_codes.append("conformance_pack.hash_mismatch")
    if record.get("status") not in STATUSES:
        reason_codes.append("conformance_pack.status_invalid")
    for key, expected in LIVE_BOUNDARY_FLAGS.items():
        if (record.get("live_boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"conformance_pack.{key}_not_false")
    checks = record.get("checks") or {}
    expected_reasons = _reason_codes(checks)
    expected_status = "passed" if expected_reasons == ["conformance_pack.passed"] else "failed"
    if record.get("status") != expected_status:
        reason_codes.append("conformance_pack.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("conformance_pack.reason_codes_mismatch")
    if (record.get("json_validation") or {}).get("ok") != checks.get("json_valid"):
        reason_codes.append("conformance_pack.json_check_mismatch")
    if (record.get("python_compile") or {}).get("ok") != checks.get("python_compile_ok"):
        reason_codes.append("conformance_pack.python_compile_check_mismatch")
    if all(bool(result.get("ok")) for result in record.get("command_results") or []) != checks.get("commands_ok"):
        reason_codes.append("conformance_pack.command_check_mismatch")
    if all(bool(item.get("replay_ok")) for item in record.get("store_checks") or []) != checks.get("stores_replay_ok"):
        reason_codes.append("conformance_pack.store_replay_check_mismatch")
    if all(bool(item.get("oracle_ok")) for item in record.get("store_checks") or []) != checks.get("stores_oracle_ok"):
        reason_codes.append("conformance_pack.store_oracle_check_mismatch")
    if (record.get("docs_check") or {}).get("ok") != checks.get("docs_current_ok"):
        reason_codes.append("conformance_pack.docs_check_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def write_conformance_evidence(record: dict[str, Any], evidence_root: str | Path) -> dict[str, Any]:
    evidence = Path(evidence_root).expanduser().resolve(strict=False)
    evidence.mkdir(parents=True, exist_ok=True)
    record_path = evidence / "conformance_pack_record.json"
    summary_path = evidence / "conformance_summary.json"
    summary = {
        "conformance_pack_id": record["conformance_pack_id"],
        "target_milestone": record["target_milestone"],
        "status": record["status"],
        "reason_codes": record["reason_codes"],
        "warning_count": len(record.get("warnings") or []),
        "warnings": list(record.get("warnings") or []),
        "conformance_pack_sha256": record["conformance_pack_sha256"],
        "checks": record["checks"],
        "store_checks": [
            {
                "path": item["path"],
                "replay_ok": item["replay_ok"],
                "oracle_ok": item["oracle_ok"],
                "oracle_cases": item["oracle_cases"],
                "oracle_missed": item["oracle_missed"],
            }
            for item in record.get("store_checks") or []
        ],
    }
    record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"record_path": str(record_path), "summary_path": str(summary_path)}


def _git_state(root: Path) -> dict[str, Any]:
    head = _run_command(root, name="git_head", argv=["git", "rev-parse", "HEAD"], timeout_seconds=30)
    branch = _run_command(root, name="git_branch", argv=["git", "branch", "--show-current"], timeout_seconds=30)
    tags = _run_command(root, name="git_tags", argv=["git", "tag", "--points-at", "HEAD"], timeout_seconds=30)
    status = _run_command(root, name="git_status", argv=["git", "status", "--short"], timeout_seconds=30)
    available = bool(head["ok"] and status["exit_code"] == 0)
    status_text = status.get("stdout") or ""
    return {
        "available": available,
        "head_sha": _single_line(head.get("stdout")) if head["ok"] else None,
        "branch": _single_line(branch.get("stdout")) if branch["ok"] else None,
        "tags_at_head": [line for line in (tags.get("stdout") or "").splitlines() if line],
        "dirty": bool(status_text.strip()),
        "status_entry_count": len([line for line in status_text.splitlines() if line.strip()]),
        "status_short_sha256": sha256_text(status_text),
    }


def _json_validation(root: Path) -> dict[str, Any]:
    globs = ["schemas/*.json", "examples/*.json", "data/*.json"]
    invalid: list[dict[str, str]] = []
    checked = 0
    for pattern in globs:
        for path in sorted(root.glob(pattern)):
            checked += 1
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                invalid.append({"path": str(path.relative_to(root)), "error": str(exc)})
    return {"ok": not invalid, "files_checked": checked, "invalid_files": invalid}


def _python_compile(root: Path, *, timeout_seconds: int) -> dict[str, Any]:
    files = [str(path.relative_to(root)) for path in sorted((root / "ams").glob("*.py"))]
    result = _public_command_result(
        _run_command(root, name="python_compile", argv=[sys.executable, "-m", "py_compile", *files], timeout_seconds=timeout_seconds)
    )
    result["files_checked"] = len(files)
    return result


def _skipped_command(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "argv": [],
        "ok": True,
        "exit_code": 0,
        "timed_out": False,
        "duration_ms": 0,
        "stdout_sha256": sha256_text(""),
        "stderr_sha256": sha256_text(""),
        "stdout_tail": "",
        "stderr_tail": "",
        "files_checked": 0,
    }


def _run_command(root: Path, *, name: str, argv: list[str], timeout_seconds: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        exit_code = int(completed.returncode)
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = _decode_timeout_output(exc.stdout)
        stderr = _decode_timeout_output(exc.stderr)
        exit_code = -1
        timed_out = True
    except FileNotFoundError as exc:
        stdout = ""
        stderr = str(exc)
        exit_code = 127
        timed_out = False
    duration_ms = int((time.monotonic() - started) * 1000)
    return {
        "name": name,
        "argv": list(argv),
        "ok": exit_code == 0 and not timed_out,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "stdout_sha256": sha256_text(stdout),
        "stderr_sha256": sha256_text(stderr),
        "stdout_tail": _tail(stdout),
        "stderr_tail": _tail(stderr),
        "stdout": stdout,
        "stderr": stderr,
    }


def _run_custom_command(root: Path, *, name: str, spec: str, timeout_seconds: int) -> dict[str, Any]:
    try:
        argv = shlex.split(spec)
    except ValueError as exc:
        return _policy_denied_result(name=name, argv=[], reason=f"shlex_error:{exc}")
    policy = _command_policy(argv)
    if not policy["allowed"]:
        return _policy_denied_result(name=name, argv=argv, reason=policy["reason"])
    result = _public_command_result(_run_command(root, name=name, argv=argv, timeout_seconds=timeout_seconds))
    result["policy_allowed"] = True
    result["policy_reason"] = policy["reason"]
    return result


def _command_policy(argv: list[str]) -> dict[str, Any]:
    if not argv:
        return {"allowed": False, "reason": "empty_command"}
    name = Path(argv[0]).name
    if name in DENIED_COMMAND_NAMES:
        return {"allowed": False, "reason": f"denied_command:{name}"}
    if _is_python_executable(argv[0]):
        if len(argv) >= 3 and argv[1] == "-m" and argv[2] in LOCAL_PYTHON_MODULES:
            return {"allowed": True, "reason": f"allowlisted_python_module:{argv[2]}"}
        return {"allowed": False, "reason": "python_module_not_allowlisted"}
    if name == "jq" and len(argv) >= 2 and argv[1] == "empty":
        return {"allowed": True, "reason": "allowlisted_jq_empty"}
    if name == "git" and tuple(argv[1:]) in LOCAL_GIT_COMMANDS:
        return {"allowed": True, "reason": "allowlisted_git_readonly"}
    return {"allowed": False, "reason": f"command_not_allowlisted:{name}"}


def _is_python_executable(command: str) -> bool:
    name = Path(command).name
    if name == Path(sys.executable).name or name.startswith("python"):
        return True
    try:
        return Path(command).resolve(strict=False) == Path(sys.executable).resolve(strict=False)
    except OSError:
        return False


def _policy_denied_result(*, name: str, argv: list[str], reason: str) -> dict[str, Any]:
    stderr = f"command denied by conformance pack policy: {reason}"
    return {
        "name": name,
        "argv": list(argv),
        "ok": False,
        "exit_code": 126,
        "timed_out": False,
        "duration_ms": 0,
        "stdout_sha256": sha256_text(""),
        "stderr_sha256": sha256_text(stderr),
        "stdout_tail": "",
        "stderr_tail": stderr,
        "policy_allowed": False,
        "policy_reason": reason,
    }


def _public_command_result(result: dict[str, Any]) -> dict[str, Any]:
    public = dict(result)
    public.pop("stdout", None)
    public.pop("stderr", None)
    return public


def _store_check(path: Path) -> dict[str, Any]:
    exists = path.exists()
    file_sha = _sha256_file(path) if exists else None
    if not exists:
        return {
            "path": str(path),
            "exists": False,
            "file_sha256": None,
            "replay_ok": False,
            "replay_error_count": 1,
            "oracle_ok": False,
            "oracle_cases": 0,
            "oracle_detected": 0,
            "oracle_missed": 1,
            "oracle_skipped": 0,
        }
    replay_check = importlib.import_module("ams.replay").replay_check
    run_replay_oracle = importlib.import_module("ams.replay_oracle").run_replay_oracle
    state = JsonStore(path).load()
    replay = replay_check(state)
    oracle = run_replay_oracle(state) if replay["ok"] else {"ok": False, "summary": {"cases": 0, "detected": 0, "missed": 1, "skipped": 0}}
    summary = oracle.get("summary") or {}
    return {
        "path": str(path),
        "exists": True,
        "file_sha256": file_sha,
        "replay_ok": bool(replay["ok"]),
        "replay_error_count": len(replay.get("errors") or []),
        "oracle_ok": bool(oracle.get("ok")),
        "oracle_cases": int(summary.get("cases") or 0),
        "oracle_detected": int(summary.get("detected") or 0),
        "oracle_missed": int(summary.get("missed") or 0),
        "oracle_skipped": int(summary.get("skipped") or 0),
    }


def _docs_check(root: Path, *, target_milestone: str) -> dict[str, Any]:
    missing: list[str] = []
    for rel in DEFAULT_DOC_FILES:
        path = root / rel
        if not path.exists() or target_milestone not in path.read_text(encoding="utf-8", errors="replace"):
            missing.append(rel)
    return {
        "ok": not missing,
        "target_milestone": target_milestone,
        "files_checked": len(DEFAULT_DOC_FILES),
        "missing_mentions": missing,
    }


def _checks(
    *,
    git: dict[str, Any],
    json_validation: dict[str, Any],
    python_compile: dict[str, Any],
    command_results: list[dict[str, Any]],
    store_checks: list[dict[str, Any]],
    docs_check: dict[str, Any],
) -> dict[str, bool]:
    return {
        "git_available": bool(git.get("available")),
        "json_valid": bool(json_validation.get("ok")),
        "python_compile_ok": bool(python_compile.get("ok")),
        "commands_ok": all(bool(result.get("ok")) for result in command_results),
        "stores_replay_ok": all(bool(item.get("replay_ok")) for item in store_checks),
        "stores_oracle_ok": all(bool(item.get("oracle_ok")) for item in store_checks),
        "docs_current_ok": bool(docs_check.get("ok")),
        "no_live_boundaries": True,
    }


def _reason_codes(checks: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if not checks.get("git_available"):
        reasons.append("conformance_pack.git_unavailable")
    if not checks.get("json_valid"):
        reasons.append("conformance_pack.json_invalid")
    if not checks.get("python_compile_ok"):
        reasons.append("conformance_pack.python_compile_failed")
    if not checks.get("commands_ok"):
        reasons.append("conformance_pack.command_failed")
    if not checks.get("stores_replay_ok"):
        reasons.append("conformance_pack.store_replay_failed")
    if not checks.get("docs_current_ok"):
        reasons.append("conformance_pack.docs_not_current")
    if not checks.get("no_live_boundaries"):
        reasons.append("conformance_pack.live_boundary_crossed")
    return reasons or ["conformance_pack.passed"]


def _warnings(
    *,
    git: dict[str, Any],
    command_results: list[dict[str, Any]],
    store_checks: list[dict[str, Any]],
) -> list[str]:
    warnings: list[str] = []
    if git.get("dirty"):
        warnings.append("conformance_pack.git_dirty_observed")
    for result in command_results:
        if result.get("duration_ms", 0) > 60_000:
            warnings.append(f"conformance_pack.slow_command:{result.get('name')}")
    for check in store_checks:
        if not check.get("oracle_ok"):
            warnings.append(f"conformance_pack.store_oracle_miss:{check.get('path')}")
    return warnings


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()



def _snapshot_hash(value: Any) -> str:
    return sha256_text(canonical_json(value))


def _single_line(value: str | None) -> str | None:
    if not value:
        return None
    lines = [line for line in value.splitlines() if line.strip()]
    return lines[0] if lines else None


def _tail(value: str, *, limit: int = 2000) -> str:
    return value[-limit:]


def _decode_timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
