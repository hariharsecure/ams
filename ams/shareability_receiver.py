from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from .models import hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .shareability_bundle import (
    GIT_CONFIG_OVERRIDES,
    GIT_TIMEOUT_SECONDS,
    _git_env,
    _sha256_file,
    validate_shareability_bundle_record,
)
from .store import JsonStore


SCHEMA_VERSION = "ams.ams.shareability_receiver_trial.v0"
STATUSES = {"allow", "defer", "deny"}
BOUNDARIES = {
    "network_call_performed": False,
    "ssh_call_performed": False,
    "remote_push_performed": False,
    "remote_pull_performed": False,
    "remote_url_stored": False,
    "raw_bundle_stored_in_record": False,
    "raw_command_output_stored": False,
    "host_repo_write_performed": False,
    "secret_stored": False,
}


class ShareabilityReceiverTrialStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_bundle: dict[str, Any],
        receiver_root: str | Path,
        label: str = "manual-shareability-receiver-trial",
        run_python_compile: bool = False,
        focused_tests: list[str] | None = None,
    ) -> dict[str, Any]:
        record = build_shareability_receiver_trial(
            source_bundle=source_bundle,
            receiver_root=receiver_root,
            label=label,
            run_python_compile=run_python_compile,
            focused_tests=focused_tests,
        )
        with self.store.locked() as state:
            trial_id = record["shareability_receiver_trial_id"]
            state.setdefault("shareability_receiver_trials", {})[trial_id] = record
            state.setdefault("indexes", {}).setdefault("shareability_receiver_trial_ids", {})[trial_id] = trial_id
            return deepcopy(record)


def build_shareability_receiver_trial(
    *,
    source_bundle: dict[str, Any],
    receiver_root: str | Path,
    label: str = "manual-shareability-receiver-trial",
    run_python_compile: bool = False,
    focused_tests: list[str] | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    receiver = Path(receiver_root).expanduser().resolve(strict=False)
    source_validation = validate_shareability_bundle_record(source_bundle)
    bundle_path = Path(str(source_bundle.get("bundle_path") or "")).expanduser().resolve(strict=False)
    expected_bundle_sha = str(source_bundle.get("bundle_sha256") or "")
    actual_bundle_sha = _sha256_file(bundle_path) if bundle_path.exists() and bundle_path.is_file() else sha256_text("")
    trial_id = stable_id(
        "sharerecv",
        label,
        source_bundle.get("shareability_bundle_id"),
        expected_bundle_sha,
        actual_bundle_sha,
        str(receiver),
        now,
    )
    trial_root = receiver / trial_id
    clone_path = trial_root / "clone"
    trial_root.mkdir(parents=True, exist_ok=True)

    clone_commands = _clone_from_bundle(
        source_bundle=source_bundle,
        bundle_path=bundle_path,
        clone_path=clone_path,
        source_validation_ok=source_validation["ok"],
        bundle_sha_matches=actual_bundle_sha == expected_bundle_sha,
    )
    clone_state = _clone_state(
        clone_path=clone_path,
        receiver_root=receiver,
        source_bundle=source_bundle,
    )
    conformance = _conformance(
        clone_path=clone_path,
        run_python_compile=run_python_compile,
        focused_tests=focused_tests or [],
        clone_ready=clone_state["clone_created"],
    )
    gates = _required_gates(
        source_validation_ok=source_validation["ok"],
        source_bundle=source_bundle,
        bundle_path=bundle_path,
        expected_bundle_sha=expected_bundle_sha,
        actual_bundle_sha=actual_bundle_sha,
        clone_state=clone_state,
        conformance=conformance,
    )
    status = _status(gates)
    reason_codes = _reason_codes(status, gates)
    record = {
        "schema_version": SCHEMA_VERSION,
        "shareability_receiver_trial_id": trial_id,
        "label": label,
        "source_bundle_ref": _source_bundle_ref(
            source_bundle=source_bundle,
            source_validation=source_validation,
            expected_bundle_sha=expected_bundle_sha,
            actual_bundle_sha=actual_bundle_sha,
            bundle_path=bundle_path,
        ),
        "receiver": {
            "receiver_root": str(receiver),
            "trial_root": str(trial_root),
            "clone_path": str(clone_path),
            **clone_state,
        },
        "git_commands": clone_commands,
        "conformance": conformance,
        "required_gates": gates,
        "boundaries": dict(BOUNDARIES),
        "status": status,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["shareability_receiver_trial_sha256"] = _hash_without(record, "shareability_receiver_trial_sha256")
    summary_path = trial_root / "shareability_receiver_summary.json"
    _write_summary(summary_path, record)
    record["artifacts"] = [{"path": str(summary_path), "kind": "summary_json", "sha256": _sha256_file(summary_path)}]
    record["shareability_receiver_trial_sha256"] = _hash_without(record, "shareability_receiver_trial_sha256")
    validation = validate_shareability_receiver_trial_record(record)
    if not validation["ok"]:
        raise ValueError("; ".join(validation["reason_codes"]))
    return deepcopy(record)


def validate_shareability_receiver_trial_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("shareability_receiver_trial.schema.json", record, location="shareability_receiver_trial")
    except SchemaValidationError:
        reason_codes.append("shareability_receiver_trial.schema_invalid")
    expected_hash = record.get("shareability_receiver_trial_sha256")
    if expected_hash and expected_hash != _hash_without(record, "shareability_receiver_trial_sha256"):
        reason_codes.append("shareability_receiver_trial.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("shareability_receiver_trial.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("shareability_receiver_trial.status_invalid")
    for key, expected in BOUNDARIES.items():
        if (record.get("boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"shareability_receiver_trial.{key}_not_false")
    gates = _required_gates_from_record(record)
    if record.get("required_gates") != gates:
        reason_codes.append("shareability_receiver_trial.required_gates_mismatch")
    expected_status = _status(gates)
    expected_reasons = _reason_codes(expected_status, gates)
    if record.get("status") != expected_status:
        reason_codes.append("shareability_receiver_trial.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("shareability_receiver_trial.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _clone_from_bundle(
    *,
    source_bundle: dict[str, Any],
    bundle_path: Path,
    clone_path: Path,
    source_validation_ok: bool,
    bundle_sha_matches: bool,
) -> dict[str, Any]:
    if not source_validation_ok or not bundle_sha_matches or not bundle_path.exists():
        return {
            "git_init": _skipped_command("git_init"),
            "git_fetch_bundle": _skipped_command("git_fetch_bundle"),
            "git_checkout": _skipped_command("git_checkout"),
            "git_fsck": _skipped_command("git_fsck"),
            "git_head": _skipped_command("git_head"),
            "git_tags_at_head": _skipped_command("git_tags_at_head"),
            "git_status": _skipped_command("git_status"),
            "git_remote_names": _skipped_command("git_remote_names"),
        }
    clone_path.parent.mkdir(parents=True, exist_ok=True)
    init = _git(clone_path.parent, ["init", str(clone_path)])
    fetch = _git(clone_path, ["fetch", "--no-tags", str(bundle_path), *_fetch_refspecs(source_bundle)])
    checkout = _git(clone_path, ["checkout", "-B", "ams-receiver", "refs/heads/ams-receiver"])
    fsck = _git(clone_path, ["fsck", "--connectivity-only"])
    head = _git(clone_path, ["rev-parse", "HEAD"])
    tags = _git(clone_path, ["tag", "--points-at", "HEAD"])
    status = _git(clone_path, ["status", "--porcelain"])
    remotes = _git(clone_path, ["remote"])
    return {
        "git_init": _command_summary(init),
        "git_fetch_bundle": _command_summary(fetch),
        "git_checkout": _command_summary(checkout),
        "git_fsck": _command_summary(fsck),
        "git_head": _command_summary(head),
        "git_tags_at_head": _command_summary(tags),
        "git_status": _command_summary(status),
        "git_remote_names": _command_summary(remotes),
    }


def _clone_state(*, clone_path: Path, receiver_root: Path, source_bundle: dict[str, Any]) -> dict[str, Any]:
    if not clone_path.exists():
        return {
            "clone_created": False,
            "clone_path_under_receiver_root": _path_under(clone_path, receiver_root),
            "head_sha": None,
            "head_matches_source": False,
            "branch": None,
            "tags_at_head": [],
            "expected_tags_present": False,
            "dirty_file_count": None,
            "remote_count": None,
            "remote_names_sha256": sha256_text(""),
            "remote_urls_stored": False,
        }
    head = _git(clone_path, ["rev-parse", "HEAD"])
    branch = _git(clone_path, ["branch", "--show-current"])
    tags = _git(clone_path, ["tag", "--points-at", "HEAD"])
    status = _git(clone_path, ["status", "--porcelain"])
    remotes = _git(clone_path, ["remote"])
    tag_lines = [line for line in tags.get("stdout", "").splitlines() if line.strip()]
    remote_lines = [line for line in remotes.get("stdout", "").splitlines() if line.strip()]
    source = source_bundle.get("source") or {}
    expected_tags = set(source.get("tags_at_head") or [])
    return {
        "clone_created": True,
        "clone_path_under_receiver_root": _path_under(clone_path, receiver_root),
        "head_sha": _single_line(head.get("stdout")),
        "head_matches_source": _single_line(head.get("stdout")) == source.get("head_sha"),
        "branch": _single_line(branch.get("stdout")),
        "tags_at_head": sorted(tag_lines),
        "expected_tags_present": expected_tags.issubset(set(tag_lines)),
        "dirty_file_count": len([line for line in status.get("stdout", "").splitlines() if line.strip()]),
        "remote_count": len(remote_lines),
        "remote_names_sha256": sha256_text(json.dumps(sorted(remote_lines), separators=(",", ":"))),
        "remote_urls_stored": False,
    }


def _conformance(
    *,
    clone_path: Path,
    run_python_compile: bool,
    focused_tests: list[str],
    clone_ready: bool,
) -> dict[str, Any]:
    if not clone_ready:
        return {
            "json_validation": {"ok": False, "checked_count": 0, "invalid_count": 0},
            "python_compile": _skipped_command("python_compile"),
            "focused_tests": _skipped_command("focused_tests"),
        }
    return {
        "json_validation": _json_validation(clone_path),
        "python_compile": _run_python_compile(clone_path) if run_python_compile else _skipped_command("python_compile"),
        "focused_tests": _run_focused_tests(clone_path, focused_tests) if focused_tests else _skipped_command("focused_tests"),
    }


def _required_gates(
    *,
    source_validation_ok: bool,
    source_bundle: dict[str, Any],
    bundle_path: Path,
    expected_bundle_sha: str,
    actual_bundle_sha: str,
    clone_state: dict[str, Any],
    conformance: dict[str, Any],
) -> dict[str, bool]:
    return {
        "source_bundle_record_valid": source_validation_ok,
        "source_bundle_status_allow": source_bundle.get("status") == "allow",
        "bundle_file_exists": bundle_path.exists() and bundle_path.is_file(),
        "bundle_sha_matches": bool(expected_bundle_sha) and actual_bundle_sha == expected_bundle_sha,
        "clone_created": clone_state.get("clone_created") is True,
        "clone_path_under_receiver_root": clone_state.get("clone_path_under_receiver_root") is True,
        "head_matches_source": clone_state.get("head_matches_source") is True,
        "expected_tags_present": clone_state.get("expected_tags_present") is True,
        "working_tree_clean": clone_state.get("dirty_file_count") == 0,
        "no_remote_configured": clone_state.get("remote_count") == 0,
        "remote_urls_not_stored": clone_state.get("remote_urls_stored") is False,
        "json_valid": (conformance.get("json_validation") or {}).get("ok") is True,
        "python_compile_ok": _command_ok_or_skipped(conformance.get("python_compile") or {}),
        "focused_tests_ok": _command_ok_or_skipped(conformance.get("focused_tests") or {}),
    }


def _required_gates_from_record(record: dict[str, Any]) -> dict[str, bool]:
    source_ref = record.get("source_bundle_ref") or {}
    receiver = record.get("receiver") or {}
    conformance = record.get("conformance") or {}
    return {
        "source_bundle_record_valid": source_ref.get("source_record_valid") is True,
        "source_bundle_status_allow": source_ref.get("source_status") == "allow",
        "bundle_file_exists": source_ref.get("bundle_file_exists") is True,
        "bundle_sha_matches": source_ref.get("bundle_sha_matches") is True,
        "clone_created": receiver.get("clone_created") is True,
        "clone_path_under_receiver_root": receiver.get("clone_path_under_receiver_root") is True,
        "head_matches_source": receiver.get("head_matches_source") is True,
        "expected_tags_present": receiver.get("expected_tags_present") is True,
        "working_tree_clean": receiver.get("dirty_file_count") == 0,
        "no_remote_configured": receiver.get("remote_count") == 0,
        "remote_urls_not_stored": receiver.get("remote_urls_stored") is False,
        "json_valid": (conformance.get("json_validation") or {}).get("ok") is True,
        "python_compile_ok": _command_ok_or_skipped(conformance.get("python_compile") or {}),
        "focused_tests_ok": _command_ok_or_skipped(conformance.get("focused_tests") or {}),
    }


def _status(gates: dict[str, bool]) -> str:
    if not gates.get("source_bundle_record_valid") or not gates.get("bundle_sha_matches"):
        return "deny"
    return "allow" if all(gates.values()) else "defer"


def _reason_codes(status: str, gates: dict[str, bool]) -> list[str]:
    if status == "allow":
        return ["shareability_receiver_trial.allow"]
    return sorted(f"shareability_receiver_trial.{key}_missing" for key, ok in gates.items() if not ok)


def _source_bundle_ref(
    *,
    source_bundle: dict[str, Any],
    source_validation: dict[str, Any],
    expected_bundle_sha: str,
    actual_bundle_sha: str,
    bundle_path: Path,
) -> dict[str, Any]:
    source = source_bundle.get("source") or {}
    return {
        "shareability_bundle_id": source_bundle.get("shareability_bundle_id"),
        "shareability_bundle_sha256": source_bundle.get("shareability_bundle_sha256"),
        "source_record_valid": source_validation["ok"],
        "source_record_reason_codes": source_validation["reason_codes"],
        "source_status": source_bundle.get("status"),
        "bundle_path": str(bundle_path),
        "bundle_filename": source_bundle.get("bundle_filename"),
        "bundle_file_exists": bundle_path.exists() and bundle_path.is_file(),
        "expected_bundle_sha256": expected_bundle_sha,
        "actual_bundle_sha256": actual_bundle_sha,
        "bundle_sha_matches": bool(expected_bundle_sha) and actual_bundle_sha == expected_bundle_sha,
        "source_head_sha": source.get("head_sha"),
        "source_branch": source.get("branch"),
        "source_tags_at_head": list(source.get("tags_at_head") or []),
        "source_ref_scope": deepcopy(source_bundle.get("ref_scope") or {}),
        "raw_bundle_stored": False,
    }


def _fetch_refspecs(source_bundle: dict[str, Any]) -> list[str]:
    refs = ["HEAD:refs/heads/ams-receiver"]
    for tag in (source_bundle.get("source") or {}).get("tags_at_head") or []:
        refs.append(f"refs/tags/{tag}:refs/tags/{tag}")
    return refs


def _json_validation(root: Path) -> dict[str, Any]:
    invalid = 0
    checked = 0
    for pattern in ("schemas/*.json", "examples/*.json", "data/*.json"):
        for path in sorted(root.glob(pattern)):
            checked += 1
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                invalid += 1
    return {"ok": invalid == 0, "checked_count": checked, "invalid_count": invalid}


def _run_python_compile(root: Path) -> dict[str, Any]:
    if not (root / "ams").exists():
        return _skipped_command("python_compile")
    return _command_summary(
        _run_command(root, [sys.executable, "-m", "compileall", "-q", "ams"], timeout_seconds=180)
    )


def _run_focused_tests(root: Path, tests: list[str]) -> dict[str, Any]:
    existing = [test for test in tests if (root / test).exists()]
    if not existing:
        return _skipped_command("focused_tests")
    return _command_summary(_run_command(root, [sys.executable, "-m", "pytest", *existing, "-q"], timeout_seconds=240))


def _git(cwd: Path, args: list[str]) -> dict[str, Any]:
    return _run_command(cwd, ["git", *GIT_CONFIG_OVERRIDES, *args], timeout_seconds=GIT_TIMEOUT_SECONDS, git_env=True)


def _run_command(cwd: Path, argv: list[str], *, timeout_seconds: int, git_env: bool = False) -> dict[str, Any]:
    env = _git_env() if git_env else None
    completed = subprocess.run(
        argv,
        cwd=str(cwd),
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout_seconds,
    )
    return {
        "argv": argv,
        "return_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _command_summary(result: dict[str, Any]) -> dict[str, Any]:
    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    return {
        "argv_sha256": sha256_text(json.dumps(result.get("argv") or [], separators=(",", ":"))),
        "return_code": int(result.get("return_code") or 0),
        "stdout_sha256": sha256_text(stdout),
        "stderr_sha256": sha256_text(stderr),
        "stdout_line_count": len(stdout.splitlines()),
        "stderr_line_count": len(stderr.splitlines()),
        "raw_output_stored": False,
        "skipped": False,
    }


def _skipped_command(name: str) -> dict[str, Any]:
    return {
        "argv_sha256": sha256_text(json.dumps([name, "skipped"], separators=(",", ":"))),
        "return_code": 0,
        "stdout_sha256": sha256_text(""),
        "stderr_sha256": sha256_text(""),
        "stdout_line_count": 0,
        "stderr_line_count": 0,
        "raw_output_stored": False,
        "skipped": True,
    }


def _command_ok_or_skipped(command: dict[str, Any]) -> bool:
    return command.get("skipped") is True or command.get("return_code") == 0


def _single_line(text: str | None) -> str | None:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[0] if lines else None


def _path_under(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _write_summary(path: Path, record: dict[str, Any]) -> None:
    summary = {
        "shareability_receiver_trial_id": record["shareability_receiver_trial_id"],
        "status": record["status"],
        "reason_codes": record["reason_codes"],
        "source_bundle_ref": record["source_bundle_ref"],
        "receiver": record["receiver"],
        "required_gates": record["required_gates"],
        "boundaries": record["boundaries"],
    }
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
