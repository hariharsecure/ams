from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from .durability import fsync_dir, fsync_path
from .models import canonical_json, hash_without as _hash_without, sha256_text, stable_id, utc_now
from .schema_validation import SchemaValidationError, validate_record
from .store import JsonStore
from .workspace import repo_root


SCHEMA_VERSION = "ams.ams.shareability_bundle.v0"
STATUSES = {"allow", "defer"}
GIT_TIMEOUT_SECONDS = 60
GIT_CONFIG_OVERRIDES = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.file.allow=always",
)
BOUNDARIES = {
    "network_call_performed": False,
    "ssh_call_performed": False,
    "remote_push_performed": False,
    "remote_pull_performed": False,
    "remote_url_stored": False,
    "raw_bundle_stored_in_record": False,
    "secret_stored": False,
}


class ShareabilityBundleStore:
    def __init__(self, store: JsonStore | None = None) -> None:
        self.store = store or JsonStore()

    def create(
        self,
        *,
        source_root: str | Path | None = None,
        output_dir: str | Path,
        label: str = "manual-shareability-bundle",
        include_all_refs: bool = False,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        record = build_shareability_bundle(
            source_root=source_root or repo_root(),
            output_dir=output_dir,
            label=label,
            include_all_refs=include_all_refs,
            overwrite=overwrite,
        )
        with self.store.locked() as state:
            bundle_id = record["shareability_bundle_id"]
            state.setdefault("shareability_bundles", {})[bundle_id] = record
            state.setdefault("indexes", {}).setdefault("shareability_bundle_ids", {})[bundle_id] = bundle_id
            return deepcopy(record)


def build_shareability_bundle(
    *,
    source_root: str | Path,
    output_dir: str | Path,
    label: str = "manual-shareability-bundle",
    include_all_refs: bool = False,
    overwrite: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    now = now or utc_now()
    root = Path(source_root).expanduser().resolve(strict=False)
    out_dir = Path(output_dir).expanduser().resolve(strict=False)
    safe_label = _safe_label(label)
    top_level = _git(root, ["rev-parse", "--show-toplevel"])
    if top_level["return_code"] != 0:
        raise ValueError("source_root is not a git repository")
    repo = Path(top_level["stdout"].strip()).resolve(strict=False)
    head = _git(repo, ["rev-parse", "HEAD"])
    branch = _git(repo, ["branch", "--show-current"])
    tags = _git(repo, ["tag", "--points-at", "HEAD"])
    status = _git(repo, ["status", "--porcelain"])
    remotes = _git(repo, ["remote"])
    fsck = _git(repo, ["fsck", "--connectivity-only"])
    head_sha = head["stdout"].strip()
    tag_names = [line for line in tags["stdout"].splitlines() if line.strip()]
    ref_scope = _ref_scope(include_all_refs=include_all_refs, tags=tag_names)
    bundle_path = out_dir / f"{safe_label}-{head_sha[:12]}.bundle"
    if bundle_path.exists() and not overwrite:
        raise FileExistsError(bundle_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    args = ["bundle", "create", str(bundle_path)]
    args.extend(ref_scope["selected_refs"])
    create = _git(repo, args)
    if create["return_code"] == 0:
        fsync_path(bundle_path)
        fsync_dir(bundle_path.parent)
    verify = _git(repo, ["bundle", "verify", str(bundle_path)]) if bundle_path.exists() else _empty_git_result(
        ["bundle", "verify", str(bundle_path)],
        return_code=1,
        stderr="bundle missing",
    )
    heads = _git(repo, ["bundle", "list-heads", str(bundle_path)]) if bundle_path.exists() else _empty_git_result(
        ["bundle", "list-heads", str(bundle_path)],
        return_code=1,
        stderr="bundle missing",
    )
    bundle_sha = _sha256_file(bundle_path) if bundle_path.exists() else sha256_text("")
    source = _source_summary(
        repo=repo,
        head_sha=head_sha,
        branch=branch["stdout"].strip(),
        tags=tag_names,
        status_text=status["stdout"],
        remote_text=remotes["stdout"],
    )
    git_commands = {
        "rev_parse_toplevel": _command_summary(top_level),
        "rev_parse_head": _command_summary(head),
        "status_porcelain": _command_summary(status),
        "remote_names": _command_summary(remotes),
        "fsck_connectivity": _command_summary(fsck),
        "bundle_create": _command_summary(create),
        "bundle_verify": _command_summary(verify),
        "bundle_list_heads": _command_summary(heads),
    }
    gates = _required_gates(
        source=source,
        ref_scope=ref_scope,
        git_safety=_git_safety_summary(),
        bundle_exists=bundle_path.exists(),
        create=create,
        verify=verify,
        heads=heads,
        fsck=fsck,
    )
    reason_codes = _reason_codes(gates)
    status_value = "allow" if reason_codes == ["shareability_bundle.allow"] else "defer"
    record = {
        "schema_version": SCHEMA_VERSION,
        "shareability_bundle_id": stable_id(
            "sharebundle",
            label,
            str(repo),
            head_sha,
            bundle_sha,
            now,
        ),
        "label": label,
        "source_root": str(repo),
        "output_dir": str(out_dir),
        "bundle_path": str(bundle_path),
        "bundle_filename": bundle_path.name,
        "bundle_sha256": bundle_sha,
        "bundle_size_bytes": bundle_path.stat().st_size if bundle_path.exists() else 0,
        "include_all_refs": bool(include_all_refs),
        "overwrite_allowed": bool(overwrite),
        "source": source,
        "ref_scope": ref_scope,
        "git_safety": _git_safety_summary(),
        "git_commands": git_commands,
        "required_gates": gates,
        "boundaries": dict(BOUNDARIES),
        "status": status_value,
        "reason_codes": reason_codes,
        "created_at": now,
    }
    record["shareability_bundle_sha256"] = _hash_without(record, "shareability_bundle_sha256")
    validation = validate_shareability_bundle_record(record)
    if not validation["ok"]:
        raise ValueError("; ".join(validation["reason_codes"]))
    return deepcopy(record)


def validate_shareability_bundle_record(record: dict[str, Any]) -> dict[str, Any]:
    reason_codes: list[str] = []
    try:
        validate_record("shareability_bundle.schema.json", record, location="shareability_bundle")
    except SchemaValidationError:
        reason_codes.append("shareability_bundle.schema_invalid")
    expected_hash = record.get("shareability_bundle_sha256")
    if expected_hash and expected_hash != _hash_without(record, "shareability_bundle_sha256"):
        reason_codes.append("shareability_bundle.hash_mismatch")
    if record.get("schema_version") != SCHEMA_VERSION:
        reason_codes.append("shareability_bundle.schema_version_invalid")
    if record.get("status") not in STATUSES:
        reason_codes.append("shareability_bundle.status_invalid")
    for key, expected in BOUNDARIES.items():
        if (record.get("boundaries") or {}).get(key) is not expected:
            reason_codes.append(f"shareability_bundle.{key}_not_false")
    if not str(record.get("bundle_sha256") or "").startswith("sha256:"):
        reason_codes.append("shareability_bundle.bundle_sha256_missing")
    source = record.get("source") or {}
    if source.get("remote_urls_stored") is not False:
        reason_codes.append("shareability_bundle.remote_urls_stored_not_false")
    if source.get("remote_names_sha256") != sha256_text(canonical_json(source.get("remote_names") or [])):
        reason_codes.append("shareability_bundle.remote_names_hash_mismatch")
    if record.get("git_safety") != _git_safety_summary():
        reason_codes.append("shareability_bundle.git_safety_mismatch")
    ref_scope = record.get("ref_scope") or {}
    if bool(record.get("include_all_refs")) != bool(ref_scope.get("all_refs_included")):
        reason_codes.append("shareability_bundle.ref_scope_mode_mismatch")
    if not record.get("include_all_refs"):
        expected_refs = _selected_refs_for_tags(source.get("tags_at_head") or [])
        if ref_scope.get("selected_refs") != expected_refs:
            reason_codes.append("shareability_bundle.selected_refs_mismatch")
    gates = _required_gates_from_record(record)
    if record.get("required_gates") != gates:
        reason_codes.append("shareability_bundle.required_gates_mismatch")
    expected_reasons = _reason_codes(gates)
    expected_status = "allow" if expected_reasons == ["shareability_bundle.allow"] else "defer"
    if record.get("status") != expected_status:
        reason_codes.append("shareability_bundle.status_reason_mismatch")
    if sorted(record.get("reason_codes") or []) != sorted(expected_reasons):
        reason_codes.append("shareability_bundle.reason_codes_mismatch")
    return {"ok": not reason_codes, "reason_codes": sorted(set(reason_codes))}


def _required_gates(
    *,
    source: dict[str, Any],
    ref_scope: dict[str, Any],
    git_safety: dict[str, Any],
    bundle_exists: bool,
    create: dict[str, Any],
    verify: dict[str, Any],
    heads: dict[str, Any],
    fsck: dict[str, Any],
) -> dict[str, bool]:
    return {
        "source_git_repo": True,
        "working_tree_clean": source.get("dirty_file_count") == 0,
        "head_sha_present": bool(source.get("head_sha")),
        "bundle_created": bundle_exists and create.get("return_code") == 0,
        "bundle_verified": verify.get("return_code") == 0,
        "bundle_heads_listed": heads.get("return_code") == 0 and len(str(heads.get("stdout") or "").splitlines()) > 0,
        "fsck_connectivity_ok": fsck.get("return_code") == 0,
        "safe_ref_scope": ref_scope.get("safe_ref_scope") is True,
        "git_config_hardened": _git_safety_ok(git_safety),
        "network_not_used": True,
        "remote_urls_not_stored": source.get("remote_urls_stored") is False,
    }


def _required_gates_from_record(record: dict[str, Any]) -> dict[str, bool]:
    commands = record.get("git_commands") or {}
    source = record.get("source") or {}
    return {
        "source_git_repo": True,
        "working_tree_clean": source.get("dirty_file_count") == 0,
        "head_sha_present": bool(source.get("head_sha")),
        "bundle_created": int(record.get("bundle_size_bytes") or 0) > 0
        and (commands.get("bundle_create") or {}).get("return_code") == 0,
        "bundle_verified": (commands.get("bundle_verify") or {}).get("return_code") == 0,
        "bundle_heads_listed": (commands.get("bundle_list_heads") or {}).get("return_code") == 0
        and int((commands.get("bundle_list_heads") or {}).get("stdout_line_count") or 0) > 0,
        "fsck_connectivity_ok": (commands.get("fsck_connectivity") or {}).get("return_code") == 0,
        "safe_ref_scope": (record.get("ref_scope") or {}).get("safe_ref_scope") is True,
        "git_config_hardened": _git_safety_ok(record.get("git_safety") or {}),
        "network_not_used": (record.get("boundaries") or {}).get("network_call_performed") is False,
        "remote_urls_not_stored": source.get("remote_urls_stored") is False,
    }


def _reason_codes(gates: dict[str, bool]) -> list[str]:
    reasons = [f"shareability_bundle.{key}_missing" for key, ok in gates.items() if not ok]
    return sorted(set(reasons)) or ["shareability_bundle.allow"]


def _source_summary(
    *,
    repo: Path,
    head_sha: str,
    branch: str,
    tags: list[str],
    status_text: str,
    remote_text: str,
) -> dict[str, Any]:
    status_lines = [line for line in status_text.splitlines() if line.strip()]
    remote_names = [line for line in remote_text.splitlines() if line.strip()]
    return {
        "repo_root": str(repo),
        "head_sha": head_sha,
        "branch": branch,
        "tags_at_head": sorted(tags),
        "dirty_file_count": len(status_lines),
        "status_porcelain_sha256": sha256_text(status_text),
        "remote_count": len(remote_names),
        "remote_names": sorted(remote_names),
        "remote_names_sha256": sha256_text(canonical_json(sorted(remote_names))),
        "remote_urls_stored": False,
    }


def _command_summary(result: dict[str, Any]) -> dict[str, Any]:
    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    return {
        "argv_sha256": sha256_text(canonical_json(result.get("argv") or [])),
        "return_code": int(result.get("return_code") or 0),
        "stdout_sha256": sha256_text(stdout),
        "stderr_sha256": sha256_text(stderr),
        "stdout_line_count": len(stdout.splitlines()),
        "stderr_line_count": len(stderr.splitlines()),
        "raw_output_stored": False,
    }


def _ref_scope(*, include_all_refs: bool, tags: list[str]) -> dict[str, Any]:
    if include_all_refs:
        return {
            "mode": "all_refs",
            "selected_refs": ["--all"],
            "all_refs_included": True,
            "safe_ref_scope": False,
        }
    return {
        "mode": "head_and_tags_at_head",
        "selected_refs": _selected_refs_for_tags(tags),
        "all_refs_included": False,
        "safe_ref_scope": True,
    }


def _selected_refs_for_tags(tags: list[str]) -> list[str]:
    return ["HEAD", *[f"refs/tags/{tag}" for tag in sorted(tags)]]


def _git_safety_summary() -> dict[str, Any]:
    return {
        "system_git_config_ignored": True,
        "global_git_config_ignored": True,
        "repo_config_helpers_disabled": True,
        "git_terminal_prompt_disabled": True,
        "git_askpass_disabled": True,
        "ssh_command_disabled": True,
        "non_file_protocols_disabled": True,
        "external_diff_disabled": True,
        "command_timeout_seconds": GIT_TIMEOUT_SECONDS,
        "raw_environment_stored": False,
    }


def _git_safety_ok(git_safety: dict[str, Any]) -> bool:
    expected = _git_safety_summary()
    return all(git_safety.get(key) == value for key, value in expected.items())


def _git(cwd: Path, args: list[str]) -> dict[str, Any]:
    argv = ["git", *GIT_CONFIG_OVERRIDES, *args]
    completed = subprocess.run(
        argv,
        cwd=str(cwd),
        check=False,
        capture_output=True,
        text=True,
        env=_git_env(),
        timeout=GIT_TIMEOUT_SECONDS,
    )
    return {
        "argv": argv,
        "return_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": _false_command(),
            "SSH_ASKPASS": _false_command(),
            "GIT_SSH_COMMAND": _false_command(),
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_EXTERNAL_DIFF": _false_command(),
            "GIT_PAGER": "cat",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return env


def _false_command() -> str:
    for candidate in ("/usr/bin/false", "/bin/false"):
        if Path(candidate).exists():
            return candidate
    return "false"


def _empty_git_result(argv: list[str], *, return_code: int, stderr: str) -> dict[str, Any]:
    return {"argv": ["git", *GIT_CONFIG_OVERRIDES, *argv], "return_code": return_code, "stdout": "", "stderr": stderr}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _safe_label(label: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", label.strip()).strip("-")
    return cleaned or "shareability-bundle"
