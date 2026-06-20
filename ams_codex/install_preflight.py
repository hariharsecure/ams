from __future__ import annotations

import getpass
import os
from pathlib import Path
from typing import Any

from .store import DEFAULT_STORE
from .workspace import path_is_under as _path_is_under, repo_root


SECRET_ENV_NAMES = (
    "DISCORD_TOKEN",
    "DISCORD_BOT_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
)


def run_install_preflight(
    *,
    store_path: str | Path = DEFAULT_STORE,
    package_manifest_path: str | Path | None = None,
    expected_agent_user: str = "ams-agent",
    env: dict[str, str] | None = None,
    current_user: str | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    root = (root or repo_root()).resolve()
    store = Path(store_path).expanduser().resolve(strict=False)
    env = dict(os.environ if env is None else env)
    current_user = current_user or getpass.getuser()
    checks = [
        _check(
            "runtime_store_outside_repo",
            "pass" if not _path_is_under(store, root) else "fail",
            "install.runtime_store_outside_repo"
            if not _path_is_under(store, root)
            else "install.runtime_store_inside_repo",
            {"store_path": str(store), "repo_root": str(root)},
        ),
        _check(
            "separate_agent_user",
            "pass" if current_user == expected_agent_user else "defer",
            "install.agent_user_matches"
            if current_user == expected_agent_user
            else "install.agent_user_not_configured",
            {"current_user": current_user, "expected_agent_user": expected_agent_user},
        ),
    ]
    present_secret_names = sorted(name for name in SECRET_ENV_NAMES if env.get(name))
    checks.append(
        _check(
            "no_ambient_secret_env",
            "pass" if not present_secret_names else "fail",
            "install.no_ambient_secret_env"
            if not present_secret_names
            else "install.ambient_secret_env_present",
            {"present_secret_names": present_secret_names},
        )
    )
    if package_manifest_path:
        manifest = Path(package_manifest_path).expanduser().resolve(strict=False)
        checks.append(
            _check(
                "package_manifest_available",
                "pass" if manifest.exists() else "fail",
                "install.package_manifest_available"
                if manifest.exists()
                else "install.package_manifest_missing",
                {"package_manifest_path": str(manifest)},
            )
        )
    else:
        checks.append(
            _check(
                "package_manifest_available",
                "defer",
                "install.package_manifest_not_supplied",
                {"package_manifest_path": None},
            )
        )

    ready = all(check["status"] == "pass" for check in checks)
    return {
        "schema_version": "ams.ams_codex.install_preflight.v0",
        "ready_for_live": ready,
        "status": "pass" if ready else "defer",
        "checks": checks,
        "summary": {
            "pass": sum(1 for check in checks if check["status"] == "pass"),
            "defer": sum(1 for check in checks if check["status"] == "defer"),
            "fail": sum(1 for check in checks if check["status"] == "fail"),
        },
    }


def _check(name: str, status: str, reason_code: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "reason_code": reason_code,
        "details": details,
    }
