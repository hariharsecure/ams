from __future__ import annotations

from copy import deepcopy
import json
from typing import Any

from .workspace import repo_root, workspace_root


LEGACY_WORKSPACE_ROOT = "/home/user/ams"
WORKSPACE_ROOT_TOKEN = "${AMS_WORKSPACE_ROOT}"


def load_example_policy(filename: str, *, root: str | None = None) -> dict[str, Any]:
    path = repo_root() / "examples" / filename
    with path.open("r", encoding="utf-8") as fh:
        policy = json.load(fh)
    if not isinstance(policy, dict):
        raise ValueError(f"expected policy object in {path}")
    return _replace_workspace_root(deepcopy(policy), root or workspace_root())


def _replace_workspace_root(value: Any, root: str) -> Any:
    if isinstance(value, str):
        if value in {LEGACY_WORKSPACE_ROOT, WORKSPACE_ROOT_TOKEN}:
            return root
        return value
    if isinstance(value, list):
        return [_replace_workspace_root(item, root) for item in value]
    if isinstance(value, dict):
        return {key: _replace_workspace_root(item, root) for key, item in value.items()}
    return value
