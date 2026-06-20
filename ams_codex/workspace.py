from __future__ import annotations

import os
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def workspace_root() -> str:
    return str(Path(os.environ.get("AMS_WORKSPACE_ROOT") or repo_root()).expanduser().resolve(strict=False))


def path_is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
