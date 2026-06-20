from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import canonical_json, sha256_text


def policy_hash(policy: dict[str, Any]) -> str:
    material = dict(policy)
    material.pop("policy_sha256", None)
    return sha256_text(canonical_json(material))


def normalize_path(path: str) -> str:
    return str(Path(path).expanduser().resolve(strict=False))


def path_under(path: str, roots: list[str]) -> bool:
    normalized = normalize_path(path)
    for root in roots:
        root_path = normalize_path(root)
        if normalized == root_path or normalized.startswith(root_path.rstrip("/") + "/"):
            return True
    return False
