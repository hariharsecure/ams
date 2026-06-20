from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import hash_without, sha256_text
from .workspace import path_is_under


def resolve_output_path(root: Path, output_path: str | Path) -> Path:
    output = Path(output_path).expanduser()
    if not output.is_absolute():
        output = root / output
    output = output.resolve(strict=False)
    if not path_is_under(output, root):
        raise ValueError("output_path must stay under source_root")
    return output


def text_stats(text: str) -> dict[str, Any]:
    encoded = text.encode("utf-8")
    return {
        "sha256": sha256_text(text),
        "line_count": len(text.splitlines()),
        "size_bytes": len(encoded),
    }


def previous_text_file(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file() or path.is_symlink():
        return {"exists": False, "sha256": None}
    return {"exists": True, "sha256": sha256_text(path.read_text(encoding="utf-8"))}


def generated_output_status(
    *,
    output_available: bool,
    rendered_stats: dict[str, Any],
    reason_codes: list[str],
    line_budget: int,
) -> str:
    if not rendered_stats.get("sha256"):
        return "deny"
    if safe_int(rendered_stats.get("line_count"), default=0) > line_budget:
        return "defer"
    if reason_codes:
        return "defer"
    return "allow" if output_available else "defer"


def safe_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
