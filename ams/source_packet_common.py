from __future__ import annotations

from typing import Any


def forbidden_keys(raw_packet: dict[str, Any], forbidden: set[str]) -> list[str]:
    found: set[str] = set()
    for key in raw_packet:
        normalized = str(key).lower()
        if normalized in forbidden:
            found.add(normalized)
    return sorted(found)


def required_str(raw_packet: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = raw_packet.get(key)
        if value is not None and str(value):
            return str(value)
    raise ValueError(f"missing required key: {'/'.join(keys)}")


def optional_str(raw_packet: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = raw_packet.get(key)
        if value is not None and str(value):
            return str(value)
    return None


def unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result
