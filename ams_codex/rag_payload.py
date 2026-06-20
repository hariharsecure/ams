from __future__ import annotations

from typing import Any


FORBIDDEN_PAYLOAD_KEYS = {"text", "content", "raw", "raw_content", "embedding", "embeddings", "vector", "vectors"}


def contains_forbidden_payload_key(value: Any) -> bool:
    if isinstance(value, dict):
        if FORBIDDEN_PAYLOAD_KEYS.intersection(value):
            return True
        return any(contains_forbidden_payload_key(child) for child in value.values())
    if isinstance(value, list):
        return any(contains_forbidden_payload_key(item) for item in value)
    return False
