from __future__ import annotations

from typing import Any


def provider_message_id(response_payload: dict[str, Any]) -> str | None:
    for key in ("message_id", "provider_message_id", "id"):
        value = response_payload.get(key)
        if value:
            return str(value)
    return None
