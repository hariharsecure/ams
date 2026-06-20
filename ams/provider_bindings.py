from __future__ import annotations

from copy import deepcopy
from typing import Any

from .models import utc_now


def upsert_provider_session(
    session: dict[str, Any],
    *,
    provider: str,
    surface: str,
    provider_session_id: str,
    status: str = "active",
    active_turn_id: str | None = None,
    provider_agent_id: str | None = None,
) -> dict[str, Any]:
    session = deepcopy(session)
    bindings = list(session.get("provider_sessions") or [])
    now = utc_now()
    updated = False
    for binding in bindings:
        if binding.get("provider") == provider and binding.get("surface") == surface:
            binding.update(
                {
                    "provider_session_id": provider_session_id,
                    "status": status,
                    "active_turn_id": active_turn_id,
                    "provider_agent_id": provider_agent_id,
                    "updated_at": now,
                }
            )
            updated = True
            break
    if not updated:
        bindings.append(
            {
                "provider": provider,
                "surface": surface,
                "provider_session_id": provider_session_id,
                "provider_agent_id": provider_agent_id,
                "active_turn_id": active_turn_id,
                "last_checkpoint_id": session.get("last_summary_checkpoint_id"),
                "compaction_epoch": session.get("compaction_epoch", 0),
                "status": status,
                "created_at": now,
                "updated_at": now,
            }
        )
    session["provider_sessions"] = bindings
    return session


def find_provider_session(session: dict[str, Any], provider: str, surface: str | None = None) -> dict[str, Any] | None:
    for binding in session.get("provider_sessions") or []:
        if binding.get("provider") != provider:
            continue
        if surface is not None and binding.get("surface") != surface:
            continue
        return deepcopy(binding)
    return None
