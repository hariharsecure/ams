from __future__ import annotations

from typing import Any


def validate_fresh_context(session: dict[str, Any], context: dict[str, Any]) -> None:
    if context.get("session_id") != session.get("session_id"):
        raise ValueError("context belongs to a different session")
    if int(context.get("compaction_epoch", 0) or 0) != int(session.get("compaction_epoch", 0) or 0):
        raise ValueError("stale context: compaction_epoch does not match session")
    if context.get("summary_checkpoint_id") != session.get("last_summary_checkpoint_id"):
        raise ValueError("stale context: summary checkpoint does not match session")
    context_revision = context.get("session_revision")
    if context_revision is not None and int(context_revision) != int(session.get("session_revision", 0) or 0):
        raise ValueError("stale context: session revision does not match session")
