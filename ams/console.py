from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from .replay import replay_check
from .store import JsonStore


def build_console_report(store: JsonStore) -> dict[str, Any]:
    try:
        state = store.load()
    except Exception as exc:
        return {
            "store": str(store.path),
            "load_ok": False,
            "load_error": f"{type(exc).__name__}: {exc}",
            "replay": {"ok": False, "errors": [f"store load failed: {type(exc).__name__}: {exc}"]},
            "counts": {},
            "active_sessions": [],
            "task_runs": [],
            "claims": [],
            "outbox": [],
            "incidents": [],
            "epoch_events": [],
        }

    replay = replay_check(state)
    return {
        "store": str(store.path),
        "load_ok": True,
        "revision": int(state.get("revision", 0) or 0),
        "replay": replay,
        "counts": replay["counts"],
        "active_sessions": _active_sessions(state),
        "task_runs": _task_runs(state),
        "claims": _claims(state),
        "outbox": _outbox(state),
        "incidents": _incidents(state),
        "epoch_events": _epoch_events(state),
    }


def render_text(report: dict[str, Any]) -> str:
    replay = report.get("replay") or {}
    lines = [
        "AMS Console",
        f"Store: {report.get('store')}",
        f"Replay: {'OK' if replay.get('ok') else 'FAIL'}",
    ]
    if report.get("revision") is not None:
        lines.append(f"Revision: {report['revision']}")
    if replay.get("errors"):
        lines.append("Errors:")
        lines.extend(f"- {error}" for error in replay["errors"][:10])
    counts = report.get("counts") or {}
    if counts:
        lines.append("Counts:")
        for key in sorted(counts):
            lines.append(f"- {key}: {counts[key]}")
    lines.extend(_text_table("Active Sessions", report.get("active_sessions") or []))
    lines.extend(_text_table("Task Runs", report.get("task_runs") or []))
    lines.extend(_text_table("Claims", report.get("claims") or []))
    lines.extend(_text_table("Outbox", report.get("outbox") or []))
    lines.extend(_text_table("Incidents", report.get("incidents") or []))
    lines.extend(_text_table("Epoch Events", report.get("epoch_events") or []))
    return "\n".join(lines) + "\n"


def render_html(report: dict[str, Any]) -> str:
    replay = report.get("replay") or {}
    ok = bool(replay.get("ok"))
    banner_class = "replay-ok" if ok else "replay-bad"
    banner_text = "Replay: OK" if ok else "Replay: FAIL"
    errors = replay.get("errors") or []
    return "\n".join(
        [
            "<!doctype html>",
            "<html lang=\"en\">",
            "<head>",
            "<meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<title>AMS Console</title>",
            "<style>",
            _css(),
            "</style>",
            "</head>",
            "<body>",
            "<main>",
            "<h1>AMS Console</h1>",
            f"<p class=\"store\">{escape(str(report.get('store') or ''))}</p>",
            f"<section class=\"banner {banner_class}\">{escape(banner_text)}</section>",
            _error_block(errors),
            _counts_block(report.get("counts") or {}),
            _html_table("Active Sessions", report.get("active_sessions") or []),
            _html_table("Task Runs", report.get("task_runs") or []),
            _html_table("Claims", report.get("claims") or []),
            _html_table("Outbox", report.get("outbox") or []),
            _html_table("Incidents", report.get("incidents") or []),
            _html_table("Epoch Events", report.get("epoch_events") or []),
            "</main>",
            "</body>",
            "</html>",
            "",
        ]
    )


def write_console(report: dict[str, Any], output: str | Path, *, fmt: str = "html") -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = render_html(report) if fmt == "html" else render_text(report)
    path.write_text(rendered, encoding="utf-8")
    return path


def _active_sessions(state: dict[str, Any]) -> list[dict[str, Any]]:
    sessions = state.get("sessions") or {}
    rows = []
    for session in sessions.values():
        if session.get("state") not in {"pending", "active", "blocked"}:
            continue
        rows.append(
            {
                "session_id": session.get("session_id"),
                "state": session.get("state"),
                "attention_id": session.get("attention_id"),
                "revision": session.get("session_revision", 0),
                "compaction_epoch": session.get("compaction_epoch", 0),
                "updated_at": session.get("updated_at"),
            }
        )
    return sorted(rows, key=lambda row: str(row.get("updated_at") or ""), reverse=True)


def _task_runs(state: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for run in (state.get("task_runs") or {}).values():
        rows.append(
            {
                "task_run_id": run.get("task_run_id"),
                "state": run.get("state"),
                "provider": run.get("provider"),
                "surface": run.get("provider_surface"),
                "action": run.get("action"),
                "updated_at": run.get("updated_at"),
            }
        )
    return sorted(rows, key=lambda row: str(row.get("updated_at") or ""), reverse=True)


def _claims(state: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "resource_claim_id": claim.get("resource_claim_id"),
            "task_run_id": claim.get("task_run_id"),
            "state": claim.get("state"),
            "updated_at": claim.get("updated_at"),
        }
        for claim in sorted(
            (state.get("resource_claims") or {}).values(),
            key=lambda row: str(row.get("updated_at") or ""),
            reverse=True,
        )
    ]


def _outbox(state: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "outbox_id": item.get("outbox_id"),
            "task_run_id": item.get("task_run_id"),
            "target": item.get("target"),
            "state": item.get("state"),
            "last_receipt_id": item.get("last_receipt_id"),
        }
        for item in sorted(
            (state.get("outbox_items") or {}).values(),
            key=lambda row: str(row.get("updated_at") or ""),
            reverse=True,
        )
    ]


def _incidents(state: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "incident_packet_id": incident.get("incident_packet_id"),
            "trigger": incident.get("trigger"),
            "task_run_id": incident.get("task_run_id"),
            "created_at": incident.get("created_at"),
        }
        for incident in sorted(
            (state.get("incident_packets") or {}).values(),
            key=lambda row: str(row.get("created_at") or ""),
            reverse=True,
        )
    ]


def _epoch_events(state: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for event in (state.get("ams_events") or {}).values():
        if event.get("type") != "ams.ams.epoch.closed":
            continue
        data = event.get("data") or {}
        rows.append(
            {
                "event_id": event.get("id"),
                "type": event.get("type"),
                "label": data.get("label"),
                "summary_sha256": data.get("summary_sha256"),
                "time": event.get("time"),
            }
        )
    return sorted(rows, key=lambda row: str(row.get("time") or ""), reverse=True)


def _text_table(title: str, rows: list[dict[str, Any]]) -> list[str]:
    lines = [f"{title}: {len(rows)}"]
    for row in rows[:10]:
        cells = ", ".join(f"{key}={value}" for key, value in row.items() if value is not None)
        lines.append(f"- {cells}")
    return lines


def _html_table(title: str, rows: list[dict[str, Any]]) -> str:
    if not rows:
        return f"<section><h2>{escape(title)}</h2><p class=\"empty\">None</p></section>"
    columns = list(rows[0].keys())
    head = "".join(f"<th>{escape(str(column))}</th>" for column in columns)
    body = []
    for row in rows[:50]:
        cells = "".join(f"<td>{escape(str(row.get(column) or ''))}</td>" for column in columns)
        body.append(f"<tr>{cells}</tr>")
    return (
        f"<section><h2>{escape(title)}</h2>"
        f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table></section>"
    )


def _counts_block(counts: dict[str, Any]) -> str:
    if not counts:
        return "<section><h2>Counts</h2><p class=\"empty\">Unavailable</p></section>"
    rows = "".join(
        f"<tr><th>{escape(str(key))}</th><td>{escape(str(counts[key]))}</td></tr>"
        for key in sorted(counts)
    )
    return f"<section><h2>Counts</h2><table><tbody>{rows}</tbody></table></section>"


def _error_block(errors: list[str]) -> str:
    if not errors:
        return ""
    items = "".join(f"<li>{escape(str(error))}</li>" for error in errors[:20])
    return f"<section class=\"errors\"><h2>Replay Errors</h2><ul>{items}</ul></section>"


def _css() -> str:
    return """
body { margin: 0; font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f7f7f5; color: #202124; }
main { max-width: 1180px; margin: 0 auto; padding: 24px; }
h1 { margin: 0 0 4px; font-size: 28px; }
h2 { margin: 24px 0 8px; font-size: 16px; }
.store { margin: 0 0 16px; color: #5f6368; }
.banner { border-radius: 6px; padding: 12px 14px; font-weight: 700; border: 1px solid; }
.replay-ok { background: #e7f4ea; border-color: #2f8a4b; color: #155724; }
.replay-bad { background: #fdecea; border-color: #c5221f; color: #8a1c17; }
table { width: 100%; border-collapse: collapse; background: white; border: 1px solid #dadce0; }
th, td { padding: 8px 10px; border-top: 1px solid #e8eaed; text-align: left; vertical-align: top; }
th { background: #f1f3f4; font-weight: 600; }
.empty { color: #6f7378; }
.errors { color: #8a1c17; }
"""
