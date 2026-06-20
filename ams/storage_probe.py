from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
import sqlite3
import tempfile
from time import perf_counter
from typing import Any

from .ams_event import build_ams_event
from .store import JsonStore


def run_storage_probe(
    *,
    iterations: int = 100,
    payload_bytes: int = 512,
    directory: str | Path | None = None,
) -> dict[str, Any]:
    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    if payload_bytes < 0:
        raise ValueError("payload_bytes must be >= 0")

    manager = tempfile.TemporaryDirectory() if directory is None else nullcontext(str(directory))
    with manager as root_text:
        root = Path(root_text)
        root.mkdir(parents=True, exist_ok=True)
        json_result = _probe_json(root / "ams_probe.json", iterations, payload_bytes)
        sqlite_result = _probe_sqlite(root / "ams_probe.sqlite3", iterations, payload_bytes)
        decision = _storage_decision(json_result, sqlite_result)
        return {
            "iterations": iterations,
            "payload_bytes": payload_bytes,
            "json": json_result,
            "sqlite_wal": sqlite_result,
            "decision": decision,
            "note": (
                "Probe is local and advisory. JSON remains acceptable while one-writer "
                "shadow load is low and replay/checkpoint costs stay bounded; SQLite WAL "
                "is the planned exit for sustained concurrent readers or larger stores."
            ),
        }


def _probe_json(path: Path, iterations: int, payload_bytes: int) -> dict[str, Any]:
    store = JsonStore(path)
    store.save(store.load(), check_revision=False)
    started = perf_counter()
    write_ms: list[float] = []
    for index in range(iterations):
        write_started = perf_counter()
        with store.locked() as state:
            event = build_ams_event(
                event_type="ams.ams.storage_probe.tick",
                source="ams://probe/json",
                subject=f"json-{index}",
                data={"index": index, "payload": "x" * payload_bytes},
            )
            state.setdefault("ams_events", {})[event["id"]] = event
        write_ms.append((perf_counter() - write_started) * 1000)
    elapsed = perf_counter() - started
    final_state = store.load()
    return _result(path, elapsed, iterations, len(final_state.get("ams_events") or {}), write_ms)


def _probe_sqlite(path: Path, iterations: int, payload_bytes: int) -> dict[str, Any]:
    started = perf_counter()
    write_ms: list[float] = []
    with sqlite3.connect(path) as conn:
        journal_mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        conn.execute("PRAGMA synchronous=FULL")
        synchronous = conn.execute("PRAGMA synchronous").fetchone()[0]
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ams_events "
            "(id TEXT PRIMARY KEY, event_type TEXT NOT NULL, payload TEXT NOT NULL)"
        )
        for index in range(iterations):
            event_id = f"sqlite-{index}"
            payload = "x" * payload_bytes
            write_started = perf_counter()
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO ams_events(id, event_type, payload) VALUES (?, ?, ?)",
                    (event_id, "ams.ams.storage_probe.tick", payload),
                )
            write_ms.append((perf_counter() - write_started) * 1000)
        conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        count = conn.execute("SELECT COUNT(*) FROM ams_events").fetchone()[0]
    elapsed = perf_counter() - started
    result = _result(path, elapsed, iterations, count, write_ms)
    result["journal_mode"] = str(journal_mode)
    result["synchronous"] = int(synchronous)
    return result


def _result(path: Path, elapsed: float, iterations: int, records: int, write_ms: list[float]) -> dict[str, Any]:
    return {
        "path": str(path),
        "records": int(records),
        "elapsed_ms": round(elapsed * 1000, 3),
        "avg_write_ms": round((elapsed * 1000) / iterations, 3),
        "p50_write_ms": round(_percentile(write_ms, 50), 3),
        "p95_write_ms": round(_percentile(write_ms, 95), 3),
        "p99_write_ms": round(_percentile(write_ms, 99), 3),
        "size_bytes": path.stat().st_size if path.exists() else 0,
    }


def _storage_decision(json_result: dict[str, Any], sqlite_result: dict[str, Any]) -> dict[str, Any]:
    json_avg = float(json_result["avg_write_ms"])
    sqlite_avg = float(sqlite_result["avg_write_ms"])
    json_p95 = float(json_result["p95_write_ms"])
    json_size = int(json_result["size_bytes"])
    ratio = json_avg / sqlite_avg if sqlite_avg > 0 else 0.0
    migrate = json_p95 > 50.0 or json_size > 5 * 1024 * 1024
    return {
        "recommendation": "plan_sqlite_wal" if migrate else "keep_json_for_m8h_shadow",
        "reason_code": (
            "storage.json_probe_exceeds_m8h_rule"
            if migrate
            else "storage.json_probe_within_m8h_rule"
        ),
        "json_to_sqlite_avg_ratio": round(ratio, 3),
        "json_p95_write_ms_threshold": 50.0,
        "json_size_bytes_threshold": 5 * 1024 * 1024,
    }


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percentile / 100) * (len(ordered) - 1))))
    return ordered[index]
