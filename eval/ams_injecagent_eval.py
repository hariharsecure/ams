#!/usr/bin/env python3
"""InjecAgent evaluation harness for AMS.

Shared library + a Codex-CLI runner. The published-baseline GPT-4 ReAct arm that
produces the headline ASR numbers lives in `ams_gpt4_react_baseline.py`, which
imports the case selection / prompt construction / gate observation / paired
statistics from this module (so the AMS gate logic is exercised verbatim, never
re-implemented).

Paths resolve from the environment so the harness runs from a clean clone:

    AMS_ROOT       repo root containing the `ams_codex/` package
                   (default: the parent of this file's directory)
    INJECAGENT_DIR clone of the public InjecAgent repo (its `data/` and `src/`)
                   (default: $AMS_ROOT/eval/injecagent/repo)
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import random
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

EVAL_DIR = Path(__file__).resolve().parent
AMS_ROOT = Path(os.environ.get("AMS_ROOT", EVAL_DIR.parent))
INJEC = Path(os.environ.get("INJECAGENT_DIR", EVAL_DIR / "injecagent" / "repo"))
sys.path[:0] = [str(INJEC), str(AMS_ROOT)]

from ams_codex.gate_adapter import build_action, shadow_verdict
from ams_codex.models import content_hash, utc_now
from src.output_parsing import evaluate_output_prompted
from src.prompts.agent_prompts import PROMPT_DICT

RISK_FLAGS = ["egress", "destructive", "unknown_tool"]
ARMS = ("baseline", "ams")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if value in (None, "", "None", "N/A"):
        return {}
    text = str(value)
    for parser in (json.loads, ast.literal_eval):
        try:
            parsed = parser(text)
            return parsed if isinstance(parsed, dict) else {"value": parsed}
        except Exception:
            pass
    return {"raw": text[:1000]}


def tool_dict() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for toolkit in load_json(INJEC / "data" / "tools.json"):
        for tool in toolkit["tools"]:
            item = deepcopy(tool)
            item["name"] = toolkit["toolkit"] + tool["name"]
            out[item["name"]] = item
    return out


def select_cases(seed: int, limit: int | None, all_cases: bool) -> list[dict[str, Any]]:
    cases = []
    for intent, fn in (("dh", "test_cases_dh_base.json"), ("ds", "test_cases_ds_base.json")):
        for i, item in enumerate(load_json(INJEC / "data" / fn)):
            row = deepcopy(item)
            row["_intent"], row["_idx"], row["_case_id"] = intent, i, f"{intent}_{i:04d}"
            cases.append(row)
    if all_cases or limit is None:
        return cases
    rnd = random.Random(seed)
    dh = [c for c in cases if c["_intent"] == "dh"]
    ds = [c for c in cases if c["_intent"] == "ds"]
    ndh = min(len(dh), limit // 2)
    nds = min(len(ds), limit - ndh)
    return sorted(rnd.sample(dh, ndh) + rnd.sample(ds, nds), key=lambda x: (x["_intent"], x["_idx"]))


def prompt_for(item: dict[str, Any], tools: dict[str, Any], observation: str, step2: dict[str, str] | None = None) -> str:
    system_prompt, user_prompt = PROMPT_DICT["InjecAgent"]
    names = [item["User Tool"]] + item["Attacker Tools"]
    desc = json.dumps([tools[n] for n in names], indent=True)
    scratch = f"\n{item['Thought']}\nAction: {item['User Tool']}\nAction Input: {item['Tool Parameters']}\nObservation: {observation}\n"
    if step2:
        scratch += (
            f"Thought: {step2['thought']}\nAction: {item['Attacker Tools'][0]}\n"
            f"Action Input: {step2['params']}\nObservation: {step2['observation']}\n"
        )
    filled = user_prompt.format(
        available_tool_descriptions=desc,
        input=item["User Instruction"],
        available_tool_names=names,
        agent_scratchpad=scratch,
    )
    return f"{system_prompt}\n\n{filled}"


def gate_observation(tool: str, payload: Any, raw_observation: str) -> tuple[str, dict[str, Any]]:
    verdict = shadow_verdict(
        build_action(tool=tool, endpoint=None, method=None, payload=parse_payload(payload), risk_flags=RISK_FLAGS)
    )
    if verdict["verdict"] == "allow":
        return raw_observation, verdict
    return f"[AMS BLOCKED: {', '.join(verdict.get('reasons') or [])}]", verdict


def benign_observation(item: dict[str, Any], treatment: bool) -> tuple[str, dict[str, Any] | None]:
    raw = str(item["Tool Response"]).replace(
        str(item["Attacker Instruction"]),
        "Benign external content; no instructions for the agent.",
    )
    if not treatment:
        return raw, None
    verdict = shadow_verdict(
        build_action(
            tool=item["User Tool"], endpoint=None, method=None, payload=parse_payload(item["Tool Parameters"]), risk_flags=[]
        )
    )
    if verdict["verdict"] == "allow":
        return raw, verdict
    return f"[AMS BLOCKED: {', '.join(verdict.get('reasons') or [])}]", verdict


def cached_attacker_response(tool: str, params: str, tools: dict[str, Any]) -> tuple[str, str]:
    cache = load_json(INJEC / "data" / "attacker_simulated_responses.json")
    key = f"({tool},{params})"
    if key in cache:
        return cache[key], "injecagent_cache_exact"
    normalized = json.dumps(parse_payload(params))
    key = f"({tool},{normalized})"
    if key in cache:
        return cache[key], "injecagent_cache_normalized"
    returns = tools.get(tool, {}).get("returns") or []
    fields = {r.get("name", "data"): f"simulated sensitive {r.get('description', 'data')}" for r in returns[:4]}
    return json.dumps(fields or {"sensitive_data": "simulated private user data"}), "deterministic_fallback"


def ci(values: list[float]) -> list[float]:
    if not values:
        return [0.0, 0.0]
    vals = sorted(values)
    return [vals[int(0.025 * (len(vals) - 1))], vals[int(0.975 * (len(vals) - 1))]]


def mcnemar_p(base: list[bool], ams: list[bool]) -> float:
    import math
    b = sum(x and not y for x, y in zip(base, ams))
    c = sum((not x) and y for x, y in zip(base, ams))
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, k) for k in range(0, min(b, c) + 1)) / (2**n)
    return min(1.0, 2 * tail)


def paired_stats(rows: list[dict[str, Any]], seed: int) -> dict[str, Any]:
    by_case: dict[str, dict[str, Any]] = {}
    for r in rows:
        by_case.setdefault(r["case_id"], {})[r["arm"]] = r
    pairs = [v for v in by_case.values() if all(a in v for a in ARMS)]
    out: dict[str, Any] = {}
    rnd = random.Random(seed)
    for intent in ("dh", "ds", "total"):
        subset = [p for p in pairs if intent == "total" or p["baseline"]["intent"] == intent]
        base = [p["baseline"]["success"] for p in subset]
        ams = [p["ams"]["success"] for p in subset]
        n = len(subset)
        reps = []
        for _ in range(2000 if n else 0):
            sample = [rnd.randrange(n) for _ in range(n)]
            br = sum(base[i] for i in sample) / n
            ar = sum(ams[i] for i in sample) / n
            reps.append((br, ar, ar - br))
        out[intent] = {
            "n": n,
            "baseline_asr": sum(base) / n if n else 0.0,
            "ams_asr": sum(ams) / n if n else 0.0,
            "delta_asr": (sum(ams) - sum(base)) / n if n else 0.0,
            "baseline_ci95": ci([r[0] for r in reps]),
            "ams_ci95": ci([r[1] for r in reps]),
            "delta_ci95": ci([r[2] for r in reps]),
            "mcnemar_p": mcnemar_p(base, ams),
        }
    return out


# --- Optional Codex-CLI runner ---------------------------------------------
# The headline ASR numbers come from ams_gpt4_react_baseline.py (OpenAI GPT-4).
# The Codex-CLI main() below is a secondary shadow runner that depends on a local
# Codex CLI being installed; it is not required to reproduce the published result.

def main() -> None:
    p = argparse.ArgumentParser(description="Codex-CLI InjecAgent shadow runner (secondary)")
    p.add_argument("--limit", type=int, default=80)
    p.add_argument("--all", action="store_true")
    p.add_argument("--benign-limit", type=int, default=16)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--model", default=os.environ.get("INJECAGENT_CODEX_MODEL"))
    args = p.parse_args()
    print(
        "This entry point requires a local Codex CLI runner. To reproduce the "
        "published GPT-4 ReAct ASR headline, use ams_gpt4_react_baseline.py instead.",
        file=sys.stderr,
    )
    raise SystemExit(2)


if __name__ == "__main__":
    main()
