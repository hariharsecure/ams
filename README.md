# AMS — Authority-Managed System

A deterministic security kernel for autonomous agents. AMS sits between an agent
and the side-effecting world (file writes, source patches, message egress, tool
calls) and decides — deterministically and with full provenance — whether each
proposed action is allowed.

The design question: *how do you let an LLM-driven agent act on real systems
without letting prompt-injected or hallucinated instructions cause unsafe
side effects?* AMS answers it with three composable mechanisms.

## Core ideas

1. **Provenance.** Every action carries an auditable chain back to the event
   that authorized it (the source surface, the policy that admitted it, the
   approval packet that signed it). Nothing acts without a traceable origin.

2. **Taint tracking.** Content that enters from an untrusted surface (an inbound
   message, a retrieved document, a model completion) is marked tainted. Tainted
   content cannot directly authorize a privileged action; it must pass through an
   explicit, logged admission step. This is the structural defense against
   prompt injection and embedding-poisoning: a malicious instruction smuggled in
   retrieved text never gains authority just by being read.

3. **Deterministic gate.** Given an action and a signed policy, the gate returns
   the same verdict every time — `allow`, `block`, or `escalate` — with machine-
   readable reason codes. Verdicts are reproducible across machines, so an
   independent reviewer can replay the decision and confirm it. No verdict
   depends on model output at decision time.

Around these sit shadow-mode execution (decisions are computed and logged before
any live boundary is crossed), signed policy/package manifests, a replay oracle
that re-derives run lifecycles deterministically, and conformance packs that
bundle reproducible evidence (target milestone `MILESTONE-29` and onward).

## What's in here

- `ams/` — the kernel: capability + resource policy, the gate adapter,
  provenance/taint records, signed-policy and package-manifest handling, the
  replay oracle, shadow runner, surface adapters (Discord / terminal / queue),
  RAG embedding quarantine, and the conformance-pack generator.
- `schemas/` — JSON Schemas (`ams:ams:*`) for every record type the kernel
  emits or consumes. The kernel validates against these at runtime.
- `tests/` — ~490 tests covering policy hashing, signed-policy verification,
  deterministic replay parity, gate verdicts, and schema validation.
- `examples/` — default capability and resource policies, an example event.
- `data/` — small demo stores used by the simulation/replay tooling.
- `eval/` — the benchmark harnesses (retrieval BM25 baseline, InjecAgent gate
  evaluation) and their recorded result JSONs under `eval/results/`.

## Evaluation

These are benchmarks I ran myself; the harnesses and the raw result JSONs are in
`eval/` so the numbers can be re-derived from a clean clone. They are not a
third-party audit — treat them as reproducible self-reported measurements with
their configs and published reference points recorded alongside.

> Provenance note: the result JSONs record the engine label
> `ams-codex-local-shadow/v0.1.0` — the project's name at the time the benchmarks
> were run (later renamed to **AMS**). The label is kept verbatim so the recorded
> result provenance is not rewritten after the fact.

- **Retrieval (RAG defense surface).** Lucene/Anserini BM25 on BEIR SciFact
  (k1=0.9, b=0.4, 300 queries): **nDCG@10 = 0.679** (Recall@10 = 0.804), in line
  with the BEIR-paper reference of 0.665. This is the retrieval quality the
  embedding-quarantine layer is meant to preserve.
  See `eval/results/beir_bm25_scifact_pyserini.json` (`eval/run_pyserini_bm25.py`).
- **Gate bite (injection resistance).** InjecAgent, GPT-4 ReAct, 80 sampled
  attack cases (40 direct-harm + 40 data-stealing) paired baseline-vs-AMS plus 16
  benign cases. Attack success rate drops from **0.20 (baseline) to 0.00 with the
  AMS gate** (McNemar p ≈ 3e-5), with **0 / 16 benign cases over-blocked**
  (utility retention 1.0). The gate runs in shadow mode and observes verdicts; it
  does not execute the tool calls.
  See `eval/results/injecagent_gpt4_react_poscontrol.json`
  (`eval/ams_gpt4_react_baseline.py`, `eval/ams_injecagent_eval.py`).

## Running

```bash
python3 -m pytest -q          # full suite
python3 -m ams.cli --help
```

Requires Python ≥ 3.9, no third-party runtime dependencies.

## Status

Research prototype. Decisions run in shadow mode; no live boundary
(network, message egress, persistent process, credential store) is crossed by
the code in this repository. All identifiers in the tests, demo data, and
fixtures are synthetic placeholders — neutral operator/agent/channel names
(`Operator A`, `agent_b`, `#channel-a`), obviously-fake numeric IDs
(`000000000000000003`), and example hosts/addresses (`@example.test`,
`example-host.local`). They do not refer to any real person, account, or
channel.

---

**Author:** Harihar Thapa
