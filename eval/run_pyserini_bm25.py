#!/usr/bin/env python3
"""
Pyserini BM25 baseline for SciFact (BEIR).

Uses the Anserini fat-JAR directly via subprocess (on arm64 macOS the pyjnius JVM
bridge crashes SIGBUS with Homebrew openjdk@11; calling the JAR directly is clean).
k1=0.9, b=0.4 -- the canonical BEIR/Anserini parameters.

Paths are resolved from environment / CLI so the script runs from a clean clone:

    SCIFACT_DIR    BEIR SciFact dir (corpus.jsonl, queries.jsonl, qrels/test.tsv)
    ANSERINI_JAR   path to anserini-*-fatjar.jar (ships with pyserini)
    JAVA_BIN       java binary (default: `java` on PATH)
    OUTPUT_FILE    where to write the result JSON

Example:
    export SCIFACT_DIR=~/beir/scifact
    export ANSERINI_JAR=$(python -c "import pyserini,glob,os;print(glob.glob(os.path.join(os.path.dirname(pyserini.__file__),'resources/jars/anserini-*-fatjar.jar'))[0])")
    python eval/run_pyserini_bm25.py --output eval/results/beir_bm25_scifact_pyserini.json
"""

import argparse
import json
import math
import os
import subprocess
from collections import defaultdict

K1 = 0.9
B = 0.4


def env_or(name, default=None):
    return os.environ.get(name, default)


def convert_beir_corpus(scifact_dir, collection_dir):
    """Convert BEIR corpus.jsonl to Anserini JSONL (id + contents = title + ' ' + text)."""
    os.makedirs(collection_dir, exist_ok=True)
    out_path = os.path.join(collection_dir, "corpus.jsonl")
    count = 0
    with open(os.path.join(scifact_dir, "corpus.jsonl")) as fin, open(out_path, "w") as fout:
        for line in fin:
            doc = json.loads(line)
            contents = (doc.get("title", "") + " " + doc.get("text", "")).strip()
            fout.write(json.dumps({"id": doc["_id"], "contents": contents}) + "\n")
            count += 1
    print(f"Converted {count} documents to Anserini JSONL: {out_path}")
    return count


def load_queries(scifact_dir):
    queries = {}
    with open(os.path.join(scifact_dir, "queries.jsonl")) as f:
        for line in f:
            q = json.loads(line)
            queries[q["_id"]] = q["text"]
    return queries


def load_qrels(scifact_dir):
    qrels = defaultdict(dict)
    with open(os.path.join(scifact_dir, "qrels", "test.tsv")) as f:
        next(f)  # skip header
        for line in f:
            qid, docid, score = line.strip().split("\t")[:3]
            qrels[qid][docid] = int(score)
    return qrels


def build_index(java_bin, jar, collection_dir, index_dir):
    os.makedirs(index_dir, exist_ok=True)
    cmd = [
        java_bin, "-cp", jar, "io.anserini.index.IndexCollection",
        "-collection", "JsonCollection", "-input", collection_dir, "-index", index_dir,
        "-generator", "DefaultLuceneDocumentGenerator", "-threads", "4",
        "-storePositions", "-storeDocvectors", "-storeRaw",
    ]
    print("Running Anserini IndexCollection...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print("STDERR:", (result.stderr or "")[-3000:])
        raise RuntimeError(f"Indexing failed (rc={result.returncode})")
    print("Indexing complete.")


def run_search(java_bin, jar, index_dir, work_dir, queries):
    results_dir = os.path.join(work_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    topics_path = os.path.join(work_dir, "queries.tsv")
    with open(topics_path, "w") as f:
        for qid, text in queries.items():
            f.write(f"{qid}\t{text}\n")
    run_output = os.path.join(results_dir, "run.txt")
    cmd = [
        java_bin, "-cp", jar, "io.anserini.search.SearchCollection",
        "-index", index_dir, "-topics", topics_path, "-topicreader", "TsvString",
        "-output", run_output, "-bm25", "-bm25.k1", str(K1), "-bm25.b", str(B),
        "-hits", "1000", "-threads", "4",
    ]
    print(f"Running Anserini SearchCollection (BM25 k1={K1}, b={B})...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print("STDERR:", (result.stderr or "")[-3000:])
        raise RuntimeError(f"Search failed (rc={result.returncode})")
    print("Search complete.")
    return run_output


def parse_trec_run(run_file):
    results = defaultdict(list)
    with open(run_file) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 6:
                results[parts[0]].append((parts[2], float(parts[4])))
    return results


def compute_ndcg(results, qrels, k=10):
    scores = []
    for qid, qdocs in qrels.items():
        if qid not in results:
            scores.append(0.0)
            continue
        dcg = sum(qdocs.get(d, 0) / math.log2(i + 2) for i, (d, _) in enumerate(results[qid][:k]))
        ideal = sorted(qdocs.values(), reverse=True)[:k]
        idcg = sum(rel / math.log2(i + 2) for i, rel in enumerate(ideal))
        scores.append(dcg / idcg if idcg > 0 else 0.0)
    return sum(scores) / len(scores) if scores else 0.0


def compute_recall(results, qrels, k):
    scores = []
    for qid, qdocs in qrels.items():
        relevant = {d for d, rel in qdocs.items() if rel > 0}
        if not relevant:
            continue
        ranked = {d for d, _ in results.get(qid, [])[:k]}
        scores.append(len(ranked & relevant) / len(relevant))
    return sum(scores) / len(scores) if scores else 0.0


def compute_mrr(results, qrels, k=10):
    scores = []
    for qid, qdocs in qrels.items():
        rr = 0.0
        for i, (d, _) in enumerate(results.get(qid, [])[:k]):
            if qdocs.get(d, 0) > 0:
                rr = 1.0 / (i + 1)
                break
        scores.append(rr)
    return sum(scores) / len(scores) if scores else 0.0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scifact-dir", default=env_or("SCIFACT_DIR"))
    p.add_argument("--anserini-jar", default=env_or("ANSERINI_JAR"))
    p.add_argument("--java-bin", default=env_or("JAVA_BIN", "java"))
    p.add_argument("--work-dir", default=env_or("WORK_DIR", "/tmp/pyserini_scifact"))
    p.add_argument("--output", default=env_or("OUTPUT_FILE", "eval/results/beir_bm25_scifact_pyserini.json"))
    args = p.parse_args()

    if not args.scifact_dir or not args.anserini_jar:
        p.error("set SCIFACT_DIR and ANSERINI_JAR (env or flag) -- see module docstring")

    collection_dir = os.path.join(args.work_dir, "collection")
    index_dir = os.path.join(args.work_dir, "index")

    print("=" * 60)
    print("Pyserini BM25 SciFact Baseline")
    print(f"k1={K1}, b={B}, Anserini/Lucene (Porter stemmer, English analyzer)")
    print("=" * 60)

    doc_count = convert_beir_corpus(args.scifact_dir, collection_dir)
    queries = load_queries(args.scifact_dir)
    qrels = load_qrels(args.scifact_dir)
    queries = {qid: t for qid, t in queries.items() if qid in qrels}
    print(f"Queries in test qrels: {len(queries)}")

    build_index(args.java_bin, args.anserini_jar, collection_dir, index_dir)
    run_file = run_search(args.java_bin, args.anserini_jar, index_dir, args.work_dir, queries)
    results = parse_trec_run(run_file)

    ndcg_10 = compute_ndcg(results, qrels, k=10)
    recall_10 = compute_recall(results, qrels, k=10)
    recall_100 = compute_recall(results, qrels, k=100)
    mrr_10 = compute_mrr(results, qrels, k=10)

    print("\n" + "=" * 60)
    print(f"nDCG@10:    {ndcg_10:.5f}")
    print(f"Recall@10:  {recall_10:.5f}")
    print(f"Recall@100: {recall_100:.5f}")
    print(f"MRR@10:     {mrr_10:.5f}")
    print("Published BEIR reference: nDCG@10 ~ 0.665")

    output = {
        "dataset": "scifact",
        "split": "test",
        "retriever": "Pyserini BM25 (Anserini 0.22.1, Lucene)",
        "config": {
            "k1": K1, "b": B, "index_type": "JsonCollection",
            "generator": "DefaultLuceneDocumentGenerator", "stemmer": "porter",
            "analyzer": "DefaultEnglishAnalyzer", "hits": 1000,
            "contents_field": "title + space + text",
        },
        "corpus_size": doc_count,
        "query_count": len(queries),
        "ndcg": {"NDCG@10": round(ndcg_10, 5)},
        "recall": {"Recall@10": round(recall_10, 5), "Recall@100": round(recall_100, 5)},
        "mrr": {"MRR@10": round(mrr_10, 5)},
        "published_reference": {
            "source": "BEIR paper (Thakur et al. 2021, Table 2) and Pyserini BEIR reproduction",
            "NDCG@10": 0.665,
            "method": "Pyserini BM25 k1=0.9 b=0.4, Anserini/Lucene",
        },
        "gap_from_published": round(ndcg_10 - 0.665, 5),
        "execution_notes": "Indexed via Anserini JAR subprocess (pyjnius JVM bridge crashes SIGBUS on arm64 macOS with Homebrew openjdk@11; calling Java directly works cleanly).",
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to: {args.output}")


if __name__ == "__main__":
    main()
