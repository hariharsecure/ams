from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ams.cli import cmd_codebase_spider_graph
from ams.codebase_spider_graph import CodebaseGraphQueryStore, CodebaseSpiderGraphStore
from ams.models import hash_without
from ams.replay import ReplayChecker
from ams.replay_oracle import ReplayOracle
from ams.store import JsonStore


class CodebaseSpiderGraphTest(unittest.TestCase):
    def test_graph_records_imports_tests_and_no_raw_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")

            result = CodebaseSpiderGraphStore(store).create(source_root=root, package_name="pkg", label="test-graph")

            snapshot = result["snapshot"]
            self.assertEqual(snapshot["status"], "allow")
            self.assertEqual(snapshot["reason_codes"], ["codebase_spider_graph.allow"])
            self.assertFalse(snapshot["analyzer"]["network_required"])
            self.assertFalse(snapshot["analyzer"]["raw_source_stored"])
            serialized = str(result)
            self.assertNotIn("secret_source_body", serialized)
            edge_keys = {(edge["from_path"], edge["edge_type"], edge["to_path"]) for edge in result["edges"]}
            self.assertIn(("pkg/alpha.py", "imports", "pkg/beta.py"), edge_keys)
            self.assertIn(("pkg/beta.py", "imported_by", "pkg/alpha.py"), edge_keys)
            self.assertIn(("tests/test_beta.py", "tests", "pkg/beta.py"), edge_keys)
            self.assertIn(("pkg/beta.py", "tested_by", "tests/test_beta.py"), edge_keys)
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_graph_queries_impact_and_related_tests(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")
            CodebaseSpiderGraphStore(store).create(source_root=root, package_name="pkg", label="test-graph")

            impact = CodebaseGraphQueryStore(store).create(
                source_root=root,
                query_kind="impact_slice",
                paths=["pkg/beta.py"],
                depth=2,
                label="test-impact",
            )
            related = CodebaseGraphQueryStore(store).create(
                source_root=root,
                query_kind="related_tests",
                paths=["pkg/beta.py"],
                label="test-related",
            )

            self.assertEqual(impact["status"], "allow")
            self.assertIn("pkg/alpha.py", impact["result"]["impact_paths"])
            self.assertIn("tests/test_beta.py", impact["result"]["related_tests"])
            self.assertEqual(related["result"]["related_tests"], ["tests/test_beta.py"])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_stale_graph_query_defers_after_source_change(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")
            CodebaseSpiderGraphStore(store).create(source_root=root, package_name="pkg", label="test-graph")
            (root / "pkg" / "beta.py").write_text(
                "def value():\n    return 'changed_source_body'\n",
                encoding="utf-8",
            )

            query = CodebaseGraphQueryStore(store).create(
                source_root=root,
                query_kind="stale_graph_check",
                paths=["pkg/beta.py"],
                label="test-stale",
            )

            self.assertEqual(query["status"], "defer")
            self.assertEqual(query["reason_codes"], ["codebase_graph_query.graph_stale"])
            self.assertEqual(query["result"]["stale_paths"], [{"path": "pkg/beta.py", "reason": "hash_mismatch"}])
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_query_rejects_path_traversal_without_reading_outside_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            (root.parent / "outside.txt").write_text("outside secret should not be read", encoding="utf-8")
            store = JsonStore(root / "store.json")
            CodebaseSpiderGraphStore(store).create(source_root=root, package_name="pkg", label="test-graph")

            query = CodebaseGraphQueryStore(store).create(
                source_root=root,
                query_kind="stale_graph_check",
                paths=["../outside.txt"],
                label="test-traversal",
            )

            self.assertEqual(query["status"], "defer")
            self.assertEqual(query["query"]["paths"], [])
            self.assertEqual(query["query"]["rejected_paths"], [{"path": "../outside.txt", "reason": "unsafe_path"}])
            self.assertIn({"path": "../outside.txt", "reason": "unsafe_path"}, query["result"]["stale_paths"])
            self.assertNotIn("outside secret should not be read", str(query))
            self.assertTrue(ReplayChecker(store).check()["ok"])

    def test_replay_rejects_rehashed_node_with_missing_source_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")
            result = CodebaseSpiderGraphStore(store).create(source_root=root, package_name="pkg", label="test-graph")
            node_id = result["nodes"][0]["codebase_graph_node_id"]
            state = store.load()
            node = state["codebase_graph_nodes"][node_id]
            node["source_sha256"] = None
            node["codebase_graph_node_sha256"] = hash_without(node, "codebase_graph_node_sha256")
            snapshot = next(iter(state["codebase_spider_graph_snapshots"].values()))
            for ref in snapshot["node_refs"]:
                if ref["codebase_graph_node_id"] == node_id:
                    ref["codebase_graph_node_sha256"] = node["codebase_graph_node_sha256"]
            snapshot["codebase_spider_graph_snapshot_sha256"] = hash_without(
                snapshot,
                "codebase_spider_graph_snapshot_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("codebase_graph_node.source_hash_missing", "\n".join(replay["errors"]))

    def test_replay_rejects_rehashed_snapshot_with_missing_reverse_edge(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")
            CodebaseSpiderGraphStore(store).create(source_root=root, package_name="pkg", label="test-graph")
            state = store.load()
            edge = next(edge for edge in state["codebase_graph_edges"].values() if edge["edge_type"] == "imported_by")
            edge_id = edge["codebase_graph_edge_id"]
            state["codebase_graph_edges"].pop(edge_id)
            state["indexes"]["codebase_graph_edge_ids"].pop(edge_id)
            snapshot = next(iter(state["codebase_spider_graph_snapshots"].values()))
            snapshot["edge_refs"] = [
                ref for ref in snapshot["edge_refs"] if ref["codebase_graph_edge_id"] != edge_id
            ]
            snapshot["edge_count"] = len(snapshot["edge_refs"])
            snapshot["codebase_spider_graph_snapshot_sha256"] = hash_without(
                snapshot,
                "codebase_spider_graph_snapshot_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("codebase_spider_graph.reverse_edge_missing", "\n".join(replay["errors"]))

    def test_replay_rejects_rehashed_false_allow_for_stale_query(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")
            CodebaseSpiderGraphStore(store).create(source_root=root, package_name="pkg", label="test-graph")
            (root / "pkg" / "beta.py").write_text("def value():\n    return 'changed'\n", encoding="utf-8")
            query = CodebaseGraphQueryStore(store).create(
                source_root=root,
                query_kind="stale_graph_check",
                paths=["pkg/beta.py"],
                label="test-stale",
            )
            state = store.load()
            receipt = state["codebase_graph_query_receipts"][query["codebase_graph_query_receipt_id"]]
            receipt["graph_fresh"] = True
            receipt["status"] = "allow"
            receipt["reason_codes"] = ["codebase_graph_query.allow"]
            receipt["codebase_graph_query_receipt_sha256"] = hash_without(
                receipt,
                "codebase_graph_query_receipt_sha256",
            )
            store.save(state, validate=False)

            replay = ReplayChecker(store).check()

            self.assertFalse(replay["ok"])
            self.assertIn("codebase_graph_query.graph_fresh_mismatch", "\n".join(replay["errors"]))

    def test_replay_oracle_covers_graph_records(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            store = JsonStore(root / "store.json")
            CodebaseSpiderGraphStore(store).create(source_root=root, package_name="pkg", label="test-graph")
            CodebaseGraphQueryStore(store).create(
                source_root=root,
                query_kind="related_tests",
                paths=["pkg/beta.py"],
                label="test-related",
            )

            result = ReplayOracle(store).check()

            self.assertTrue(result["baseline"]["ok"], result["baseline"]["errors"])
            self.assertTrue(result["ok"], result["misses"])
            collections = {case["collection"] for case in result["cases"]}
            self.assertIn("codebase_spider_graph_snapshots", collections)
            self.assertIn("codebase_graph_nodes", collections)
            self.assertIn("codebase_graph_edges", collections)
            self.assertIn("codebase_graph_query_receipts", collections)

    def test_cli_writes_graph_and_uses_compact_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = _graph_repo(Path(td))
            args = SimpleNamespace(
                store=str(root / "store.json"),
                source_root=str(root),
                package_name="pkg",
                label="test-cli",
                architecture_audit_id=None,
                full_output=False,
            )

            self.assertEqual(cmd_codebase_spider_graph(args), 0)
            self.assertTrue(ReplayChecker(JsonStore(root / "store.json")).check()["ok"])


def _graph_repo(root: Path) -> Path:
    pkg = root / "pkg"
    tests = root / "tests"
    pkg.mkdir(parents=True)
    tests.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "alpha.py").write_text(
        "from . import beta\n\n\ndef run():\n    return beta.value()\n",
        encoding="utf-8",
    )
    (pkg / "beta.py").write_text(
        "def value():\n    return 'secret_source_body'\n",
        encoding="utf-8",
    )
    (tests / "test_beta.py").write_text(
        "from pkg import beta\n\n\ndef test_value():\n    assert beta.value()\n",
        encoding="utf-8",
    )
    return root


if __name__ == "__main__":
    unittest.main()
