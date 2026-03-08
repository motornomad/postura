"""Latency evaluation — P5.5c

Measures parse + graph-build latency for:
  - Full scan: entire vulnerable Flask fixture
  - Incremental: 1-file, 3-file, 10-file changes (simulated)

The parse phase is always offline.
The graph-build phase requires Neo4j (skipped gracefully if unavailable).

Usage:
    PYTHONPATH=. python evaluation/latency_eval.py
    PYTHONPATH=. python evaluation/latency_eval.py --parse-only   # no Neo4j needed
    PYTHONPATH=. python evaluation/latency_eval.py --json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent.parent / "tests" / "fixtures" / "vulnerable_flask_app"
POSTURA_SRC = Path(__file__).parent.parent / "src"


# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------

def _timeit(fn, *args, **kwargs):
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    return result, time.perf_counter() - t0


# ---------------------------------------------------------------------------
# Parse-phase measurements
# ---------------------------------------------------------------------------

def measure_parse(target_dir: Path) -> dict:
    """Measure AST parse time for a directory."""
    from postura.ingest.ast_parser import parse_directory

    _, elapsed = _timeit(parse_directory, str(target_dir))
    nodes, edges, events = parse_directory(str(target_dir))
    return {
        "target": str(target_dir.relative_to(Path(__file__).parent.parent)),
        "elapsed_s": round(elapsed, 4),
        "nodes": len(nodes),
        "edges": len(edges),
        "events": len(events),
    }


def measure_single_file_parse(file_path: Path) -> dict:
    """Measure parse time for a single file."""
    from postura.ingest.ast_parser import parse_file

    _, elapsed = _timeit(parse_file, str(file_path))
    nodes, edges, events, imports = parse_file(str(file_path))
    return {
        "target": file_path.name,
        "elapsed_s": round(elapsed, 4),
        "nodes": len(nodes),
        "edges": len(edges),
        "events": len(events),
    }


# ---------------------------------------------------------------------------
# Incremental simulations (parse only)
# ---------------------------------------------------------------------------

_FIXTURE_FILES = [
    "app.py", "db.py", "auth.py", "config.py", "utils.py",
    "models.py", "requirements.txt",
]

_POSTURA_SRC_FILES = list((POSTURA_SRC / "postura").rglob("*.py"))


def _pick_files(file_list: list[Path], n: int) -> list[Path]:
    """Pick first n files from list."""
    return file_list[:min(n, len(file_list))]


def measure_incremental_parse(base_dir: Path, n_files: int) -> dict:
    """Simulate incremental parse of n_files within base_dir."""
    py_files = sorted(base_dir.rglob("*.py"))
    target_files = _pick_files(py_files, n_files)

    from postura.ingest.ast_parser import parse_file

    t0 = time.perf_counter()
    total_nodes = total_edges = total_events = 0
    for fp in target_files:
        nodes, edges, events, _ = parse_file(str(fp))
        total_nodes += len(nodes)
        total_edges += len(edges)
        total_events += len(events)
    elapsed = time.perf_counter() - t0

    return {
        "n_files": n_files,
        "actual_files": len(target_files),
        "elapsed_s": round(elapsed, 4),
        "nodes": total_nodes,
        "edges": total_edges,
        "events": total_events,
    }


# ---------------------------------------------------------------------------
# Graph-build measurements (requires Neo4j)
# ---------------------------------------------------------------------------

def measure_graph_build(target_dir: Path) -> dict | None:
    """Measure full graph build time. Returns None if Neo4j unavailable."""
    try:
        from postura.graph.builder import GraphBuilder
        from postura.ingest.ast_parser import parse_directory
        from postura.models.ingest import StructuredIngestResult

        nodes, edges, events = parse_directory(str(target_dir))
        result = StructuredIngestResult(
            repo="eval/latency",
            commit_sha="latency-eval",
            ast_nodes=nodes,
            call_edges=edges,
            data_accesses=events,
        )

        builder = GraphBuilder(service_name="eval", repo_root=str(target_dir))
        _, elapsed = _timeit(builder.build, result)
        return {
            "target": str(target_dir.relative_to(Path(__file__).parent.parent)),
            "elapsed_s": round(elapsed, 4),
            "nodes_ingested": len(nodes),
        }
    except Exception as exc:
        return {"error": str(exc), "elapsed_s": None}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass
class LatencyReport:
    full_parse: dict = field(default_factory=dict)
    full_graph_build: dict | None = None
    incremental_parse: list[dict] = field(default_factory=list)
    self_parse: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "full_parse": self.full_parse,
            "full_graph_build": self.full_graph_build,
            "incremental_parse": self.incremental_parse,
            "self_parse": self.self_parse,
        }


def print_report(report: LatencyReport) -> None:
    W = 68
    print("=" * W)
    print("POSTURA — Latency Evaluation (P5.5c)")
    print("=" * W)

    fp = report.full_parse
    print(f"\n── Full Scan: Vulnerable Flask Fixture ─────────────────────")
    print(f"  Parse time  : {fp.get('elapsed_s', '?'):.4f}s")
    print(f"  AST nodes   : {fp.get('nodes', '?')}")
    print(f"  Call edges  : {fp.get('edges', '?')}")
    print(f"  Data events : {fp.get('events', '?')}")

    gb = report.full_graph_build
    if gb:
        if gb.get("error"):
            print(f"  Graph build : SKIPPED ({gb['error'][:60]})")
        else:
            print(f"  Graph build : {gb.get('elapsed_s', '?'):.4f}s")
    else:
        print(f"  Graph build : SKIPPED (--parse-only)")

    sp = report.self_parse
    print(f"\n── Self-Analysis: POSTURA Source ────────────────────────────")
    print(f"  Parse time  : {sp.get('elapsed_s', '?'):.4f}s")
    print(f"  AST nodes   : {sp.get('nodes', '?')}")
    print(f"  Call edges  : {sp.get('edges', '?')}")

    print(f"\n── Incremental Parse Simulation (fixture files) ─────────────")
    print(f"  {'Files':<8} {'Elapsed (s)':<14} {'Nodes':<8} {'Edges'}")
    for r in report.incremental_parse:
        print(
            f"  {r['actual_files']:<8} {r['elapsed_s']:<14.4f} "
            f"{r['nodes']:<8} {r['edges']}"
        )

    print(f"\n── Notes ────────────────────────────────────────────────────")
    print("  Parse phase is CPU-bound (tree-sitter). Incremental updates")
    print("  only re-parse changed files — latency scales with change size,")
    print("  not repo size. Graph build scales with number of changed nodes.")
    print("=" * W)


def run_latency_eval(parse_only: bool = False) -> LatencyReport:
    report = LatencyReport()

    # Full fixture parse
    report.full_parse = measure_parse(FIXTURE_DIR)

    # POSTURA self-parse
    report.self_parse = measure_parse(POSTURA_SRC)

    # Incremental simulations on fixture (fixture has 6 py files)
    fixture_py = sorted(FIXTURE_DIR.glob("*.py"))
    for n in [1, 3, min(6, len(fixture_py))]:
        result = measure_incremental_parse(FIXTURE_DIR, n)
        report.incremental_parse.append(result)

    # Graph build (skipped if parse_only or Neo4j unavailable)
    if not parse_only:
        report.full_graph_build = measure_graph_build(FIXTURE_DIR)

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run POSTURA latency evaluation")
    parser.add_argument("--parse-only", action="store_true", help="Skip graph build (no Neo4j)")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    report = run_latency_eval(parse_only=args.parse_only)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_report(report)

    sys.exit(0)
