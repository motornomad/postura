"""Self-analysis: point POSTURA at its own source tree — P5.6

Ingests the POSTURA source code into the graph and reports what POSTURA
finds about itself. Useful for demonstrating the system and surfacing
real issues in the POSTURA codebase itself.

Usage:
    # Requires Neo4j running and POSTURA source available
    PYTHONPATH=. python evaluation/self_analysis.py [--repo-path PATH]
    PYTHONPATH=. python evaluation/self_analysis.py --dry-run  # parse only, no graph
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

DEFAULT_REPO_PATH = Path(__file__).parent.parent  # postura/ root


def _run_dry(repo_path: Path) -> None:
    """Parse the repo AST and print a summary without touching Neo4j."""
    from postura.ingest.ast_parser import parse_directory

    print(f"Parsing: {repo_path / 'src'}")
    nodes, edges, events = parse_directory(str(repo_path / "src"))
    print(f"  AST nodes (functions/classes): {len(nodes)}")
    print(f"  Call edges:                    {len(edges)}")
    print(f"  Data access events:            {len(events)}")

    # Top files by function count
    from collections import Counter
    file_counts = Counter(n.file for n in nodes)
    print("\nTop 5 files by function count:")
    for file, count in file_counts.most_common(5):
        rel = Path(file).relative_to(repo_path) if Path(file).is_absolute() else file
        print(f"  {count:3d}  {rel}")


def _run_full(repo_path: Path) -> None:
    """Full ingest + graph query report."""
    from postura.graph.builder import GraphBuilder
    from postura.ingest.ast_parser import parse_directory
    from postura.ingest.endpoint_extractor import extract_endpoints_from_directory
    from postura.ingest.sast_runner import run_sast
    from postura.models.ingest import StructuredIngestResult
    from postura.reasoning.chain_discovery import discover_chains
    from postura.reasoning.severity_scorer import score_all_findings
    from postura.graph.connection import run_query

    src_path = repo_path / "src"
    print(f"Ingesting POSTURA source: {src_path}")
    t0 = time.time()

    nodes, edges, events = parse_directory(str(src_path))
    print(f"  Parsed:    {len(nodes)} nodes, {len(edges)} edges")

    endpoints = extract_endpoints_from_directory(str(src_path))
    print(f"  Endpoints: {len(endpoints)}")

    sast = run_sast(str(src_path))
    print(f"  SAST:      {len(sast)} findings")

    result = StructuredIngestResult(
        repo="postura/postura",
        commit_sha="self-analysis",
        ast_nodes=nodes,
        call_edges=edges,
        endpoints=endpoints,
        sast_findings=sast,
        data_accesses=events,
    )

    builder = GraphBuilder(service_name="postura", repo_root=str(src_path))
    builder.build(result)
    discover_chains()
    score_all_findings()
    print(f"  Graph built in {time.time()-t0:.1f}s total")

    # Query what POSTURA found about itself
    _report_self(run_query)


def _report_self(run_query) -> None:
    print("\n── POSTURA Self-Analysis Results ────────────────────────────────")

    # Findings
    findings = run_query(
        """
        MATCH (f:Finding {status: 'open'})
        RETURN f.uid AS uid, f.title AS title,
               f.contextual_severity AS severity, f.cwe_id AS cwe
        ORDER BY f.contextual_severity DESC
        LIMIT 10
        """
    )
    print(f"\nOpen findings (top 10 of {len(findings)}):")
    if not findings:
        print("  (none — clean codebase!)")
    for row in findings:
        sev = row.get("severity") or "?"
        cwe = row.get("cwe") or "—"
        title = row.get("title") or ""
        print(f"  [{sev}] {cwe}: {title[:60]}")

    # Public endpoints
    endpoints = run_query(
        """
        MATCH (e:Endpoint {is_public: true})
        RETURN e.path AS path, e.method AS method,
               e.auth_required AS auth
        ORDER BY e.path
        """
    )
    print(f"\nPublic endpoints ({len(endpoints)}):")
    for row in endpoints:
        auth = "auth" if row.get("auth") else "NO AUTH"
        print(f"  {row.get('method','?')} {row.get('path','?')}  [{auth}]")

    # Chains (CHAINS_TO edges between Finding nodes)
    chains = run_query(
        """
        MATCH (f1:Finding)-[r:CHAINS_TO]->(f2:Finding)
        RETURN f1.title AS from_title, f2.title AS to_title,
               r.chain_type AS chain_type, r.confidence AS confidence
        """
    )
    print(f"\nVulnerability chains ({len(chains)} CHAINS_TO edges):")
    if not chains:
        print("  (none)")
    for row in chains:
        conf = row.get("confidence") or "?"
        ctype = row.get("chain_type") or "unknown"
        print(f"  [{conf}] {row.get('from_title','?')} → {row.get('to_title','?')}  ({ctype})")

    # Posture score
    from postura.reasoning.severity_scorer import compute_posture_score
    score = compute_posture_score()
    print(f"\nPosture score: {score:.1f}/100")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run POSTURA self-analysis")
    parser.add_argument(
        "--repo-path", default=str(DEFAULT_REPO_PATH),
        help="Path to POSTURA repo root (default: auto-detect)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Parse only — do not write to Neo4j",
    )
    args = parser.parse_args()

    repo_path = Path(args.repo_path)
    if not (repo_path / "src").exists():
        print(f"ERROR: {repo_path}/src not found", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        _run_dry(repo_path)
    else:
        try:
            _run_full(repo_path)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            print("Is Neo4j running?  Try --dry-run for offline parse.", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
