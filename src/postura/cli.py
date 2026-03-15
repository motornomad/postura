"""POSTURA CLI — postura init / start / stop / status / analyze / open"""
from __future__ import annotations

import os
import secrets
import subprocess
import sys
import webbrowser
from pathlib import Path

import click

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

API_URL = "http://localhost:8000"
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "white",
}


def _compose_file() -> Path:
    """Return path to the bundled docker-compose.yml."""
    import importlib.resources as pkg_resources
    try:
        ref = pkg_resources.files("postura").joinpath("docker-compose.yml")
        # Extract to a temp path if inside a zip/wheel
        with pkg_resources.as_file(ref) as p:
            return Path(p)
    except Exception:
        # Fallback: repo root (dev install)
        return Path(__file__).parent / "docker-compose.yml"


def _env_example() -> Path:
    """Return path to the bundled .env.example."""
    import importlib.resources as pkg_resources
    try:
        ref = pkg_resources.files("postura").joinpath(".env.example")
        with pkg_resources.as_file(ref) as p:
            return Path(p)
    except Exception:
        return Path(__file__).parent / ".env.example"


def _run_compose(args: list[str], capture: bool = False) -> subprocess.CompletedProcess:
    compose_path = _compose_file()
    cmd = ["docker", "compose", "-f", str(compose_path)] + args
    if capture:
        return subprocess.run(cmd, capture_output=True, text=True)
    return subprocess.run(cmd)


def _check_docker() -> bool:
    result = subprocess.run(
        ["docker", "info"], capture_output=True, text=True
    )
    return result.returncode == 0


def _api_get(path: str) -> dict | None:
    try:
        import httpx
        r = httpx.get(f"{API_URL}{path}", timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def _severity_color(sev: str) -> str:
    return _SEVERITY_COLORS.get(sev.upper(), "white")


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="postura")
def cli():
    """POSTURA — agentic attack surface posture analysis."""


# ---------------------------------------------------------------------------
# postura init
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--force", is_flag=True, help="Overwrite existing .env")
def init(force: bool):
    """One-time setup: configure .env, verify Docker, pull images."""
    click.echo(click.style("POSTURA setup", bold=True))
    click.echo("─" * 40)

    # 1. Docker check
    click.echo("Checking Docker... ", nl=False)
    if not _check_docker():
        click.echo(click.style("✗", fg="red"))
        click.echo(
            click.style("Docker is not running. Start Docker Desktop and retry.", fg="red")
        )
        sys.exit(1)
    click.echo(click.style("✓", fg="green"))

    # 2. .env handling
    env_path = Path.cwd() / ".env"
    if env_path.exists() and not force:
        click.echo(f".env already exists at {env_path}")
        if not click.confirm("Overwrite?", default=False):
            click.echo("Skipping .env setup. Use --force to overwrite.")
        else:
            _write_env(env_path)
    else:
        _write_env(env_path)

    # 3. Pull images
    click.echo("\nPulling Docker images (this takes a minute on first run)...")
    _run_compose(["pull"])

    click.echo(click.style("\nSetup complete.", fg="green", bold=True))
    click.echo("Next: " + click.style("postura start", bold=True))


def _write_env(env_path: Path):
    """Interactively write .env from .env.example."""
    example = _env_example()
    template = example.read_text() if example.exists() else ""

    click.echo("\nConfigure POSTURA (press Enter to keep defaults):\n")

    llm_key = click.prompt(
        "  Anthropic API key (POSTURA_LLM_API_KEY)",
        default="",
        show_default=False,
        hide_input=True,
    )
    github_token = click.prompt(
        "  GitHub token for PR comments (POSTURA_GITHUB_TOKEN, optional)",
        default="",
        show_default=False,
        hide_input=True,
    )
    webhook_secret = click.prompt(
        "  Webhook secret (POSTURA_GITHUB_WEBHOOK_SECRET, leave blank to generate)",
        default="",
        show_default=False,
    )
    if not webhook_secret:
        webhook_secret = secrets.token_hex(32)
        click.echo(f"  Generated webhook secret: {webhook_secret}")

    # Write .env
    lines = template.splitlines() if template else []
    overrides = {
        "POSTURA_LLM_API_KEY": llm_key,
        "POSTURA_GITHUB_TOKEN": github_token,
        "POSTURA_GITHUB_WEBHOOK_SECRET": webhook_secret,
    }
    written_keys: set[str] = set()
    out_lines: list[str] = []
    for line in lines:
        key = line.split("=")[0].strip() if "=" in line else ""
        if key in overrides:
            out_lines.append(f"{key}={overrides[key]}")
            written_keys.add(key)
        else:
            out_lines.append(line)
    # Append any keys not found in template
    for k, v in overrides.items():
        if k not in written_keys:
            out_lines.append(f"{k}={v}")

    env_path.write_text("\n".join(out_lines) + "\n")
    click.echo(click.style(f"  .env written to {env_path}", fg="green"))


# ---------------------------------------------------------------------------
# postura start
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--services", default="neo4j,redis,api,worker",
              help="Comma-separated services to start (default: all)")
def start(services: str):
    """Start POSTURA services (Neo4j, Redis, API, Celery worker)."""
    svc_list = [s.strip() for s in services.split(",")]
    click.echo(f"Starting: {', '.join(svc_list)}")
    _run_compose(["up", "-d"] + svc_list)
    click.echo(click.style("\nServices started.", fg="green"))
    click.echo("API: " + click.style(f"{API_URL}/docs", bold=True))
    click.echo("Run " + click.style("postura status", bold=True) + " to verify.")


# ---------------------------------------------------------------------------
# postura stop
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--volumes", is_flag=True, help="Also delete data volumes (destructive)")
def stop(volumes: bool):
    """Stop POSTURA services."""
    if volumes and not click.confirm(
        click.style("This will delete all graph data. Continue?", fg="yellow"),
        default=False,
    ):
        click.echo("Aborted.")
        return
    args = ["down"]
    if volumes:
        args.append("-v")
    _run_compose(args)
    click.echo(click.style("Services stopped.", fg="yellow"))


# ---------------------------------------------------------------------------
# postura status
# ---------------------------------------------------------------------------

@cli.command()
def status():
    """Check service health and show posture score."""
    click.echo(click.style("POSTURA status", bold=True))
    click.echo("─" * 40)

    # API health
    health = _api_get("/health")
    if health is None:
        click.echo(click.style("  API        OFFLINE", fg="red"))
        click.echo("\nRun " + click.style("postura start", bold=True) + " to start services.")
        sys.exit(1)

    neo4j_status = health.get("neo4j", "unknown")
    api_color = "green" if health.get("status") == "ok" else "yellow"
    neo4j_color = "green" if neo4j_status == "connected" else "red"

    click.echo(f"  API        {click.style('ONLINE', fg=api_color)}")
    click.echo(f"  Neo4j      {click.style(neo4j_status.upper(), fg=neo4j_color)}")

    # Posture score
    posture = _api_get("/api/v1/posture")
    if posture:
        score = posture.get("score", 0)
        counts = posture.get("finding_counts", {})
        interp = posture.get("interpretation", "")
        score_color = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
        click.echo(f"\n  Posture score: {click.style(str(score), fg=score_color, bold=True)}/100  ({interp})")
        if counts:
            click.echo("  Findings:")
            for sev in _SEVERITY_ORDER:
                count = counts.get(sev, 0)
                if count:
                    click.echo(f"    {click.style(sev, fg=_severity_color(sev))}: {count}")

    click.echo(f"\n  Dashboard: {click.style(f'{API_URL}/docs', bold=True)}")


# ---------------------------------------------------------------------------
# postura analyze
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option("--output", type=click.Choice(["text", "json", "markdown"]), default="text")
@click.option(
    "--full",
    is_flag=True,
    help="Build graph + discover chains (requires running services)",
)
def analyze(path: str, output: str, full: bool):
    """Run security analysis on a local directory.

    Without --full: runs SAST (Semgrep + Bandit) + AST parse offline.
    With --full: also builds the threat graph and discovers vulnerability chains.
    """
    target = Path(path).resolve()
    click.echo(click.style(f"Analyzing: {target}", bold=True))

    if full:
        _analyze_full(target, output)
    else:
        _analyze_offline(target, output)


def _analyze_offline(target: Path, output: str):
    """SAST + AST parse only — no services required."""
    click.echo("Mode: offline (SAST + AST parse)\n")

    try:
        from postura.ingest.sast_runner import run_sast
        from postura.ingest.ast_parser import parse_directory
        from postura.ingest.config_analyzer import analyze_directory as analyze_config
    except ImportError as e:
        click.echo(click.style(f"Import error: {e}", fg="red"))
        sys.exit(1)

    click.echo("Running SAST tools (Semgrep + Bandit)... ", nl=False)
    findings = run_sast(str(target))
    click.echo(click.style(f"{len(findings)} findings", fg="yellow"))

    click.echo("Parsing AST... ", nl=False)
    nodes, edges, accesses = parse_directory(str(target))
    click.echo(click.style(f"{len(nodes)} functions, {len(edges)} call edges", fg="cyan"))

    click.echo("Scanning config... ", nl=False)
    config_issues = analyze_config(str(target))
    click.echo(click.style(f"{len(config_issues)} config issues", fg="yellow"))

    all_issues = findings + config_issues
    _print_results_offline(all_issues, nodes, edges, output)


def _print_results_offline(findings, nodes, edges, output: str):
    from collections import Counter
    sev_counts: Counter = Counter()
    for f in findings:
        sev = getattr(f, "severity", "UNKNOWN").upper()
        sev_counts[sev] += 1

    if output == "json":
        import json
        data = {
            "findings": [f.model_dump() if hasattr(f, "model_dump") else str(f) for f in findings],
            "function_count": len(nodes),
            "call_edge_count": len(edges),
            "severity_counts": dict(sev_counts),
        }
        click.echo(json.dumps(data, indent=2))
        return

    click.echo("\n" + click.style("Results", bold=True))
    click.echo("─" * 40)
    click.echo(f"Functions parsed:  {len(nodes)}")
    click.echo(f"Call edges:        {len(edges)}")
    click.echo(f"Findings:          {len(findings)}")
    click.echo()

    for sev in _SEVERITY_ORDER:
        count = sev_counts.get(sev, 0)
        if count:
            click.echo(f"  {click.style(sev, fg=_severity_color(sev))}: {count}")

    if findings:
        click.echo(click.style("\nTop findings:", bold=True))
        shown = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.index(
                getattr(f, "severity", "INFO").upper()
            ) if getattr(f, "severity", "INFO").upper() in _SEVERITY_ORDER else 99
        )[:10]
        for f in shown:
            sev = getattr(f, "severity", "?").upper()
            msg = getattr(f, "message", getattr(f, "description", str(f)))
            file_ = getattr(f, "file_path", "")
            line = getattr(f, "line", "")
            loc = f"{Path(file_).name}:{line}" if file_ else ""
            click.echo(
                f"  [{click.style(sev, fg=_severity_color(sev))}] {msg[:80]}"
                + (f"  ({loc})" if loc else "")
            )

    if output == "markdown":
        _print_markdown_offline(findings, nodes, sev_counts)

    click.echo(
        click.style(
            "\nTip: Run with --full to build the threat graph and discover vulnerability chains.",
            fg="cyan"
        )
    )


def _print_markdown_offline(findings, nodes, sev_counts):
    click.echo("\n---\n## POSTURA Analysis Report\n")
    click.echo("| Severity | Count |")
    click.echo("|---|---|")
    for sev in _SEVERITY_ORDER:
        count = sev_counts.get(sev, 0)
        if count:
            click.echo(f"| {sev} | {count} |")


def _analyze_full(target: Path, output: str):
    """Full pipeline: SAST + AST + graph build + chain discovery."""
    click.echo("Mode: full (requires Neo4j + Redis)\n")

    health = _api_get("/health")
    if health is None:
        click.echo(click.style("Services are not running.", fg="red"))
        click.echo("Run " + click.style("postura start", bold=True) + " first.")
        sys.exit(1)

    click.echo("Running SAST tools... ", nl=False)
    from postura.ingest.sast_runner import run_sast
    findings = run_sast(str(target))
    click.echo(click.style(f"{len(findings)} findings", fg="yellow"))

    click.echo("Parsing AST... ", nl=False)
    from postura.ingest.ast_parser import parse_directory
    from postura.ingest.endpoint_extractor import extract_endpoints
    from postura.ingest.dep_scanner import scan_project
    from postura.ingest.config_analyzer import analyze_directory as analyze_config
    nodes, edges, accesses = parse_directory(str(target))
    endpoints = extract_endpoints(str(target))
    dep_vulns = scan_project(str(target))
    config_issues = analyze_config(str(target))
    click.echo(click.style(f"{len(nodes)} functions, {len(edges)} call edges", fg="cyan"))

    click.echo("Building threat graph... ", nl=False)
    from postura.models.ingest import StructuredIngestResult
    from postura.graph.builder import GraphBuilder
    from postura.graph.connection import health_check
    if not health_check():
        click.echo(click.style("Neo4j not reachable.", fg="red"))
        sys.exit(1)
    result = StructuredIngestResult(
        ast_nodes=nodes,
        call_edges=edges,
        endpoints=endpoints,
        sast_findings=findings,
        dep_vulnerabilities=dep_vulns,
        config_issues=config_issues,
        data_accesses=accesses,
        file_imports={},
    )
    GraphBuilder(result).build()
    click.echo(click.style("done", fg="green"))

    click.echo("Discovering chains + scoring... ", nl=False)
    from postura.reasoning.chain_discovery import discover_chains
    from postura.reasoning.severity_scorer import score_all_findings, compute_posture_score
    discover_chains()
    score_all_findings()
    click.echo(click.style("done", fg="green"))

    score = compute_posture_score()
    posture = _api_get("/api/v1/posture")
    chains = _api_get("/api/v1/chains") or []

    _print_results_full(findings, nodes, score, posture, chains, output)


def _print_results_full(findings, nodes, score, posture, chains, output: str):
    if output == "json":
        import json
        click.echo(json.dumps({
            "posture_score": score,
            "finding_count": len(findings),
            "chain_count": len(chains),
            "posture": posture,
        }, indent=2))
        return

    score_color = "green" if score >= 70 else ("yellow" if score >= 40 else "red")

    click.echo("\n" + click.style("Results", bold=True))
    click.echo("─" * 40)
    click.echo(f"Posture score:  {click.style(str(round(score, 1)), fg=score_color, bold=True)}/100")
    click.echo(f"Functions:      {len(nodes)}")
    click.echo(f"Findings:       {len(findings)}")
    click.echo(f"Chains:         {len(chains)}")

    if chains:
        click.echo(click.style("\nVulnerability chains:", bold=True))
        for ch in chains[:5]:
            click.echo(f"  • {ch.get('summary', str(ch))}")

    if posture:
        counts = posture.get("finding_counts", {})
        click.echo(click.style("\nBy severity:", bold=True))
        for sev in _SEVERITY_ORDER:
            count = counts.get(sev, 0)
            if count:
                click.echo(f"  {click.style(sev, fg=_severity_color(sev))}: {count}")

    click.echo(f"\nFull dashboard: {click.style(f'{API_URL}/docs', bold=True)}")


# ---------------------------------------------------------------------------
# postura open
# ---------------------------------------------------------------------------

@cli.command(name="open")
def open_browser():
    """Open the POSTURA API dashboard in your browser."""
    url = f"{API_URL}/docs"
    click.echo(f"Opening {url}")
    webbrowser.open(url)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
