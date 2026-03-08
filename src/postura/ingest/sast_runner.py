"""Semgrep and Bandit subprocess wrappers.

Runs SAST tools against a target directory, parses JSON output,
returns deduplicated SASTFinding list.
"""
from __future__ import annotations

import json
import subprocess
import logging
import sys
from pathlib import Path

# Resolve tool paths relative to the running Python's bin directory so they
# work whether invoked via a venv, pipx, or system install.
_BIN_DIR = Path(sys.executable).parent


def _tool_path(name: str) -> str:
    """Return the absolute path to a tool in the same bin dir as Python, or
    fall back to the bare name (let the OS PATH resolve it)."""
    candidate = _BIN_DIR / name
    return str(candidate) if candidate.exists() else name

from postura.models.ingest import SASTFinding, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP_SEMGREP = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_SEVERITY_MAP_BANDIT = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def run_semgrep(target_dir: str, config: str = "auto") -> list[SASTFinding]:
    """
    Run semgrep against target_dir and return SASTFinding list.
    Returns empty list if semgrep is not installed or produces errors.
    """
    try:
        result = subprocess.run(
            [_tool_path("semgrep"), "scan", "--config", config, "--json", "--quiet", target_dir],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode not in (0, 1):  # 1 = findings found, which is OK
            logger.warning("semgrep exited with code %d: %s", result.returncode, result.stderr[:200])
            return []
        return _parse_semgrep_output(result.stdout, target_dir)
    except FileNotFoundError:
        logger.warning("semgrep not found — skipping semgrep scan")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("semgrep timed out")
        return []


def run_bandit(target_dir: str) -> list[SASTFinding]:
    """
    Run bandit against target_dir and return SASTFinding list.
    Returns empty list if bandit is not installed or produces errors.
    """
    try:
        result = subprocess.run(
            [_tool_path("bandit"), "-r", target_dir, "-f", "json", "-q"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 2:
            logger.warning("bandit exited with error: %s", result.stderr[:200])
            return []
        return _parse_bandit_output(result.stdout, target_dir)
    except FileNotFoundError:
        logger.warning("bandit not found — skipping bandit scan")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("bandit timed out")
        return []


def run_sast(target_dir: str) -> list[SASTFinding]:
    """Run both Semgrep and Bandit, returning deduplicated results."""
    semgrep_findings = run_semgrep(target_dir)
    bandit_findings = run_bandit(target_dir)
    return _deduplicate(semgrep_findings, bandit_findings, target_dir)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_semgrep_output(stdout: str, target_dir: str) -> list[SASTFinding]:
    findings = []
    if not stdout.strip():
        return findings
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("Could not parse semgrep JSON output")
        return findings

    for result in data.get("results", []):
        extra = result.get("extra", {})
        severity_str = extra.get("severity", "INFO").upper()
        severity = _SEVERITY_MAP_SEMGREP.get(severity_str, Severity.INFO)

        # CWE extraction: metadata may have cwe as list or string
        cwe = None
        meta = extra.get("metadata", {})
        cwe_raw = meta.get("cwe", meta.get("cwe-id", None))
        if isinstance(cwe_raw, list) and cwe_raw:
            cwe = str(cwe_raw[0])
        elif isinstance(cwe_raw, str):
            cwe = cwe_raw

        file_path = result.get("path", "")
        # Make relative to target_dir if possible
        try:
            file_path = str(Path(file_path).relative_to(target_dir))
        except ValueError:
            pass

        findings.append(SASTFinding(
            tool="semgrep",
            rule_id=result.get("check_id", "unknown"),
            title=result.get("check_id", "Semgrep finding"),
            description=extra.get("message", ""),
            severity=severity,
            cwe_id=cwe,
            file=file_path,
            line=result.get("start", {}).get("line", 0),
            end_line=result.get("end", {}).get("line", None),
            code_snippet=extra.get("lines", None),
        ))
    return findings


def _parse_bandit_output(stdout: str, target_dir: str) -> list[SASTFinding]:
    findings = []
    if not stdout.strip():
        return findings
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("Could not parse bandit JSON output")
        return findings

    for result in data.get("results", []):
        severity_str = result.get("issue_severity", "LOW").upper()
        severity = _SEVERITY_MAP_BANDIT.get(severity_str, Severity.LOW)

        # CWE
        cwe = None
        cwe_raw = result.get("issue_cwe", {})
        if isinstance(cwe_raw, dict) and cwe_raw.get("id"):
            cwe = f"CWE-{cwe_raw['id']}"

        file_path = result.get("filename", "")
        try:
            file_path = str(Path(file_path).relative_to(target_dir))
        except ValueError:
            pass

        rule_id = result.get("test_id", "unknown")
        title = result.get("test_name", rule_id)

        findings.append(SASTFinding(
            tool="bandit",
            rule_id=rule_id,
            title=title,
            description=result.get("issue_text", ""),
            severity=severity,
            cwe_id=cwe,
            file=file_path,
            line=result.get("line_number", 0),
            end_line=result.get("end_col_offset", None),
            code_snippet=result.get("code", None),
        ))
    return findings


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(
    semgrep: list[SASTFinding],
    bandit: list[SASTFinding],
    target_dir: str,
) -> list[SASTFinding]:
    """
    Deduplicate: same file + overlapping lines + same CWE → keep the richer one.
    Same file + same line + different CWE → keep both.
    """
    combined = semgrep + bandit
    seen: dict[tuple, SASTFinding] = {}

    for finding in combined:
        key = (finding.file, finding.line, finding.cwe_id or finding.rule_id)
        if key not in seen:
            seen[key] = finding
        else:
            existing = seen[key]
            # Keep the one with more detail (longer description)
            if len(finding.description) > len(existing.description):
                seen[key] = finding

    return list(seen.values())
