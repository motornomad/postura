"""pip-audit wrapper for dependency vulnerability scanning."""
from __future__ import annotations

import json
import subprocess
import logging
import sys
from pathlib import Path

_BIN_DIR = Path(sys.executable).parent


def _pip_audit_cmd() -> str:
    candidate = _BIN_DIR / "pip-audit"
    return str(candidate) if candidate.exists() else "pip-audit"

from postura.models.ingest import DepVulnerability, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def scan_dependencies(requirements_file: str) -> list[DepVulnerability]:
    """Run pip-audit against requirements_file and return vulnerabilities."""
    path = Path(requirements_file)
    if not path.exists():
        logger.warning("requirements file not found: %s", requirements_file)
        return []

    try:
        result = subprocess.run(
            [_pip_audit_cmd(), "-r", str(path), "--format=json", "--progress-spinner=off"],
            capture_output=True, text=True, timeout=180,
        )
        return _parse_pip_audit_output(result.stdout)
    except FileNotFoundError:
        logger.warning("pip-audit not found — skipping dependency scan")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("pip-audit timed out")
        return []


def scan_project(project_dir: str) -> list[DepVulnerability]:
    """Try requirements.txt, then pyproject.toml in project_dir."""
    project_path = Path(project_dir)
    # Try common requirements files
    for req_file in ("requirements.txt", "requirements/base.txt", "requirements/prod.txt"):
        candidate = project_path / req_file
        if candidate.exists():
            return scan_dependencies(str(candidate))

    # Fallback: pip-audit against installed environment
    try:
        result = subprocess.run(
            [_pip_audit_cmd(), "--format=json", "--progress-spinner=off"],
            capture_output=True, text=True, timeout=180,
        )
        return _parse_pip_audit_output(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def _parse_pip_audit_output(stdout: str) -> list[DepVulnerability]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        logger.warning("Could not parse pip-audit JSON output")
        return []

    vulnerabilities = []
    for dep in data.get("dependencies", []):
        package_name = dep.get("name", "")
        version = dep.get("version", "")
        for vuln in dep.get("vulns", []):
            cve_id = vuln.get("id", "")
            description = vuln.get("description", "")
            fix_versions = vuln.get("fix_versions", [])
            fixed_version = fix_versions[0] if fix_versions else None

            # pip-audit doesn't always give a severity — default to HIGH for CVEs
            severity_str = vuln.get("severity", "HIGH").upper()
            severity = _SEVERITY_MAP.get(severity_str, Severity.HIGH)

            vulnerabilities.append(DepVulnerability(
                package_name=package_name,
                installed_version=version,
                fixed_version=fixed_version,
                cve_id=cve_id,
                severity=severity,
                description=description,
            ))
    return vulnerabilities


def parse_requirements_txt(file_path: str) -> list[tuple[str, str, bool]]:
    """
    Parse requirements.txt and return list of (name, version, pinned).
    pinned = True if version is exact (==), False if >= or * etc.
    """
    deps = []
    path = Path(file_path)
    if not path.exists():
        return deps

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            deps.append((name.strip(), version.strip(), True))
        elif ">=" in line:
            name, version = line.split(">=", 1)
            deps.append((name.strip(), version.strip(), False))
        elif "~=" in line:
            name, version = line.split("~=", 1)
            deps.append((name.strip(), version.strip(), False))
        else:
            # No version constraint
            deps.append((line, "", False))
    return deps
