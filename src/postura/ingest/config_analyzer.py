"""Config analyzer — detects hardcoded secrets, CORS misconfigs, debug flags."""
from __future__ import annotations

import re
from pathlib import Path

from postura.models.ingest import ConfigIssue, Severity

# Patterns for hardcoded secrets
_SECRET_PATTERNS = [
    (re.compile(r'(?i)(secret[_\-]?key|SECRET_KEY)\s*=\s*["\']([^"\']{6,})["\']'), "hardcoded_secret"),
    (re.compile(r'(?i)(password|passwd|pwd)\s*=\s*["\']([^"\']{4,})["\']'), "hardcoded_password"),
    (re.compile(r'(?i)(api[_\-]?key|apikey)\s*=\s*["\']([^"\']{8,})["\']'), "hardcoded_api_key"),
    (re.compile(r'(?i)(token)\s*=\s*["\']([^"\']{8,})["\']'), "hardcoded_token"),
    (re.compile(r'(?i)(aws[_\-]?access[_\-]?key[_\-]?id)\s*=\s*["\']([A-Z0-9]{16,})["\']'), "hardcoded_aws_key"),
    (re.compile(r'(?i)(private[_\-]?key)\s*=\s*["\']([^"\']{8,})["\']'), "hardcoded_private_key"),
]

# Patterns that likely indicate environment variable references (not hardcoded)
_ENV_PATTERNS = re.compile(r'os\.environ|os\.getenv|getenv\(|environ\[|settings\.|config\.')

# CORS misconfiguration
_CORS_STAR_PATTERNS = [
    re.compile(r'CORS\s*\([^)]*origins\s*=\s*["\']?\*["\']?'),
    re.compile(r'Access-Control-Allow-Origin.*\*'),
    re.compile(r'allow_origins\s*=\s*\[\s*["\']?\*["\']?\s*\]'),
]

# Debug flag patterns
_DEBUG_PATTERNS = [
    re.compile(r'(?i)DEBUG\s*=\s*True'),
    re.compile(r'app\.run\s*\([^)]*debug\s*=\s*True'),
]


def analyze_file(file_path: str, repo_root: str = "") -> list[ConfigIssue]:
    """Scan a single file for config issues."""
    path = Path(file_path)
    if not path.exists():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    rel_path = str(Path(file_path).relative_to(repo_root)) if repo_root else file_path
    issues: list[ConfigIssue] = []

    lines = content.splitlines()
    for lineno, line in enumerate(lines, start=1):
        # Skip obvious env-var references
        if _ENV_PATTERNS.search(line):
            continue

        # Hardcoded secrets
        for pattern, issue_type in _SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                issues.append(ConfigIssue(
                    issue_type=issue_type,
                    description=f"Hardcoded credential found in {issue_type.replace('_', ' ')}",
                    severity=Severity.HIGH,
                    file=rel_path,
                    line=lineno,
                    evidence=line.strip()[:200],
                ))
                break  # one issue per line is enough

        # CORS misconfiguration
        for pattern in _CORS_STAR_PATTERNS:
            if pattern.search(line):
                issues.append(ConfigIssue(
                    issue_type="cors_misconfiguration",
                    description="CORS allows all origins (*) — may expose API to cross-origin attacks",
                    severity=Severity.MEDIUM,
                    file=rel_path,
                    line=lineno,
                    evidence=line.strip()[:200],
                ))
                break

        # Debug mode
        for pattern in _DEBUG_PATTERNS:
            if pattern.search(line):
                issues.append(ConfigIssue(
                    issue_type="debug_mode_enabled",
                    description="Debug mode enabled — leaks stack traces and internal details in production",
                    severity=Severity.MEDIUM,
                    file=rel_path,
                    line=lineno,
                    evidence=line.strip()[:200],
                ))
                break

    # Check for .env files with hardcoded values
    if path.suffix == "" and path.name.startswith(".env"):
        issues.extend(_analyze_env_file(content, rel_path))

    return issues


_SKIP_DIRS = {
    ".venv", "venv", "env", ".env",
    "__pycache__", ".git", ".tox", ".mypy_cache", ".pytest_cache",
    "node_modules", "dist", "build", "*.egg-info",
    "site-packages",
}


def analyze_directory(dir_path: str, repo_root: str = "") -> list[ConfigIssue]:
    """Recursively scan Python files and config files for issues.

    Skips common non-project directories (.venv, node_modules, __pycache__,
    site-packages, etc.) to avoid flooding results with third-party code.
    """
    root = repo_root or dir_path
    all_issues: list[ConfigIssue] = []

    extensions = {".py", ".cfg", ".ini", ".yaml", ".yml", ".json", ".toml", ""}
    for file in Path(dir_path).rglob("*"):
        # Skip noise directories
        if any(part in _SKIP_DIRS or part.endswith(".egg-info")
               for part in file.parts):
            continue
        if file.is_file() and (file.suffix in extensions or file.name.startswith(".env")):
            issues = analyze_file(str(file), root)
            all_issues.extend(issues)

    return all_issues


def _analyze_env_file(content: str, file_path: str) -> list[ConfigIssue]:
    """Analyze a .env file for secrets that shouldn't be committed."""
    issues = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("\"'")
            if value and not value.startswith("$") and len(value) > 4:
                if any(keyword in key.upper() for keyword in
                       ("SECRET", "PASSWORD", "TOKEN", "KEY", "PRIVATE")):
                    issues.append(ConfigIssue(
                        issue_type="secret_in_env_file",
                        description=f"Secret value found in .env file for key: {key}",
                        severity=Severity.HIGH,
                        file=file_path,
                        line=lineno,
                        evidence=f"{key}=***",
                    ))
    return issues
