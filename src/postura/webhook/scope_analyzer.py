"""Change scope analyzer — P3.2a + P3.2b

Given a repo path and commit SHA, determines the minimal affected scope:
- Changed files (from git diff)
- Categorization: code / dependency / config
- Transitive dependents (1-hop importers of changed files)
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import git

logger = logging.getLogger(__name__)

_DEP_FILES = {"requirements.txt", "pyproject.toml", "setup.cfg", "setup.py",
              "Pipfile", "Pipfile.lock", "poetry.lock"}
_CONFIG_PATTERNS = re.compile(
    r"(config|settings|\.env|secrets|credentials)", re.IGNORECASE
)


@dataclass
class ChangeScope:
    commit_sha: str
    changed_code_files: list[str] = field(default_factory=list)
    changed_dep_files: list[str] = field(default_factory=list)
    changed_config_files: list[str] = field(default_factory=list)
    transitive_dependents: list[str] = field(default_factory=list)
    is_security_relevant: bool = False

    @property
    def all_affected_files(self) -> list[str]:
        """All files that need re-analysis: directly changed + transitive dependents."""
        seen = set()
        result = []
        for f in (self.changed_code_files + self.transitive_dependents):
            if f not in seen:
                seen.add(f)
                result.append(f)
        return result


def compute_scope(repo_path: str, commit_sha: str, base_sha: Optional[str] = None) -> ChangeScope:
    """
    Compute the change scope for a commit.

    Args:
        repo_path: Local path to the git repo.
        commit_sha: The new commit SHA to analyze.
        base_sha: The base commit SHA to diff against. Defaults to commit_sha~1.
    """
    try:
        repo = git.Repo(repo_path)
    except git.InvalidGitRepositoryError:
        logger.error("Not a git repository: %s", repo_path)
        return ChangeScope(commit_sha=commit_sha)

    changed_files = _get_changed_files(repo, commit_sha, base_sha)
    code_files, dep_files, config_files = _categorize_files(changed_files)

    # Expand scope: find 1-hop importers of changed Python files
    transitive = _find_transitive_dependents(repo_path, code_files)

    scope = ChangeScope(
        commit_sha=commit_sha,
        changed_code_files=code_files,
        changed_dep_files=dep_files,
        changed_config_files=config_files,
        transitive_dependents=transitive,
        is_security_relevant=bool(code_files or dep_files or config_files),
    )

    logger.info(
        "Scope for %s: %d code, %d dep, %d config, %d transitive",
        commit_sha[:8], len(code_files), len(dep_files), len(config_files), len(transitive),
    )
    return scope


def _get_changed_files(repo: git.Repo, commit_sha: str, base_sha: Optional[str]) -> list[str]:
    """Get list of changed files between base and commit."""
    try:
        commit = repo.commit(commit_sha)
        if base_sha:
            base = repo.commit(base_sha)
        else:
            # Default: parent commit
            if not commit.parents:
                # First commit — all files are "new"
                return [item.path for item in commit.tree.traverse() if item.type == "blob"]
            base = commit.parents[0]

        diff = base.diff(commit)
        changed = []
        for item in diff:
            if item.a_path:
                changed.append(item.a_path)
            if item.b_path and item.b_path != item.a_path:
                changed.append(item.b_path)
        return list(set(changed))
    except Exception as e:
        logger.warning("Could not compute git diff for %s: %s", commit_sha[:8], e)
        return []


def _categorize_files(
    files: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """Categorize files into code, dependency, and config."""
    code, deps, config = [], [], []
    for f in files:
        fname = Path(f).name
        if fname in _DEP_FILES:
            deps.append(f)
        elif _CONFIG_PATTERNS.search(f):
            config.append(f)
        elif f.endswith(".py"):
            code.append(f)
        # Non-.py, non-dep, non-config files (JS, HTML, etc.) are ignored for now
    return code, deps, config


def _find_transitive_dependents(repo_path: str, changed_py_files: list[str]) -> list[str]:
    """
    Find Python files that import from any of the changed files.
    Only goes 1 hop to avoid over-expanding scope.
    """
    if not changed_py_files:
        return []

    # Build a set of module names from changed files
    changed_modules: set[str] = set()
    for f in changed_py_files:
        module = _file_to_module(f)
        if module:
            changed_modules.add(module)
            # Also add just the filename stem (for relative imports)
            changed_modules.add(Path(f).stem)

    dependents: set[str] = set()
    repo_path_obj = Path(repo_path)

    for py_file in repo_path_obj.rglob("*.py"):
        rel_path = str(py_file.relative_to(repo_path_obj))
        if rel_path in changed_py_files:
            continue  # skip files already in the changed set

        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Check if this file imports any of the changed modules
        for module in changed_modules:
            # Match: import module, from module import X, from .module import X
            if (re.search(rf"^\s*import\s+{re.escape(module)}\b", content, re.MULTILINE) or
                    re.search(rf"^\s*from\s+{re.escape(module)}\s+import", content, re.MULTILINE) or
                    re.search(rf"^\s*from\s+\.{re.escape(module)}\s+import", content, re.MULTILINE)):
                dependents.add(rel_path)
                break

    return sorted(dependents)


def _file_to_module(file_path: str) -> Optional[str]:
    """Convert a relative file path to a Python module string."""
    p = file_path.replace("\\", "/")
    if not p.endswith(".py"):
        return None
    p = p[:-3]
    if p.endswith("/__init__"):
        p = p[:-9]
    return p.replace("/", ".")
