"""CVE knowledge loader for Python ecosystem packages — P4.1b

Fetches CVE data from the NVD API 2.0 for a curated set of Python packages
commonly found in web applications. Results are embedded and stored in
ChromaDB collection "cve".

NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
Rate limit: 5 req/30s (no API key), 50 req/30s (with API key via POSTURA_NVD_API_KEY).
"""
from __future__ import annotations

import logging
import time
from typing import Any

import requests

from postura.config import settings
from postura.knowledge.embedder import get_or_create_collection, upsert_documents

logger = logging.getLogger(__name__)

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Python web ecosystem packages to fetch CVEs for
_TARGET_PACKAGES = [
    "flask", "django", "fastapi", "werkzeug", "jinja2", "requests",
    "urllib3", "cryptography", "pyjwt", "pillow", "sqlalchemy",
    "celery", "redis", "pymongo", "aiohttp", "starlette",
    "paramiko", "pyyaml", "lxml", "defusedxml",
]

_REQUEST_DELAY = 6.5  # seconds between NVD requests (stays under rate limit)


def load_cve_knowledge(
    packages: list[str] | None = None,
    force_reload: bool = False,
    max_per_package: int = 20,
) -> int:
    """
    Fetch CVE data from NVD for Python ecosystem packages and embed into ChromaDB.

    Args:
        packages: Override the default package list.
        force_reload: Re-fetch even if collection already has data.
        max_per_package: Maximum CVEs to ingest per package.

    Returns the total number of CVE entries in the collection.
    """
    collection = get_or_create_collection("cve")
    if not force_reload and collection.count() > 0:
        logger.info("CVE collection already has %d entries — skipping reload", collection.count())
        return collection.count()

    target = packages or _TARGET_PACKAGES
    all_entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for pkg in target:
        try:
            entries = _fetch_cves_for_package(pkg, max_results=max_per_package)
            for e in entries:
                if e["id"] not in seen_ids:
                    seen_ids.add(e["id"])
                    all_entries.append(e)
            logger.info("Fetched %d CVEs for package '%s'", len(entries), pkg)
            time.sleep(_REQUEST_DELAY)
        except Exception as exc:
            logger.warning("Failed to fetch CVEs for '%s': %s", pkg, exc)
            continue

    if not all_entries:
        logger.warning("No CVE entries fetched — NVD may be unavailable")
        return 0

    upsert_documents(
        collection,
        ids=[e["id"] for e in all_entries],
        documents=[e["document"] for e in all_entries],
        metadatas=[e["metadata"] for e in all_entries],
    )
    logger.info("CVE knowledge base ready: %d entries in ChromaDB", collection.count())
    return collection.count()


# ---------------------------------------------------------------------------
# NVD API fetch
# ---------------------------------------------------------------------------

def _fetch_cves_for_package(package_name: str, max_results: int = 20) -> list[dict[str, Any]]:
    """Query NVD API for CVEs mentioning the package name."""
    headers = {"Accept": "application/json"}
    api_key = getattr(settings, "nvd_api_key", "")
    if api_key:
        headers["apiKey"] = api_key

    params: dict[str, Any] = {
        "keywordSearch": package_name,
        "keywordExactMatch": "",
        "resultsPerPage": min(max_results, 100),
        "startIndex": 0,
    }

    resp = requests.get(_NVD_BASE, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    entries = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        # Description (English preferred)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS score
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = m.get("baseSeverity") or cvss_data.get("baseSeverity") or "UNKNOWN"
                break

        # Affected CPE (extract package name + version)
        affected_versions = []
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    if package_name.lower() in cpe.lower():
                        version_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")
                        if version_end:
                            affected_versions.append(f"<= {version_end}")

        published = cve.get("published", "")[:10]

        document = (
            f"{cve_id}: {description}\n"
            f"Package: {package_name}\n"
            f"Severity: {severity} (CVSS: {cvss_score})\n"
            f"Published: {published}"
        )
        if affected_versions:
            document += f"\nAffected versions: {'; '.join(affected_versions[:5])}"

        entries.append({
            "id": f"{cve_id}:{package_name}",
            "document": document,
            "metadata": {
                "source": "cve",
                "cve_id": cve_id,
                "package_name": package_name,
                "severity": severity,
                "cvss_score": str(cvss_score or ""),
                "published": published,
            },
        })

    return entries
