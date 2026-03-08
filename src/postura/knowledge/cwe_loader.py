"""CWE knowledge base loader — P4.1a

Downloads the MITRE CWE XML dataset, parses it into structured documents,
and embeds them into ChromaDB collection "cwe".

Source: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
Cached at: settings.knowledge_store_path + /cwe_raw.xml
"""
from __future__ import annotations

import io
import logging
import re
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import requests

from postura.config import settings
from postura.knowledge.embedder import get_or_create_collection, upsert_documents

logger = logging.getLogger(__name__)

_CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_cwe_knowledge(force_reload: bool = False) -> int:
    """
    Download, parse, and embed CWE entries into ChromaDB.

    Returns the number of CWE entries loaded.
    Skips download if already cached and force_reload=False.
    """
    collection = get_or_create_collection("cwe")
    if not force_reload and collection.count() > 0:
        logger.info("CWE collection already has %d entries — skipping reload", collection.count())
        return collection.count()

    xml_path = _ensure_cwe_xml()
    entries = _parse_cwe_xml(xml_path)
    logger.info("Parsed %d CWE entries from XML", len(entries))

    ids = [e["id"] for e in entries]
    documents = [e["document"] for e in entries]
    metadatas = [e["metadata"] for e in entries]

    upsert_documents(collection, ids, documents, metadatas)
    logger.info("CWE knowledge base ready: %d entries in ChromaDB", collection.count())
    return collection.count()


# ---------------------------------------------------------------------------
# Download / cache
# ---------------------------------------------------------------------------

def _ensure_cwe_xml() -> Path:
    """Return path to cached CWE XML, downloading + unzipping if needed."""
    cache_dir = Path(settings.knowledge_store_path) / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    xml_path = cache_dir / "cwec_latest.xml"

    if xml_path.exists():
        logger.info("Using cached CWE XML at %s", xml_path)
        return xml_path

    logger.info("Downloading CWE XML from MITRE...")
    resp = requests.get(_CWE_ZIP_URL, timeout=60)
    resp.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        xml_names = [n for n in zf.namelist() if n.endswith(".xml")]
        if not xml_names:
            raise ValueError("No XML file found in CWE zip archive")
        xml_path.write_bytes(zf.read(xml_names[0]))

    logger.info("CWE XML saved to %s (%d bytes)", xml_path, xml_path.stat().st_size)
    return xml_path


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def _parse_cwe_xml(xml_path: Path) -> list[dict[str, Any]]:
    """Parse CWE XML into a list of document dicts."""
    tree = ET.parse(str(xml_path))
    root = tree.getroot()

    entries = []
    # Weaknesses are under /Weaknesses/Weakness
    weaknesses = root.findall(".//cwe:Weakness", _NS) or root.findall(".//Weakness")

    for w in weaknesses:
        cwe_id = w.get("ID", "")
        name = w.get("Name", "")
        abstraction = w.get("Abstraction", "")
        status = w.get("Status", "")

        description = _get_text(w, "Description") or _get_text(w, "cwe:Description")
        extended_desc = _get_text(w, "Extended_Description") or _get_text(w, "cwe:Extended_Description")
        likelihood = w.get("Likelihood_Of_Exploit", "")

        # Consequences
        consequences = []
        for cons in (w.findall(".//Consequence") or w.findall(".//cwe:Consequence", _NS)):
            scope = _get_text(cons, "Scope") or _get_text(cons, "cwe:Scope")
            impact = _get_text(cons, "Impact") or _get_text(cons, "cwe:Impact")
            if scope or impact:
                consequences.append(f"{scope}: {impact}".strip(": "))

        # Mitigations
        mitigations = []
        for mit in (w.findall(".//Mitigation") or w.findall(".//cwe:Mitigation", _NS)):
            phase = _get_text(mit, "Phase") or _get_text(mit, "cwe:Phase")
            desc = _get_text(mit, "Description") or _get_text(mit, "cwe:Description")
            if desc:
                mitigations.append(f"[{phase}] {desc}" if phase else desc)

        # Related CWEs
        related_ids = []
        for rel in (w.findall(".//Related_Weakness") or w.findall(".//cwe:Related_Weakness", _NS)):
            related_ids.append(rel.get("CWE_ID", ""))

        if not cwe_id or not name:
            continue

        # Build the document text for embedding
        doc_parts = [
            f"CWE-{cwe_id}: {name}",
            f"Abstraction: {abstraction}",
        ]
        if description:
            doc_parts.append(f"Description: {_clean_text(description)}")
        if extended_desc:
            doc_parts.append(f"Extended: {_clean_text(extended_desc)}")
        if consequences:
            doc_parts.append("Consequences: " + "; ".join(consequences[:3]))
        if mitigations:
            doc_parts.append("Mitigations: " + "; ".join(mitigations[:2]))
        if likelihood:
            doc_parts.append(f"Likelihood: {likelihood}")

        document = "\n".join(doc_parts)

        entries.append({
            "id": f"CWE-{cwe_id}",
            "document": document,
            "metadata": {
                "source": "cwe",
                "cwe_id": f"CWE-{cwe_id}",
                "name": name,
                "abstraction": abstraction,
                "status": status,
                "likelihood": likelihood,
                "related_cwe_ids": ",".join(related_ids[:10]),
            },
        })

    return entries


def _get_text(node: ET.Element, tag: str) -> str:
    """Return the concatenated inner text of all matching child elements."""
    children = node.findall(tag) or node.findall(f"cwe:{tag}", _NS)
    parts = []
    for child in children:
        text = "".join(child.itertext()).strip()
        if text:
            parts.append(text)
    return " ".join(parts)


def _clean_text(text: str) -> str:
    """Collapse whitespace and strip XML-ish noise."""
    text = re.sub(r"\s+", " ", text)
    return text.strip()
