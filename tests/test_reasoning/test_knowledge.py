"""Unit tests for the knowledge base and retrieval pipeline — P4.1/P4.2

These tests use a temp ChromaDB directory and do NOT require network access
(CWE/CVE downloads are mocked or skipped for unit tests).
"""
from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_temp_settings(tmp_path: Path, monkeypatch):
    """Patch settings.knowledge_store_path to a temp dir and clear caches."""
    monkeypatch.setattr(
        "postura.config.settings.knowledge_store_path",
        str(tmp_path / "kb"),
    )
    # Clear lru_cache singletons so they pick up the new path
    from postura.knowledge import embedder, retriever
    embedder._get_client.cache_clear()
    # _get_model may not be cached yet; guard with hasattr check
    if hasattr(embedder._get_model, "cache_clear"):
        embedder._get_model.cache_clear()
    retriever._get_bm25_index.cache_clear()


# ---------------------------------------------------------------------------
# Embedder tests (use a lightweight model to avoid slow BGE-M3 in CI)
# ---------------------------------------------------------------------------

@pytest.fixture()
def patched_embed(monkeypatch):
    """Replace embed_texts with a deterministic stub."""
    def _fake_embed(texts):
        import hashlib
        return [
            [float(b) / 255.0 for b in hashlib.sha256(t.encode()).digest()[:32]]
            for t in texts
        ]
    monkeypatch.setattr("postura.knowledge.embedder._get_model", lambda: None)
    monkeypatch.setattr("postura.knowledge.embedder.embed_texts", _fake_embed)
    return _fake_embed


class TestEmbedder:
    def test_upsert_and_query(self, tmp_path, monkeypatch, patched_embed):
        _make_temp_settings(tmp_path, monkeypatch)
        from postura.knowledge.embedder import (
            get_or_create_collection, upsert_documents, query_collection, collection_count
        )

        col = get_or_create_collection("test_col")
        upsert_documents(
            col,
            ids=["doc1", "doc2"],
            documents=["SQL injection vulnerability CWE-89", "SSRF server-side request forgery"],
            metadatas=[{"source": "test"}, {"source": "test"}],
        )
        assert collection_count("test_col") == 2

        results = query_collection(col, "SQL injection", n_results=1)
        assert len(results) == 1
        assert "id" in results[0]
        assert "document" in results[0]

    def test_upsert_empty_is_noop(self, tmp_path, monkeypatch, patched_embed):
        _make_temp_settings(tmp_path, monkeypatch)
        from postura.knowledge.embedder import get_or_create_collection, upsert_documents, collection_count
        col = get_or_create_collection("empty_col")
        upsert_documents(col, [], [], [])
        assert collection_count("empty_col") == 0


# ---------------------------------------------------------------------------
# OWASP loader tests (no network needed — data is hardcoded)
# ---------------------------------------------------------------------------

class TestOWASPLoader:
    def test_load_owasp(self, tmp_path, monkeypatch, patched_embed):
        _make_temp_settings(tmp_path, monkeypatch)
        from postura.knowledge.owasp_loader import load_owasp_knowledge
        count = load_owasp_knowledge(force_reload=True)
        assert count == 10  # OWASP Top 10

    def test_load_owasp_idempotent(self, tmp_path, monkeypatch, patched_embed):
        _make_temp_settings(tmp_path, monkeypatch)
        from postura.knowledge.owasp_loader import load_owasp_knowledge
        count1 = load_owasp_knowledge(force_reload=True)
        count2 = load_owasp_knowledge(force_reload=False)  # should skip
        assert count1 == count2 == 10

    def test_owasp_has_injection_entry(self, tmp_path, monkeypatch, patched_embed):
        _make_temp_settings(tmp_path, monkeypatch)
        from postura.knowledge.owasp_loader import load_owasp_knowledge
        from postura.knowledge.embedder import get_or_create_collection
        load_owasp_knowledge(force_reload=True)
        col = get_or_create_collection("owasp")
        result = col.get(ids=["A03:2021"], include=["documents"])
        assert result["ids"] == ["A03:2021"]
        assert "Injection" in result["documents"][0]
        assert "CWE-89" in result["documents"][0]


# ---------------------------------------------------------------------------
# Retriever tests
# ---------------------------------------------------------------------------

class TestRetriever:
    def test_retrieve_from_owasp(self, tmp_path, monkeypatch, patched_embed):
        _make_temp_settings(tmp_path, monkeypatch)
        from postura.knowledge.owasp_loader import load_owasp_knowledge
        from postura.knowledge.retriever import retrieve
        load_owasp_knowledge(force_reload=True)

        results = retrieve("SQL injection", k=3, sources=["owasp"])
        assert len(results) > 0
        assert all("id" in r for r in results)
        assert all("document" in r for r in results)
        assert all("score" in r for r in results)

    def test_retrieve_empty_collection_returns_empty(self, tmp_path, monkeypatch, patched_embed):
        _make_temp_settings(tmp_path, monkeypatch)
        from postura.knowledge.retriever import retrieve
        results = retrieve("anything", k=5, sources=["cwe"])
        assert results == []

    def test_retrieve_by_cwe_exact(self, tmp_path, monkeypatch, patched_embed):
        _make_temp_settings(tmp_path, monkeypatch)
        # Manually insert a fake CWE entry
        from postura.knowledge.embedder import get_or_create_collection, upsert_documents
        col = get_or_create_collection("cwe")
        upsert_documents(
            col,
            ids=["CWE-89"],
            documents=["CWE-89: SQL Injection. Description: Parameterized queries not used."],
            metadatas=[{"source": "cwe", "cwe_id": "CWE-89", "name": "SQL Injection"}],
        )
        from postura.knowledge.retriever import retrieve_by_cwe
        results = retrieve_by_cwe("CWE-89", k=1)
        assert len(results) == 1
        assert results[0]["id"] == "CWE-89"

    def test_retrieve_invalid_source_skipped(self, tmp_path, monkeypatch, patched_embed):
        _make_temp_settings(tmp_path, monkeypatch)
        from postura.knowledge.retriever import retrieve
        # "bogus" is not a valid collection — should just return empty
        results = retrieve("test", k=3, sources=["bogus"])
        assert results == []


# ---------------------------------------------------------------------------
# Tool: knowledge_retrieve
# ---------------------------------------------------------------------------

class TestKnowledgeRetrieveTool:
    def test_tool_returns_results(self, tmp_path, monkeypatch, patched_embed):
        _make_temp_settings(tmp_path, monkeypatch)
        from postura.knowledge.owasp_loader import load_owasp_knowledge
        from postura.reasoning.tools import knowledge_retrieve
        load_owasp_knowledge(force_reload=True)

        results = knowledge_retrieve("broken access control", k=2, sources=["owasp"])
        assert isinstance(results, list)
        assert len(results) > 0

    def test_tool_cwe_id_lookup(self, tmp_path, monkeypatch, patched_embed):
        _make_temp_settings(tmp_path, monkeypatch)
        from postura.knowledge.embedder import get_or_create_collection, upsert_documents
        col = get_or_create_collection("cwe")
        upsert_documents(
            col,
            ids=["CWE-918"],
            documents=["CWE-918: Server-Side Request Forgery."],
            metadatas=[{"source": "cwe", "cwe_id": "CWE-918", "name": "SSRF"}],
        )
        from postura.reasoning.tools import knowledge_retrieve
        results = knowledge_retrieve("CWE-918", k=1, sources=["cwe"])
        assert any("918" in r["id"] for r in results)


# ---------------------------------------------------------------------------
# Tool: graph_query safety
# ---------------------------------------------------------------------------

class TestGraphQuerySafety:
    def test_write_query_rejected(self):
        from postura.reasoning.tools import graph_query
        with pytest.raises(ValueError, match="read operations"):
            graph_query("MERGE (n:Test) RETURN n")

    def test_delete_rejected(self):
        from postura.reasoning.tools import graph_query
        with pytest.raises(ValueError, match="read operations"):
            graph_query("MATCH (n) DELETE n")

    def test_set_rejected(self):
        from postura.reasoning.tools import graph_query
        with pytest.raises(ValueError, match="read operations"):
            graph_query("MATCH (n) SET n.x = 1 RETURN n")
