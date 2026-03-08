"""Unit tests for the NL query engine — P5.2

All LLM calls and Neo4j calls are mocked — no external services required.
"""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _llm_returns(text: str):
    """Context manager: patch _llm_call to return `text`."""
    return patch("postura.api.nl_query._llm_call", return_value=text)


def _neo4j_returns(rows: list[dict]):
    """Context manager: patch run_query to return `rows`."""
    # run_query returns neo4j record-like objects; for tests, plain dicts work
    # since _execute_cypher does dict(r) on each row
    mock_rows = [MagicMock(**{k: v, **{"__iter__": lambda s: iter(s.keys()),
                                        "keys": lambda s: list(row.keys()),
                                        "get": lambda s, k, d=None: row.get(k, d),
                                        "__getitem__": lambda s, k: row[k]}})
                 for row in rows]
    # Simpler: just return plain dicts and patch dict() conversion
    return patch("postura.graph.connection.run_query", return_value=rows)


# ---------------------------------------------------------------------------
# Cypher generation
# ---------------------------------------------------------------------------

class TestCypherGeneration:
    def test_extracts_cypher_from_code_fence(self):
        from postura.api.nl_query import _generate_cypher
        cypher_text = "MATCH (f:Finding {status: 'open'}) RETURN f LIMIT 10"
        with _llm_returns(f"```cypher\n{cypher_text}\n```"):
            result = _generate_cypher("Show me open findings")
        assert result == cypher_text

    def test_extracts_cypher_without_language_tag(self):
        from postura.api.nl_query import _generate_cypher
        cypher_text = "MATCH (e:Endpoint) RETURN e"
        with _llm_returns(f"```\n{cypher_text}\n```"):
            result = _generate_cypher("Show all endpoints")
        assert result == cypher_text

    def test_falls_back_to_raw_text_when_no_fence(self):
        from postura.api.nl_query import _generate_cypher
        cypher_text = "MATCH (f:Finding) RETURN f LIMIT 5"
        with _llm_returns(cypher_text):
            result = _generate_cypher("List findings")
        assert result == cypher_text

    def test_rejects_write_cypher(self):
        from postura.api.nl_query import _generate_cypher
        with _llm_returns("```cypher\nMERGE (n:Test) RETURN n\n```"):
            result = _generate_cypher("Create a test node")
        assert result == ""

    def test_rejects_delete_cypher(self):
        from postura.api.nl_query import _generate_cypher
        with _llm_returns("```cypher\nMATCH (n) DELETE n\n```"):
            result = _generate_cypher("Delete all nodes")
        assert result == ""

    def test_returns_empty_on_llm_failure(self):
        from postura.api.nl_query import _generate_cypher
        with _llm_returns(""):
            result = _generate_cypher("Anything")
        assert result == ""


# ---------------------------------------------------------------------------
# Answer synthesis
# ---------------------------------------------------------------------------

class TestAnswerSynthesis:
    def test_no_results_returns_informative_message(self):
        from postura.api.nl_query import _synthesize_answer
        answer = _synthesize_answer("Show findings", "MATCH (f:Finding) RETURN f", [])
        assert "no results" in answer.lower() or "no data" in answer.lower()

    def test_synthesizes_from_results(self):
        from postura.api.nl_query import _synthesize_answer
        rows = [{"title": "SQL Injection", "severity": "CRITICAL", "file": "db.py"}]
        with _llm_returns("The most critical issue is SQL Injection in db.py."):
            answer = _synthesize_answer("What are the risks?", "MATCH ...", rows)
        assert "SQL Injection" in answer

    def test_fallback_when_llm_fails(self):
        from postura.api.nl_query import _synthesize_answer
        rows = [{"title": "SSRF", "severity": "HIGH"}]
        with _llm_returns(""):
            answer = _synthesize_answer("Risks?", "MATCH ...", rows)
        assert "1 result" in answer or "SSRF" in answer


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------

class TestAnswerQuestion:
    def test_full_pipeline_happy_path(self):
        from postura.api.nl_query import answer_question
        rows = [{"path": "/admin/users", "method": "GET", "auth_required": False}]
        with _llm_returns("```cypher\nMATCH (e:Endpoint {is_public: true}) RETURN e.path AS path, e.method AS method, e.auth_required AS auth_required\n```"):
            with patch("postura.api.nl_query._execute_cypher", return_value=(rows, "")):
                with _llm_returns("The /admin/users endpoint is publicly accessible without authentication."):
                    result = answer_question("Which endpoints have no auth?")
        assert result.result_count == 1
        assert result.cypher != ""
        assert "admin" in result.answer or result.answer != ""

    def test_cypher_generation_fails_returns_graceful_message(self):
        from postura.api.nl_query import answer_question
        with _llm_returns(""):
            result = answer_question("xyz abc def")
        assert result.answer != ""
        assert result.cypher == ""
        assert result.result_count == 0

    def test_execution_error_handled_gracefully(self):
        from postura.api.nl_query import answer_question
        with _llm_returns("```cypher\nMATCH (f:Finding) RETURN f\n```"):
            with patch("postura.api.nl_query._execute_cypher", return_value=([], "connection refused")):
                result = answer_question("What are the findings?")
        assert "failed" in result.answer.lower() or "execute" in result.answer.lower()
        assert result.result_count == 0

    def test_to_dict_structure(self):
        from postura.api.nl_query import answer_question
        with _llm_returns("```cypher\nMATCH (f:Finding) RETURN f.title AS title LIMIT 5\n```"):
            with patch("postura.api.nl_query._execute_cypher", return_value=([{"title": "SQLi"}], "")):
                with _llm_returns("There is one SQL injection finding."):
                    result = answer_question("List findings")
        d = result.to_dict()
        assert "question" in d
        assert "answer" in d
        assert "cypher" in d
        assert "raw_results" in d
        assert "result_count" in d
        assert d["result_count"] == 1


# ---------------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------------

class TestFormatHelpers:
    def test_format_rows_empty(self):
        from postura.api.nl_query import _format_rows
        assert "(no results)" in _format_rows([])

    def test_format_rows_numbered(self):
        from postura.api.nl_query import _format_rows
        rows = [{"title": "SQLi", "severity": "CRITICAL"}, {"title": "SSRF", "severity": "HIGH"}]
        result = _format_rows(rows)
        assert "1." in result
        assert "2." in result
        assert "SQLi" in result
        assert "SSRF" in result

    def test_format_rows_skips_none_values(self):
        from postura.api.nl_query import _format_rows
        rows = [{"title": "SQLi", "cwe_id": None}]
        result = _format_rows(rows)
        assert "None" not in result
        assert "SQLi" in result


# ---------------------------------------------------------------------------
# Schema / safety constants
# ---------------------------------------------------------------------------

class TestSafetyConstants:
    def test_write_pattern_catches_merge(self):
        from postura.api.nl_query import _WRITE_KEYWORDS
        assert _WRITE_KEYWORDS.search("MERGE (n:Test) RETURN n")

    def test_write_pattern_catches_set(self):
        from postura.api.nl_query import _WRITE_KEYWORDS
        assert _WRITE_KEYWORDS.search("MATCH (n) SET n.x = 1")

    def test_write_pattern_allows_match(self):
        from postura.api.nl_query import _WRITE_KEYWORDS
        assert not _WRITE_KEYWORDS.search("MATCH (f:Finding) WHERE f.status = 'open' RETURN f")

    def test_schema_contains_all_node_labels(self):
        from postura.api.nl_query import _SCHEMA
        for label in ("Finding", "Endpoint", "Function", "DataStore", "Dependency", "TrustZone"):
            assert label in _SCHEMA

    def test_schema_contains_edge_types(self):
        from postura.api.nl_query import _SCHEMA
        for rel in ("HANDLED_BY", "CALLS", "AFFECTS", "CHAINS_TO", "USES", "READS_FROM"):
            assert rel in _SCHEMA
