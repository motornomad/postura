"""Hybrid knowledge retriever — P4.2

Combines:
  1. Dense retrieval via ChromaDB (BGE-M3 embeddings, cosine similarity)
  2. BM25 sparse retrieval (rank-bm25) over in-memory corpus
  3. Reciprocal Rank Fusion (RRF) to merge ranked lists

Usage:
    results = retrieve("SQL injection in Flask", k=5)
    results = retrieve("werkzeug CVE", k=3, sources=["cve"])
"""
from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from rank_bm25 import BM25Okapi

from postura.knowledge.embedder import get_or_create_collection, query_collection

logger = logging.getLogger(__name__)

_COLLECTIONS = ("cwe", "cve", "owasp")
_RRF_K = 60  # standard RRF constant


# ---------------------------------------------------------------------------
# BM25 corpus — built lazily and cached per collection
# ---------------------------------------------------------------------------

@lru_cache(maxsize=3)
def _get_bm25_index(collection_name: str) -> tuple[BM25Okapi | None, list[dict]]:
    """
    Build and cache a BM25 index for a collection.
    Returns (BM25Okapi, corpus_items) or (None, []) if collection is empty.
    """
    try:
        collection = get_or_create_collection(collection_name)
        count = collection.count()
        if count == 0:
            return None, []

        # Fetch all documents (ChromaDB supports get() for full corpus)
        results = collection.get(include=["documents", "metadatas"])
        ids = results.get("ids", [])
        docs = results.get("documents", [])
        metas = results.get("metadatas", [])

        corpus_items = [
            {"id": uid, "document": doc, "metadata": meta or {}}
            for uid, doc, meta in zip(ids, docs, metas)
        ]
        tokenized = [doc.lower().split() for doc in docs]
        bm25 = BM25Okapi(tokenized)
        logger.info("Built BM25 index for '%s': %d docs", collection_name, len(corpus_items))
        return bm25, corpus_items

    except Exception as exc:
        logger.warning("Failed to build BM25 index for '%s': %s", collection_name, exc)
        return None, []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def retrieve(
    query: str,
    k: int = 5,
    sources: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Hybrid retrieval across knowledge collections.

    Args:
        query: Natural language query.
        k: Number of results to return.
        sources: Optional filter. Any subset of ["cwe", "cve", "owasp"].
                 Defaults to all three.

    Returns:
        List of result dicts (id, document, metadata, score) sorted by RRF score desc.
    """
    target_collections = sources or list(_COLLECTIONS)
    # Validate
    target_collections = [c for c in target_collections if c in _COLLECTIONS]
    if not target_collections:
        return []

    all_results: dict[str, dict[str, Any]] = {}  # id → result
    dense_ranks: dict[str, int] = {}              # id → rank (1-based)
    sparse_ranks: dict[str, int] = {}             # id → rank (1-based)

    fetch_k = k * 4  # fetch more for fusion

    for col_name in target_collections:
        collection = get_or_create_collection(col_name)
        if collection.count() == 0:
            continue

        # Dense retrieval
        dense_results = query_collection(collection, query, n_results=min(fetch_k, collection.count()))
        for rank, result in enumerate(dense_results, start=1):
            uid = result["id"]
            dense_ranks[uid] = min(dense_ranks.get(uid, rank), rank)
            all_results[uid] = result

        # Sparse retrieval (BM25)
        bm25, corpus_items = _get_bm25_index(col_name)
        if bm25 and corpus_items:
            query_tokens = query.lower().split()
            scores = bm25.get_scores(query_tokens)
            ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
            for rank, (idx, score) in enumerate(ranked[:fetch_k], start=1):
                uid = corpus_items[idx]["id"]
                sparse_ranks[uid] = min(sparse_ranks.get(uid, rank), rank)
                if uid not in all_results:
                    all_results[uid] = corpus_items[idx]

    if not all_results:
        return []

    # Reciprocal Rank Fusion
    rrf_scores: dict[str, float] = {}
    for uid in all_results:
        dense_score = 1.0 / (_RRF_K + dense_ranks.get(uid, fetch_k + 1))
        sparse_score = 1.0 / (_RRF_K + sparse_ranks.get(uid, fetch_k + 1))
        rrf_scores[uid] = dense_score + sparse_score

    sorted_ids = sorted(rrf_scores, key=rrf_scores.__getitem__, reverse=True)
    results = []
    for uid in sorted_ids[:k]:
        item = dict(all_results[uid])
        item["score"] = rrf_scores[uid]
        results.append(item)

    return results


def retrieve_by_cwe(cwe_id: str, k: int = 3) -> list[dict[str, Any]]:
    """
    Retrieve CWE entries by CWE ID (exact match preferred, then semantic fallback).

    Args:
        cwe_id: e.g. "CWE-89" or "89"
    """
    if not cwe_id.upper().startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"
    cwe_id = cwe_id.upper()

    collection = get_or_create_collection("cwe")
    if collection.count() == 0:
        return []

    # Try direct ID lookup first
    try:
        result = collection.get(ids=[cwe_id], include=["documents", "metadatas"])
        if result["ids"]:
            return [{
                "id": result["ids"][0],
                "document": result["documents"][0],
                "metadata": (result["metadatas"] or [{}])[0],
                "score": 1.0,
            }]
    except Exception:
        pass

    # Fallback to semantic search
    return retrieve(cwe_id, k=k, sources=["cwe"])


def invalidate_bm25_cache() -> None:
    """Invalidate BM25 index cache (call after reloading knowledge base)."""
    _get_bm25_index.cache_clear()
    logger.info("BM25 cache cleared")
