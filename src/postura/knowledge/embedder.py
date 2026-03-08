"""Embedding + ChromaDB wrapper for the POSTURA knowledge base.

Uses sentence-transformers (configurable model, defaults to BAAI/bge-m3).
ChromaDB is used in persistent mode under settings.knowledge_store_path.

Collections:
    - "cwe"   : MITRE CWE entries
    - "cve"   : NVD/GHSA CVE entries for Python ecosystem packages
    - "owasp" : OWASP Top 10 2021 entries
"""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import chromadb
from chromadb import Collection
from sentence_transformers import SentenceTransformer

from postura.config import settings

logger = logging.getLogger(__name__)

_COLLECTION_NAMES = ("cwe", "cve", "owasp")


# ---------------------------------------------------------------------------
# Lazy singletons
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _get_model() -> SentenceTransformer:
    """Load the embedding model (cached — loaded once per process)."""
    model_name = settings.embedding_model
    logger.info("Loading embedding model: %s", model_name)
    return SentenceTransformer(model_name)


@lru_cache(maxsize=1)
def _get_client() -> chromadb.PersistentClient:
    """Return the persistent ChromaDB client."""
    path = Path(settings.knowledge_store_path)
    path.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(path))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def embed_texts(texts: list[str]) -> list[list[float]]:
    """Embed a list of texts and return their vectors."""
    model = _get_model()
    vectors = model.encode(texts, show_progress_bar=False, normalize_embeddings=True)
    return [v.tolist() for v in vectors]


def get_or_create_collection(name: str) -> Collection:
    """Return (or create) a named ChromaDB collection."""
    client = _get_client()
    return client.get_or_create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},
    )


def upsert_documents(
    collection: Collection,
    ids: list[str],
    documents: list[str],
    metadatas: list[dict[str, Any]],
) -> None:
    """Embed documents and upsert them into the collection (batched)."""
    if not ids:
        return

    batch_size = 64
    for start in range(0, len(ids), batch_size):
        batch_ids = ids[start:start + batch_size]
        batch_docs = documents[start:start + batch_size]
        batch_metas = metadatas[start:start + batch_size]
        batch_embeddings = embed_texts(batch_docs)
        collection.upsert(
            ids=batch_ids,
            documents=batch_docs,
            metadatas=batch_metas,
            embeddings=batch_embeddings,
        )
    logger.info("Upserted %d documents into collection '%s'", len(ids), collection.name)


def query_collection(
    collection: Collection,
    query_text: str,
    n_results: int = 5,
    where: dict | None = None,
) -> list[dict[str, Any]]:
    """
    Query a collection with a text query.

    Returns a list of result dicts:
        {id, document, metadata, distance}
    """
    query_embedding = embed_texts([query_text])[0]
    kwargs: dict[str, Any] = {
        "query_embeddings": [query_embedding],
        "n_results": min(n_results, collection.count() or 1),
        "include": ["documents", "metadatas", "distances"],
    }
    if where:
        kwargs["where"] = where

    results = collection.query(**kwargs)
    output = []
    ids = results.get("ids", [[]])[0]
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    dists = results.get("distances", [[]])[0]
    for uid, doc, meta, dist in zip(ids, docs, metas, dists):
        output.append({
            "id": uid,
            "document": doc,
            "metadata": meta or {},
            "distance": dist,
        })
    return output


def collection_count(name: str) -> int:
    """Return the number of documents in a named collection (0 if not found)."""
    try:
        return get_or_create_collection(name).count()
    except Exception:
        return 0
