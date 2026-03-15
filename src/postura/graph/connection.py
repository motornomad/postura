"""Neo4j driver wrapper with connection pooling and health check."""
import logging
from contextlib import contextmanager
from typing import Generator

from neo4j import GraphDatabase, Driver, Session
from neo4j.exceptions import ServiceUnavailable

from postura.config import settings

# Suppress neo4j notification spam (e.g. "relationship type USES does not exist yet")
# These are harmless schema-order warnings, not errors.
logging.getLogger("neo4j.notifications").setLevel(logging.ERROR)

_driver: Driver | None = None


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            max_connection_pool_size=50,
        )
    return _driver


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None


@contextmanager
def get_session() -> Generator[Session, None, None]:
    driver = get_driver()
    session = driver.session()
    try:
        yield session
    finally:
        session.close()


def health_check() -> bool:
    """Return True if Neo4j is reachable, False otherwise."""
    try:
        with get_session() as session:
            result = session.run("RETURN 1 AS ok")
            record = result.single()
            return record is not None and record["ok"] == 1
    except ServiceUnavailable:
        return False


def run_query(cypher: str, params: dict | None = None) -> list[dict]:
    """Execute a Cypher query and return results as a list of dicts."""
    with get_session() as session:
        result = session.run(cypher, params or {})
        return [dict(record) for record in result]


def run_write(cypher: str, params: dict | None = None) -> None:
    """Execute a write Cypher statement (no return value needed)."""
    with get_session() as session:
        session.run(cypher, params or {})
