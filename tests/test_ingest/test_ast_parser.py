"""Unit tests for the AST parser."""
import pytest
from pathlib import Path
from postura.ingest.ast_parser import parse_file, parse_directory

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "vulnerable_flask_app"


def test_parse_db_file():
    """Parse db.py and check extracted functions."""
    nodes, edges, accesses, _imports = parse_file(str(FIXTURE_DIR / "db.py"), str(FIXTURE_DIR))
    names = [n.name for n in nodes]
    assert "get_user_by_name" in names
    assert "get_user_by_id" in names
    assert "create_user" in names
    assert "get_all_users" in names


def test_parse_app_file():
    """Parse app.py and check extracted functions."""
    nodes, edges, accesses, _imports = parse_file(str(FIXTURE_DIR / "app.py"), str(FIXTURE_DIR))
    names = [n.name for n in nodes]
    assert "login" in names
    assert "get_user" in names
    assert "list_all_users" in names
    assert "fetch_external" in names
    assert "health" in names


def test_function_line_numbers():
    """Check line numbers are extracted correctly."""
    nodes, _, _a, _i = parse_file(str(FIXTURE_DIR / "db.py"), str(FIXTURE_DIR))
    get_user = next((n for n in nodes if n.name == "get_user_by_name"), None)
    assert get_user is not None
    assert get_user.line > 0
    assert get_user.end_line >= get_user.line


def test_call_edges_extracted():
    """Check that call edges are extracted from app.py."""
    _, edges, _a, _i = parse_file(str(FIXTURE_DIR / "app.py"), str(FIXTURE_DIR))
    callees = [e.callee for e in edges]
    assert any("get_user_by_name" in c for c in callees), f"Expected get_user_by_name in {callees}"


def test_decorator_extraction():
    """Check that decorators are captured on functions."""
    nodes, _, _a, _i = parse_file(str(FIXTURE_DIR / "app.py"), str(FIXTURE_DIR))
    login = next((n for n in nodes if n.name == "login"), None)
    assert login is not None
    assert any("route" in dec for dec in login.decorators), f"Expected route decorator, got {login.decorators}"


def test_parse_directory():
    """Parse the entire fixture directory."""
    nodes, edges, accesses = parse_directory(str(FIXTURE_DIR), str(FIXTURE_DIR))
    assert len(nodes) >= 8
    assert len(edges) >= 3


def test_datastore_detection_db_file():
    """Detect SQL access events in db.py."""
    _, _, accesses, _i = parse_file(str(FIXTURE_DIR / "db.py"), str(FIXTURE_DIR))
    assert len(accesses) > 0, "Expected at least one DataAccessEvent from db.py"

    # get_user_by_name does cursor.execute with a SELECT
    read_accesses = [a for a in accesses if a.access_type == "read"]
    write_accesses = [a for a in accesses if a.access_type == "write"]
    assert len(read_accesses) > 0, f"Expected read accesses, got {accesses}"
    assert len(write_accesses) > 0, f"Expected write accesses (INSERT in create_user), got {accesses}"


def test_datastore_pii_detection():
    """The 'users' table should be flagged as PII."""
    _, _, accesses, _i = parse_file(str(FIXTURE_DIR / "db.py"), str(FIXTURE_DIR))
    user_accesses = [a for a in accesses if "user" in a.datastore_name.lower()]
    assert len(user_accesses) > 0, f"Expected access to 'users' table, got {[a.datastore_name for a in accesses]}"


def test_import_packages_extracted():
    """parse_file returns top-level imported package names."""
    _, _, _, imports = parse_file(str(FIXTURE_DIR / "app.py"), str(FIXTURE_DIR))
    assert "flask" in imports, f"Expected 'flask' in imports, got {imports}"

    _, _, _, db_imports = parse_file(str(FIXTURE_DIR / "db.py"), str(FIXTURE_DIR))
    assert "sqlite3" in db_imports, f"Expected 'sqlite3' in db imports, got {db_imports}"
