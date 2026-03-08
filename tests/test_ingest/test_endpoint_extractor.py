"""Unit tests for the endpoint extractor."""
import pytest
from pathlib import Path
from postura.ingest.endpoint_extractor import extract_endpoints

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "vulnerable_flask_app"


def test_extract_flask_endpoints():
    """Extract all endpoints from the Flask fixture app.py."""
    eps = extract_endpoints(
        str(FIXTURE_DIR / "app.py"),
        module="app",
        repo_root=str(FIXTURE_DIR),
    )
    paths = [ep.path for ep in eps]
    assert "/login" in paths
    assert "/admin/users" in paths
    assert "/fetch" in paths
    assert "/health" in paths


def test_login_endpoint_method():
    eps = extract_endpoints(str(FIXTURE_DIR / "app.py"), "app", str(FIXTURE_DIR))
    login_eps = [ep for ep in eps if ep.path == "/login"]
    assert len(login_eps) >= 1
    assert login_eps[0].method == "POST"


def test_admin_endpoint_not_authenticated():
    """The /admin/users endpoint has no auth — should be flagged as public."""
    eps = extract_endpoints(str(FIXTURE_DIR / "app.py"), "app", str(FIXTURE_DIR))
    admin_ep = next((ep for ep in eps if ep.path == "/admin/users"), None)
    assert admin_ep is not None
    assert admin_ep.auth_required is False


def test_get_user_endpoint_authenticated():
    """The /users/<user_id> endpoint has @login_required."""
    eps = extract_endpoints(str(FIXTURE_DIR / "app.py"), "app", str(FIXTURE_DIR))
    user_ep = next((ep for ep in eps if "/users/" in ep.path), None)
    assert user_ep is not None
    assert user_ep.auth_required is True


def test_handler_function_qualified_name():
    eps = extract_endpoints(str(FIXTURE_DIR / "app.py"), "app", str(FIXTURE_DIR))
    login_ep = next((ep for ep in eps if ep.path == "/login"), None)
    assert login_ep is not None
    assert "login" in login_ep.handler_function
