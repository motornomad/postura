"""Auth middleware — INTENTIONALLY has gaps."""
from functools import wraps
from flask import session, redirect, url_for, request


def login_required(f):
    """Decorator that requires the user to be logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_only(f):
    """Decorator that requires admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            return {"error": "Forbidden"}, 403
        return f(*args, **kwargs)
    return decorated_function
