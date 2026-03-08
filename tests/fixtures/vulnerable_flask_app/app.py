"""Main Flask app — INTENTIONALLY VULNERABLE for testing POSTURA."""
from flask import Flask, request, jsonify, session
from config import SECRET_KEY, DEBUG
from auth import login_required, admin_only
from db import get_user_by_name, get_user_by_id, create_user, get_all_users
from utils import fetch_url

app = Flask(__name__)
app.secret_key = SECRET_KEY


@app.route("/login", methods=["POST"])
def login():
    """Login endpoint — calls vulnerable get_user_by_name (SQLi)."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # VULNERABLE: passes user input directly to SQL-injectable function
    user = get_user_by_name(username)
    if user:
        session["user_id"] = user[0]
        session["role"] = "user"
        return jsonify({"status": "ok"})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/users/<int:user_id>", methods=["GET"])
@login_required
def get_user(user_id):
    """Get user by ID — authenticated."""
    user = get_user_by_id(user_id)
    if user:
        return jsonify({"id": user[0], "username": user[1], "email": user[2]})
    return jsonify({"error": "Not found"}), 404


@app.route("/admin/users", methods=["GET"])
def list_all_users():
    """CWE-306: Missing auth — admin endpoint without @login_required or @admin_only."""
    users = get_all_users()
    return jsonify([
        {"id": u[0], "username": u[1], "email": u[2]}
        for u in users
    ])


@app.route("/fetch", methods=["POST"])
def fetch_external():
    """CWE-918: SSRF — passes user-supplied URL to fetch_url without validation."""
    url = request.json.get("url", "")
    content = fetch_url(url)
    return jsonify({"content": content[:1000]})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # DEBUG=True is a vulnerability in production
    app.run(debug=DEBUG, host="0.0.0.0", port=5000)
