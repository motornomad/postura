"""Database access layer — INTENTIONALLY VULNERABLE for testing."""
import sqlite3


def get_connection():
    return sqlite3.connect("app.db")


def get_user_by_name(username):
    """CWE-89: SQL Injection — user input interpolated directly into SQL query."""
    conn = get_connection()
    cursor = conn.cursor()
    # VULNERABLE: f-string in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


def get_user_by_id(user_id):
    """Parameterized query — safe."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def create_user(username, email, password_hash):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (username, email, password_hash),
    )
    conn.commit()


def get_all_users():
    """Returns all users including PII (email, password_hash)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, password_hash FROM users")
    return cursor.fetchall()
