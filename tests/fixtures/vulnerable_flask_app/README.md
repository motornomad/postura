# Vulnerable Flask App — POSTURA Test Fixture

> **WARNING: This application is intentionally insecure. Do NOT deploy it.**
> It exists solely as a test fixture for POSTURA's detection capabilities.

## Intentional Vulnerabilities

| # | Vulnerability | CWE | Location | Description |
|---|--------------|-----|----------|-------------|
| 1 | SQL Injection | CWE-89 | `db.py:get_user_by_name()` | f-string used directly in SQL query |
| 2 | Hardcoded Secret | CWE-798 | `config.py:SECRET_KEY` | `SECRET_KEY = "super_secret_123"` |
| 3 | Missing Authentication | CWE-306 | `app.py:/admin/users` | Admin endpoint has no `@login_required` or `@admin_only` |
| 4 | SSRF | CWE-918 | `utils.py:fetch_url()` | User-supplied URL passed to `urllib.request.urlopen` without validation |
| 5 | Debug Mode | CWE-215 | `config.py:DEBUG=True` | Debug mode enabled, leaks stack traces |
| 6 | Vulnerable Dependencies | Various CVEs | `requirements.txt` | Old pinned versions of flask, werkzeug, requests with known CVEs |

## The PII Exposure Chain (Multi-hop)

This is the key chain POSTURA should detect:

```
Public Endpoint (/login)
    → login() handler
    → get_user_by_name(username)   [SQL Injection — CWE-89]
    → users table                  [contains PII: email, password_hash]
```

Attack narrative: An unauthenticated attacker can exploit the SQL injection in
`get_user_by_name()` via the public `/login` endpoint to exfiltrate all user records
including email addresses and password hashes from the `users` table.

## The Missing Auth Chain

```
Public Endpoint (/admin/users)
    → list_all_users() handler     [Missing auth — CWE-306]
    → get_all_users()
    → users table                  [contains PII: email, password_hash]
```

## Why This Matters for POSTURA

- Static tools (Semgrep/Bandit) detect each vulnerability individually
- POSTURA detects the **chains**: that these vulnerabilities compose into a critical risk
- POSTURA assigns **contextual severity**: SQLi in public endpoint + PII = CRITICAL
  (even if the raw CVSS score is only HIGH)
