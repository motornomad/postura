# POSTURA Ground Truth — Vulnerable Flask App Fixture

This document defines the expert-labeled expected findings, vulnerability chains, and
contextual severity assignments for the fixture at `tests/fixtures/vulnerable_flask_app/`.
It is the evaluation gold standard (P2.8b) for testing the full POSTURA pipeline.

---

## 1. Individual Findings

### F1 — SQL Injection (CWE-89)
| Field | Value |
|---|---|
| File | `db.py` |
| Line | ~14 |
| Function | `db.get_user_by_name` |
| Tool | semgrep / bandit (B608) |
| CWE | CWE-89 |
| Raw severity | HIGH |
| Evidence | `f"SELECT * FROM users WHERE username = '{username}'"` |

`get_user_by_name` interpolates user input directly into a SQL query string using an
f-string. Parameterized queries are absent. Exploitable via the `/login` endpoint which
passes `request.form.get("username")` verbatim.

---

### F2 — Missing Authentication on Admin Endpoint (CWE-306)
| Field | Value |
|---|---|
| File | `app.py` |
| Line | ~36–43 |
| Function | `app.list_all_users` |
| Tool | config_analyzer / semgrep |
| CWE | CWE-306 |
| Raw severity | HIGH |
| Evidence | `@app.route("/admin/users")` with no `@login_required` or `@admin_only` decorator |

`/admin/users` returns all user records including email and password_hash columns.
No authentication decorator is applied. The sibling `get_user` endpoint correctly uses
`@login_required`, making the omission here clearly a vulnerability rather than
intentional design.

---

### F3 — Server-Side Request Forgery (CWE-918)
| Field | Value |
|---|---|
| File | `utils.py` / `app.py` |
| Line | call site in `app.py` ~50 |
| Function | `app.fetch_external` |
| Tool | semgrep |
| CWE | CWE-918 |
| Raw severity | HIGH |
| Evidence | `url = request.json.get("url", "")` passed to `fetch_url(url)` without validation |

`/fetch` accepts an arbitrary URL from the request body and issues an HTTP request to
it. No allowlist, scheme restriction, or hostname validation is applied. Allows attackers
to probe internal services (e.g., AWS metadata endpoint at `169.254.169.254`).

---

### F4 — Hardcoded Secret Key (CWE-798)
| Field | Value |
|---|---|
| File | `config.py` |
| Line | 3 |
| Function | N/A (module-level) |
| Tool | config_analyzer / semgrep / bandit (B105) |
| CWE | CWE-798 |
| Raw severity | CRITICAL |
| Evidence | `SECRET_KEY = "super_secret_123"` |

Flask's session signing key is a well-known literal string committed to source.
An attacker with read access to the repository can forge session cookies for any user,
including admin roles.

---

### F5 — Debug Mode Enabled (CWE-94 / misconfiguration)
| Field | Value |
|---|---|
| File | `config.py` |
| Line | 4 |
| Function | N/A (module-level) |
| Tool | config_analyzer |
| CWE | — (configuration finding) |
| Raw severity | MEDIUM |
| Evidence | `DEBUG = True` consumed by `app.run(debug=DEBUG)` |

Running Flask in debug mode exposes the interactive Werkzeug debugger, which allows
arbitrary Python code execution via the browser if an unhandled exception is triggered.

---

### F6 — Dependency CVEs (multiple packages)
| Package | Pinned version | Known CVE(s) | Raw severity |
|---|---|---|---|
| werkzeug | 2.0.1 | CVE-2023-25577 | HIGH |
| requests | 2.25.0 | CVE-2023-32681 | MEDIUM |
| jinja2 | 3.0.1 | CVE-2024-22195 | MEDIUM |
| flask | 2.0.1 | (transitively affected by Werkzeug CVE) | HIGH |

All versions pinned in `requirements.txt` are intentionally outdated.

---

## 2. Expected Vulnerability Chains

### Chain A — Supply-Chain CVE Reachable from Public Endpoint (Chain Rule 3)
```
CVE on werkzeug/requests (Finding F6)
  → Dependency node (werkzeug / requests)
  → USES edge from Function (app.fetch_external)
  → HANDLED_BY Endpoint (/fetch — public, no auth)
```
**Expected**: `reachable_from_public = true` annotated on the CVE Finding node.
**Chain confidence**: HIGH (direct call path, public endpoint, no auth).

---

### Chain B — SQL Injection + Public Endpoint + PII DataStore (Chain Rule 1)
```
SQLi Finding (F1) in db.get_user_by_name
  → AFFECTS Function db.get_user_by_name
  ← CALLS from app.login (via /login endpoint, public)
  → Function db.get_user_by_name WRITES_TO / READS_FROM DataStore (users table, PII)
```
**Expected**: CHAINS_TO edge from SQLi Finding → PII DataStore node (users).
**Chain confidence**: HIGH.
**Contextual severity upgrade**: SQLi + public endpoint + PII → CRITICAL (from HIGH).

---

### Chain C — Missing Auth + PII Data Access (Chain Rule 2)
```
Endpoint /admin/users (public, no auth)
  → HANDLED_BY Function app.list_all_users
  → Function app.list_all_users CALLS db.get_all_users
  → db.get_all_users READS_FROM DataStore (users table, PII)
```
**Expected**: CHAINS_TO edge from missing-auth Finding (F2) → users DataStore.
**Chain confidence**: HIGH (direct call chain, confirmed PII columns).
**Contextual severity upgrade**: Missing auth + public endpoint + PII → CRITICAL (from HIGH).

---

## 3. Expected Contextual Severity Upgrades

| Finding | Raw | Upgrade reason | Expected contextual |
|---|---|---|---|
| F1 (SQLi) | HIGH | Public endpoint + PII datastore access | CRITICAL |
| F2 (Missing auth) | HIGH | Public endpoint + PII datastore read | CRITICAL |
| F3 (SSRF) | HIGH | Public endpoint, no auth | CRITICAL |
| F4 (Hardcoded secret) | CRITICAL | Already critical | CRITICAL |
| F5 (Debug mode) | MEDIUM | Config issue, production context | HIGH |
| F6 (Dep CVEs) | MEDIUM/HIGH | Reachable from public endpoint | +1 level |

---

## 4. Expected Graph Nodes (minimum)

| Label | Count | Notes |
|---|---|---|
| Function | ≥ 8 | get_user_by_name, get_user_by_id, create_user, get_all_users, login, get_user, list_all_users, fetch_external, health |
| Endpoint | ≥ 4 | /login (POST), /users/<id> (GET), /admin/users (GET), /fetch (POST) |
| DataStore | ≥ 1 | users table (sqlite, contains_pii=true) |
| Finding | ≥ 6 | F1–F6 above |
| Dependency | ≥ 4 | flask, werkzeug, requests, jinja2 |
| TrustZone | 4 | public, authenticated, admin, system |
| Service | 1 | vulnerable_flask_app |

---

## 5. Expected Graph Edges (minimum)

| Type | From → To | Notes |
|---|---|---|
| CALLS | app.login → db.get_user_by_name | Verified via AST |
| CALLS | app.list_all_users → db.get_all_users | Verified via AST |
| CALLS | app.fetch_external → utils.fetch_url | Verified via AST |
| HANDLED_BY | Endpoint /login → app.login | Flask route |
| HANDLED_BY | Endpoint /admin/users → app.list_all_users | Flask route |
| READS_FROM | db.get_user_by_name → DataStore(users) | SQL SELECT |
| READS_FROM | db.get_all_users → DataStore(users) | SQL SELECT |
| WRITES_TO | db.create_user → DataStore(users) | SQL INSERT |
| AFFECTS | F1 (SQLi) → db.get_user_by_name | Line containment |
| AFFECTS | F2 (Missing auth) → app.list_all_users | Line containment |
| USES | app.fetch_external → Dependency(requests) | import requests in utils.py |
| CHAINS_TO | F1 → DataStore(users) | Chain Rule 1 |
| CHAINS_TO | F2 → DataStore(users) | Chain Rule 2 |
| IN_ZONE | Endpoint /login → TrustZone(public) | No auth decorator |
| IN_ZONE | Endpoint /users/<id> → TrustZone(authenticated) | @login_required |
| IN_ZONE | Endpoint /admin/users → TrustZone(public) | Missing auth (bug) |

---

## 6. Evaluation Checklist

Use these assertions in integration tests (`tests/test_graph/test_e2e_phase3.py`):

```python
# Nodes
assert graph_has_node("Finding", cwe_id="CWE-89")
assert graph_has_node("DataStore", name="users", contains_pii=True)
assert graph_has_node("Endpoint", path="/admin/users", is_public=True)

# Edges
assert graph_has_edge("READS_FROM", from_fn="db.get_user_by_name", to_ds="users")
assert graph_has_edge("CALLS", caller="app.login", callee="db.get_user_by_name")
assert graph_has_edge("CHAINS_TO")  # at least one chain

# Severity
sqli_finding = get_finding(cwe="CWE-89")
assert sqli_finding["contextual_severity"] == "CRITICAL"

# Posture score
score = compute_posture_score()
assert score < 50  # fixture is severely vulnerable
```
