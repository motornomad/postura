# POSTURA

**Agentic Attack Surface Posture Intelligence**

POSTURA is an agentic security system that maintains a persistent Neo4j threat graph of your codebase, updating incrementally on every commit. Unlike static analysis tools that examine code in isolation, POSTURA reasons about *compositional risk* — vulnerability chains that emerge from how endpoints, functions, data stores, and dependencies interact at runtime.

---

## The problem static tools miss

Two developers. Two innocent commits. Neither triggers a SAST alert alone.

**Commit A** — Developer adds `GET /api/orders/<order_id>` without `@login_required`. Bandit and Semgrep flag it as a missing-auth warning. Not critical — the endpoint only returns order status. PR is merged.

**Commit B** — Different developer adds `get_user_by_id()` to `db.py` and wires it into `get_order()` for the order confirmation view. A diff-only SAST scan of the changed files sees a new SQL query. Nothing in the diff says *"this query is now reachable from an unauthenticated public endpoint."* No alert fires.

**What actually happened:** any unauthenticated HTTP request to `/api/orders/<any_id>` now returns the buyer's email, name, address, and phone number. No token required. No brute force. One GET request per order ID.

POSTURA detects this because the graph persists across commits. When commit B creates the `CALLS` edge `get_order → get_user_by_id` and the `READS_FROM` edge to `DataStore(users, PII=true)`, chain discovery fires on the CWE-306 finding that was recorded in commit A:

```
[1] COMMIT A — PR NOT BLOCKED
    ⚠ [CRITICAL] Missing Authentication on Public Endpoint (CWE-306)
    ✓  No vulnerability chains detected
    → PR DECISION: NOT BLOCKED  (missing auth flagged, chain incomplete)

[2] COMMIT B — PR BLOCKED
    🔴 1 vulnerability chain(s) detected:
    Chain: [Missing Authentication on Public Endpoint] ──CHAINS_TO──▶ [users]
    CWE:   CWE-306  |  Conf: 0.95
    Evidence: Endpoint '/api/orders/<order_id>' has no authentication (CWE-306)
    and its call chain directly reads PII from datastore 'users'.
    An unauthenticated attacker can retrieve all user records.
    → PR DECISION: BLOCKED  (CRITICAL chain confirmed)
```

Run this demo yourself:
```bash
docker compose up -d neo4j
PYTHONPATH=src python demo/run_demo.py
```

---

## Why POSTURA

Static tools (Bandit, Semgrep) find individual vulnerabilities but miss the context:

| What static tools miss | How POSTURA closes the gap |
|---|---|
| Cross-commit chains — two safe commits combine into an exploit | Persistent graph remembers prior state across every commit |
| Missing auth (CWE-306) — no static test for "should have auth" | Auth graph edge absence + public endpoint flag |
| Contextual severity — code severity ≠ runtime severity | Graph paths: exposure × datastore sensitivity |
| Supply-chain CVE reachability — CVE known, call-path unknown | USES edges: Function→Dependency + endpoint reachability |
| SQLi + PII chains — B608 finds SQLi, but not the PII path | CHAINS_TO: Finding→DataStore(PII=true) |
| Dependency blast radius — not modeled anywhere | Graph traversal: Dependency→Function→Endpoint |

On the included vulnerable Flask fixture, Bandit detects **4/6 findings** (67%), all at incorrect severities, and **0/3 vulnerability chains**. POSTURA targets **6/6 findings** and **3/3 chains**.

---

## Architecture

```
GitHub webhook
     │
     ▼
WebhookReceiver (FastAPI)
     │  push / PR event
     ▼
ScopeAnalyzer ──► git diff → changed files
     │
     ▼
AST Parser (tree-sitter)
  ├─ ASTNode (functions, classes)
  ├─ CallEdge (function→function)
  ├─ DataAccessEvent (SQL/ORM reads)
  └─ ImportedPackages (top-level)
     │
     ▼
GraphBuilder / GraphUpdater (Neo4j)
  Nodes: Finding · Endpoint · Function · DataStore · Dependency · TrustZone
  Edges: HANDLED_BY · CALLS · AFFECTS · CHAINS_TO · USES · READS_FROM · IN_ZONE
     │
     ▼
Reasoning Layer (LangGraph ReAct agent + 6 tools)
  ├─ graph_query        — read-only Cypher
  ├─ knowledge_retrieve — BM25 + ChromaDB hybrid search (CWE/CVE/OWASP)
  ├─ trace_dataflow     — endpoint → function → datastore paths
  ├─ find_chains        — vulnerability chain discovery
  ├─ assess_exploitability — context-aware severity scoring
  └─ generate_remediation  — LLM-powered fix suggestions
     │
     ▼
Delivery Layer
  ├─ GitHub PR comment (POST /repos/.../issues/.../comments)
  ├─ GitHub commit status (POST /repos/.../statuses/...)
  └─ Posture history (PostureSnapshot nodes in Neo4j)
     │
     ▼
REST API (FastAPI)
  /api/v1/posture      /api/v1/findings   /api/v1/chains
  /api/v1/endpoints    /api/v1/dashboard  /api/v1/history
  /api/v1/trend        /api/v1/query      /api/v1/knowledge/*
```

---

## Quickstart

### Prerequisites

- Python 3.11+
- Docker (for Neo4j and Redis)

### 1. Install

```bash
pip install postura
```

### 2. Initialize and start

```bash
postura init     # configure .env, pull Docker images
postura start    # start Neo4j + Redis + API + Celery worker
```

### 3. Analyze a repository

```bash
# Offline: SAST + AST parse, no services required
postura analyze ./myproject

# Full: builds threat graph + discovers vulnerability chains
postura analyze ./myproject --full
```

### 4. View results

```bash
postura status   # posture score + finding counts
postura open     # open API dashboard in browser
```

### 5. Local LLM (no Anthropic account needed)

POSTURA works with any OpenAI-compatible local model server — Ollama, vLLM, LM Studio:

```bash
# Example: Ollama with Llama 3.2
ollama pull llama3.2

# In your .env:
POSTURA_LLM_PROVIDER=openai_compatible
POSTURA_LLM_BASE_URL=http://localhost:11434/v1
POSTURA_LLM_MODEL=llama3.2
POSTURA_LLM_API_KEY=ollama
```

For best results with local models use a code-aware model: `qwen2.5-coder`, `deepseek-coder-v2`, or `codellama`. The agent relies on structured tool calling — verify your chosen model supports it.

### 6. Bootstrap knowledge base (optional, improves agent reasoning)

```bash
# OWASP Top 10 (offline, always works)
curl -X POST "http://localhost:8000/api/v1/knowledge/reload?sources=owasp"

# CWE + CVE (requires network)
curl -X POST "http://localhost:8000/api/v1/knowledge/reload?sources=cwe,cve"
```

### 6. GitHub webhook integration

```bash
# Point your GitHub repo's webhook at:
# http://<your-server>/webhook/github
# Content-Type: application/json
# Secret: $POSTURA_GITHUB_WEBHOOK_SECRET
```

### Manual setup (advanced)

For custom deployments without the CLI:

```bash
docker run -d --name neo4j \
  -e NEO4J_AUTH=neo4j/postura_dev \
  -p 7474:7474 -p 7687:7687 \
  neo4j:5

docker run -d --name redis -p 6379:6379 redis:7-alpine

cp .env.example .env  # fill in API keys
uvicorn postura.api.app:app --reload
celery -A postura.tasks.celery_app worker --loglevel=info
```

---

## REST API

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/posture` | Current posture score + finding counts |
| GET | `/api/v1/findings` | All findings (filter by status, severity) |
| GET | `/api/v1/findings/{uid}` | Finding detail with graph context |
| GET | `/api/v1/findings/{uid}/chains` | Chains involving a finding |
| POST | `/api/v1/findings/{uid}/remediate` | LLM remediation suggestion |
| GET | `/api/v1/endpoints` | All endpoints with trust zone / auth |
| GET | `/api/v1/chains` | All vulnerability chains |
| GET | `/api/v1/dashboard` | Top risks, trend, chain count |
| GET | `/api/v1/history` | Time-series posture history |
| GET | `/api/v1/trend` | Posture trend over N snapshots |
| POST | `/api/v1/query` | Natural language graph query |
| GET | `/api/v1/diff/{sha}` | Findings introduced/resolved by commit |
| GET | `/api/v1/dependencies/{name}/blast-radius` | Dependency blast radius |
| POST | `/api/v1/knowledge/reload` | Reload CWE/CVE/OWASP knowledge |
| GET | `/api/v1/knowledge/status` | Knowledge collection sizes |
| GET | `/api/v1/knowledge/search` | Hybrid search across knowledge base |

### Natural language query

```bash
curl -X POST http://localhost:8000/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"question": "Which public endpoints have no authentication?"}'
```

```json
{
  "question": "Which public endpoints have no authentication?",
  "answer": "There are 2 public unauthenticated endpoints: GET /admin/users and GET /fetch. The /admin/users endpoint exposes PII from the users table without any authentication check (CWE-306).",
  "cypher": "MATCH (e:Endpoint {is_public: true, auth_required: false}) RETURN e.path, e.method",
  "result_count": 2,
  "raw_results": [...]
}
```

---

## Evaluation

```bash
# Static baseline only (no Neo4j required)
PYTHONPATH=. python evaluation/baseline_static.py

# Full comparison report (requires ingested graph)
PYTHONPATH=. python evaluation/report.py

# Save Markdown report
PYTHONPATH=. python evaluation/report.py --output evaluation/REPORT.md
```

**Benchmark results on vulnerable Flask fixture** (`tests/fixtures/vulnerable_flask_app`):

| Metric | Bandit | POSTURA |
|---|---|---|
| Findings detected (6 total) | 4 (67%) | 6 (100%) |
| Severity correct | ❌ 3/4 underrated | ✅ Contextual |
| Chains detected (3 total) | 0 (0%) | 3 (100%) |
| Missing auth (F2/CWE-306) | ❌ | ✅ |
| Supply-chain reachability | ❌ | ✅ |

---

## Development

```bash
# Run all tests (skips e2e that need Docker)
PYTHONPATH=. .venv/bin/pytest tests/ -v

# Run evaluation tests only
PYTHONPATH=. .venv/bin/pytest tests/test_evaluation/ -v

# Type check
.venv/bin/mypy src/postura --ignore-missing-imports

# Lint
.venv/bin/ruff check src/
```

---

## Phase Completion

| Phase | Description | Status |
|---|---|---|
| P1 | Foundation (models, ingest, AST parser) | ✅ |
| P2 | Threat Graph (Neo4j builder, chain discovery, severity scoring) | ✅ |
| P3 | Incremental Updates (webhook, git diff, updater) | ✅ |
| P4 | Reasoning Layer (LangGraph agent, knowledge base, 6 tools) | ✅ |
| P5 | Delivery & Reporting (GitHub integration, dashboard, NL query) | ✅ |
| P5.5 | Evaluation Framework (ground truth, baseline, report generator) | ✅ |

---

## Security & Limitations

**This is pre-production software.** Do not expose the API publicly without adding authentication in front of it.

### What is hardened
- **Webhook HMAC verification** — all GitHub webhook payloads are verified against `POSTURA_GITHUB_WEBHOOK_SECRET` using SHA-256 HMAC before processing (`webhook/receiver.py`). Set this secret or webhooks are rejected.
- **Read-only Cypher** — the agent's `graph_query` tool blocks write operations (CREATE, MERGE, DELETE, SET) to prevent prompt injection from modifying the threat graph.
- **Subprocess sandboxing** — Semgrep and Bandit run as subprocesses with a 120s timeout. They do not have network access.

### What is not yet hardened (known gaps)
- **No API authentication** — the REST API has no auth layer. Run it behind a reverse proxy with auth (nginx + basic auth, or a gateway) if exposed beyond localhost.
- **No rate limiting** — add via your reverse proxy or a middleware like `slowapi`.
- **No RBAC** — all API consumers have full read/write access to findings.
- **No audit log** — finding status changes and agent runs are not logged to an immutable store.
- **Secrets in the graph** — POSTURA's config analyzer detects hardcoded secrets in source files and stores the evidence string in Neo4j. The evidence is truncated to 200 chars but may contain partial secret values. Secure your Neo4j instance accordingly.

### Data leaving your network
When using `POSTURA_LLM_PROVIDER=anthropic` or `openai`, code context (function names, finding descriptions, diff summaries) is sent to the respective API. **No full source files are sent** — only the structured graph data extracted from them.

Use `POSTURA_LLM_PROVIDER=openai_compatible` with a local model to keep all data on-premises.

---

## License

MIT
