# POSTURA

**Agentic Attack Surface Posture Intelligence**

POSTURA is an agentic security system that maintains a persistent Neo4j threat graph of your codebase, updating incrementally on every commit. Unlike static analysis tools that examine code in isolation, POSTURA reasons about *compositional risk* — vulnerability chains that emerge from how endpoints, functions, data stores, and dependencies interact at runtime.

---

## Why POSTURA

Static tools (Bandit, Semgrep) find individual vulnerabilities but miss the context:

| What static tools miss | How POSTURA closes the gap |
|---|---|
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

### 5. Bootstrap knowledge base (optional, improves agent reasoning)

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

## License

MIT
