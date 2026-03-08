# POSTURA — Build Task List

> Granular task list for the 12-week build.
> Each task is scoped to a single coding session (1–3 hours).
> Reference `IMPLEMENTATION_CONTEXT.md` for detailed specs on any task.
> Reference `POSTURA_ARCHITECTURE.md` for the high-level vision.

---

## Phase 1: Foundation (Week 1–2)

> **Goal:** Parse a Python repo, build a basic graph in Neo4j, visualize it.

### P1.1 — Project Scaffolding
- [x] **P1.1a** Create `pyproject.toml` with core dependencies
  - Dependencies: fastapi, uvicorn, neo4j, pydantic, pydantic-settings, celery, redis, tree-sitter, tree-sitter-python, httpx, pytest, testcontainers
  - Dev dependencies: ruff, mypy, pytest-asyncio
  - Files: `pyproject.toml`
  - Done when: `pip install -e .` succeeds

- [x] **P1.1b** Create project directory structure (empty `__init__.py` files)
  - All directories from repo structure in architecture doc
  - Files: `src/postura/**/__init__.py`
  - Done when: `from postura import config` doesn't error

- [x] **P1.1c** Create `config.py` with pydantic-settings
  - See §1.3 in Implementation Context for exact schema
  - Create `.env.example` with all variables documented
  - Files: `src/postura/config.py`, `.env.example`
  - Done when: `Settings()` loads from env vars or `.env`

- [x] **P1.1d** Create Docker Compose file
  - Services: neo4j (5-community), redis (7-alpine)
  - See §1.2 in Implementation Context for exact spec
  - Files: `docker-compose.yml`
  - Done when: `docker compose up -d` starts both services, Neo4j Browser accessible at localhost:7474

### P1.2 — Neo4j Connection & Schema
- [x] **P1.2a** Neo4j driver wrapper
  - Connection class with context manager, connection pooling
  - Health check method (run a trivial query)
  - Files: `src/postura/graph/connection.py`
  - Done when: can connect to Neo4j from Python, run `RETURN 1`, get result

- [x] **P1.2b** Schema initialization
  - Function to create all constraints and indexes (see §2.3 in Implementation Context)
  - Idempotent — safe to run multiple times (`IF NOT EXISTS`)
  - Files: `src/postura/graph/schema.py`
  - Done when: constraints and indexes visible in Neo4j Browser

### P1.3 — Pydantic Data Models
- [x] **P1.3a** Ingest models
  - `ASTNode`, `CallEdge`, `SASTFinding`, `DepVulnerability`, `EndpointInfo`, `ConfigIssue`, `StructuredIngestResult`
  - See §3.1 in Implementation Context
  - Files: `src/postura/models/ingest.py`
  - Done when: all models instantiate and serialize to JSON

- [x] **P1.3b** Graph models
  - Node/edge creation helpers: functions that take Pydantic models and produce Cypher parameter dicts
  - UID generation functions for each node type
  - Files: `src/postura/models/graph.py`
  - Done when: `create_function_uid("module", "func")` returns `"fn:module:func"`

### P1.4 — Tree-sitter Parser
- [x] **P1.4a** Basic Python file parsing
  - Parse a `.py` file into a tree-sitter syntax tree
  - Extract function definitions: name, line, end_line, parameters, decorators
  - Extract class definitions: name, methods
  - Files: `src/postura/ingest/ast_parser.py`
  - Done when: parsing a sample Python file returns correct list of `ASTNode` objects

- [x] **P1.4b** Import extraction
  - Parse `import X` and `from X import Y` statements
  - Build module → imported names map per file
  - Files: `src/postura/ingest/ast_parser.py` (extend)
  - Done when: import map for a multi-file project is correct

- [x] **P1.4c** Call graph extraction
  - Walk function bodies, find `call` expression nodes
  - Resolve callee to qualified name using import map + local scope
  - Output: list of `CallEdge` objects
  - Depends on: P1.4a, P1.4b
  - Files: `src/postura/ingest/ast_parser.py` (extend)
  - Done when: call graph for a sample Python file has correct caller→callee pairs

### P1.5 — SAST Tool Integration
- [x] **P1.5a** Semgrep runner
  - Subprocess wrapper: invoke semgrep with JSON output on a target directory
  - Parse JSON into list of `SASTFinding` objects
  - Handle: semgrep not installed (skip gracefully), empty results, error results
  - Files: `src/postura/ingest/sast_runner.py`
  - Done when: running on vulnerable Flask fixture returns findings

- [x] **P1.5b** Bandit runner
  - Subprocess wrapper: invoke bandit with JSON output
  - Parse JSON into list of `SASTFinding` objects
  - Deduplication with Semgrep findings (same file + overlapping lines + same CWE)
  - Files: `src/postura/ingest/sast_runner.py` (extend)
  - Done when: running on vulnerable Flask fixture returns findings, deduped with Semgrep

### P1.6 — Graph Population
- [x] **P1.6a** Graph builder: Function nodes + CALLS edges
  - Take `ASTNode` list → create `:Function` nodes in Neo4j via Cypher MERGE
  - Take `CallEdge` list → create `:CALLS` edges
  - Batch operations for performance
  - Depends on: P1.2a, P1.2b, P1.3b, P1.4c
  - Files: `src/postura/graph/builder.py`
  - Done when: Neo4j Browser shows function nodes connected by CALLS edges

- [x] **P1.6b** Graph builder: Finding nodes + AFFECTS edges
  - Take `SASTFinding` list → create `:Finding` nodes
  - Map findings to functions by file + line range overlap → create `:AFFECTS` edges
  - Depends on: P1.5a, P1.6a
  - Files: `src/postura/graph/builder.py` (extend)
  - Done when: findings visible in Neo4j connected to the functions they affect

- [x] **P1.6c** Graph builder: Endpoint nodes + HANDLED_BY edges
  - Take `EndpointInfo` list → create `:Endpoint` nodes
  - Create `:HANDLED_BY` edges to handler functions
  - Depends on: P1.6a
  - Files: `src/postura/graph/builder.py` (extend)
  - Done when: endpoints visible in Neo4j connected to their handler functions

### P1.7 — Endpoint Extraction
- [x] **P1.7a** Flask endpoint extractor
  - Detect `@app.route`, `@blueprint.route`, `@app.get/post/put/delete` decorators
  - Extract: path, method(s), handler function, auth decorators
  - Files: `src/postura/ingest/endpoint_extractor.py`
  - Done when: correctly extracts all routes from vulnerable Flask fixture

- [x] **P1.7b** FastAPI endpoint extractor
  - Detect `@app.get`, `@router.post`, etc. decorators
  - Detect `Depends()` for auth
  - Files: `src/postura/ingest/endpoint_extractor.py` (extend)
  - Done when: correctly extracts all routes from a sample FastAPI app

### P1.8 — Test Fixture & Phase 1 Milestone
- [x] **P1.8a** Create vulnerable Flask app test fixture
  - Small Flask app with: SQL injection, hardcoded secret, missing auth, SSRF, vulnerable dependency
  - See §8.1 in Implementation Context for exact structure
  - Files: `tests/fixtures/vulnerable_flask_app/**`
  - Done when: app runs, vulnerabilities are documented in its README

- [ ] **P1.8b** Phase 1 end-to-end test
  - Parse the vulnerable Flask app
  - Run Semgrep + Bandit on it
  - Build graph: Function nodes, Endpoint nodes, Finding nodes, CALLS edges, HANDLED_BY edges, AFFECTS edges
  - Assert: correct node counts, correct edge connectivity
  - Files: `tests/test_ingest/test_e2e_phase1.py`
  - **MILESTONE:** Can ingest a Python repo and visualize the call graph + findings in Neo4j Browser
  - NOTE: Requires Neo4j running (Docker). Unit tests for parser/extractor are passing (11/11).

---

## Phase 2: Threat Graph (Week 3–4)

> **Goal:** Full graph schema with all node/edge types. Compositional risk (CHAINS_TO).

### P2.1 — DataStore & Data Access Edges
- [x] **P2.1a** DataStore detection
  - Detect database calls: SQLAlchemy session/query, raw SQL (sqlite3, psycopg2), Redis client calls
  - Detect file system operations: open(), Path operations
  - Create `:DataStore` nodes with type, name, contains_pii heuristic
  - PII heuristic: table/variable names containing `user`, `email`, `password`, `payment`, `profile`, `ssn`, `address`
  - Files: `src/postura/ingest/ast_parser.py` (extend), `src/postura/graph/builder.py` (extend)
  - DataAccessEvent model added to models/ingest.py; _detect_data_access() in ast_parser; 13/13 tests pass

- [x] **P2.1b** READS_FROM / WRITES_TO edges
  - From function call analysis: `cursor.execute("SELECT...")` → READS_FROM
  - Heuristic: SELECT/GET = read, INSERT/UPDATE/DELETE/SET = write
  - Files: `src/postura/graph/builder.py` (extend) — _create_datastore_nodes() added
  - Done: SQL read/write classification from SQL string keywords

### P2.2 — Trust Zones & Service Boundaries
- [x] **P2.2a** TrustZone inference
  - Directory/path heuristic: public/admin/authenticated/system zones
  - Create `:TrustZone` nodes + `:IN_ZONE` edges from endpoints
  - Files: `src/postura/graph/builder.py` — _infer_trust_zone(), _create_trustzones()

- [x] **P2.2b** Service boundary detection
  - Single `:Service` node + `:BELONGS_TO` edges for monolith
  - Files: `src/postura/graph/builder.py` — _create_service_node()

### P2.3 — Dependency Scanning
- [x] **P2.3a** pip-audit integration
  - Files: `src/postura/ingest/dep_scanner.py` — scan_dependencies(), scan_project()

- [x] **P2.3b** Dependency nodes + edges
  - `:Dependency` nodes, `:AFFECTS` findings, `:USES` edges fully implemented
  - `parse_file()` now returns 4-tuple including `imported_packages: list[str]`
  - `StructuredIngestResult.file_imports: dict[str, list[str]]` populated by updater
  - `GraphBuilder._create_uses_edges()` creates `(Function)-[:USES {via_import}]->(Dependency)` edges
  - Chain Rule 3 (supply-chain CVE reachable from public endpoint) now works end-to-end
  - Files: `src/postura/models/ingest.py`, `src/postura/ingest/ast_parser.py`, `src/postura/graph/updater.py`, `src/postura/graph/builder.py`

### P2.4 — Config Analysis
- [x] **P2.4a** Config analyzer
  - Hardcoded secrets, CORS, debug mode detection
  - Files: `src/postura/ingest/config_analyzer.py`

### P2.5 — Auth Detection
- [x] **P2.5a** Endpoint auth classification
  - Decorator pattern matching + function parameter inspection
  - Files: `src/postura/ingest/endpoint_extractor.py` — _detect_auth()

### P2.6 — Call-Graph Reachability & Chain Detection
- [x] **P2.6a** Reachability analysis
  - Cypher queries in `src/postura/graph/queries.py` — check_reachability_from_public()
  - `reachable_from_public` property set on Finding nodes via chain_discovery.py

- [x] **P2.6b** CHAINS_TO edge computation (rule-based)
  - Rule 1: SQLi + public endpoint + PII datastore
  - Rule 2: Missing auth endpoint + PII data access
  - Rule 3: Vulnerable dependency reachable from public endpoint
  - Files: `src/postura/reasoning/chain_discovery.py` — discover_chains()

### P2.7 — Posture Scoring
- [x] **P2.7a** Contextual severity scoring (rule-based)
  - All 4 rules implemented: public+no auth+PII=+2, public+no auth=+1, strong auth=-1, chain=+1
  - Files: `src/postura/reasoning/severity_scorer.py` — score_all_findings()

- [x] **P2.7b** Aggregate posture score
  - CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, normalized to 0–100
  - Files: `src/postura/reasoning/severity_scorer.py` — compute_posture_score()

### P2.8 — Phase 2 Milestone
- [x] **P2.8a** Full graph population test written
  - Files: `tests/test_graph/test_e2e_phase2.py`
  - Tests: node type presence, edge types, posture score, public endpoint detection
  - NOTE: Requires Neo4j running (`docker compose up -d neo4j`) — unit tests pass (13/13)
  - **MILESTONE READY:** Run `pytest tests/test_graph/test_e2e_phase2.py` with Neo4j up

- [x] **P2.8b** Document ground truth for evaluation
  - All 6 findings, 3 chains, expected contextual severity upgrades, minimum node/edge counts, evaluation checklist
  - Files: `tests/fixtures/vulnerable_flask_app/GROUND_TRUTH.md`

---

## Phase 3: Incremental Updates (Week 5–6)

> **Goal:** Push a commit, graph updates incrementally, diff is computed.

### P3.1 — Webhook Infrastructure
- [x] **P3.1a** GitHub webhook receiver
  - FastAPI endpoint: `POST /webhook/github`, HMAC-SHA256 verification, background task enqueue
  - Files: `src/postura/webhook/receiver.py`

- [x] **P3.1b** Event router
  - push + pull_request (opened/synchronize/reopened) events parsed
  - Security relevance heuristic based on file patterns
  - Files: `src/postura/webhook/event_router.py`
  - Tests: 6 unit tests passing

### P3.2 — Change Scope Analysis
- [x] **P3.2a** Git diff parsing
  - gitpython-based: compare commit to parent, categorize code/dep/config files
  - Files: `src/postura/webhook/scope_analyzer.py`
  - Tests: 2 unit tests passing

- [x] **P3.2b** Affected module expansion
  - Regex import graph: finds 1-hop importers of changed Python files
  - Files: `src/postura/webhook/scope_analyzer.py` — _find_transitive_dependents()

### P3.3 — Git Repo Management
- [x] **P3.3a** Repo checkout manager
  - Clone cache under /tmp/postura_repos/, fetch+checkout on subsequent calls
  - Files: `src/postura/webhook/repo_manager.py` — RepoManager, get_repo_at_commit()

### P3.4 — Incremental Graph Update
- [x] **P3.4a** Subgraph identification
  - Query nodes by file + 1-hop neighborhood via Cypher
  - Files: `src/postura/graph/updater.py` — _snapshot_affected_subgraph()

- [x] **P3.4b** Soft delete + rebuild
  - _mark_stale() → re-ingest changed files → _remove_stale_nodes()
  - Path normalization added: absolute paths from webhooks are normalized to repo-relative before graph matching
  - Files: `src/postura/graph/updater.py` — update_graph_for_files()

- [x] **P3.4c** Graph diff computation
  - Pre/post UID set diff, re-runs chain discovery + severity scoring
  - Files: `src/postura/graph/differ.py` — compute_graph_diff()

### P3.5 — Async Task Pipeline
- [x] **P3.5a** Celery task definition
  - analyze_commit(): full pipeline with retry logic
  - Files: `src/postura/tasks/analysis.py`, `src/postura/tasks/__init__.py` (Celery app factory)

- [x] **P3.5b** Wire webhook to Celery
  - receiver.py enqueues analyze_commit.delay() in background task
  - Files: `src/postura/webhook/receiver.py`, `src/postura/api/app.py` (FastAPI app created)
  - Also created: `src/postura/api/routes.py` (core REST endpoints), `src/postura/api/app.py`

### P3.6 — Phase 3 Milestone
- [ ] **P3.6a** Incremental update end-to-end test
  - Requires Docker (Neo4j + Redis + running Celery worker)
  - Files: `tests/test_graph/test_e2e_phase3.py` — TO BE WRITTEN
  - NOTE: All Phase 3 components import cleanly; 36/36 unit tests passing

---

## Phase 4: Reasoning Layer (Week 7–9)

> **Goal:** LLM agent produces contextual PR security review with chain analysis.

### P4.1 — Knowledge Base
- [x] **P4.1a** CWE data ingestion
  - Downloads MITRE CWE XML, parses into structured docs (ID, name, description, consequences, mitigations, related CWEs), embeds with BGE-M3 into ChromaDB
  - Idempotent (skip if already loaded), cached XML under knowledge_store_path/cache/
  - Files: `src/postura/knowledge/cwe_loader.py`, `src/postura/knowledge/embedder.py`

- [x] **P4.1b** CVE data ingestion
  - NVD API 2.0 wrapper; fetches CVEs for 20 Python ecosystem packages; stores in ChromaDB "cve" collection
  - Includes CVSS scores, severity, affected versions
  - Files: `src/postura/knowledge/cve_loader.py`

- [x] **P4.1c** OWASP data ingestion
  - OWASP Top 10 2021 (A01–A10) hardcoded with full descriptions, CWE mappings, mitigations
  - Files: `src/postura/knowledge/owasp_loader.py`

### P4.2 — Hybrid Retrieval
- [x] **P4.2a** Embedding pipeline
  - `embed_texts()`, `get_or_create_collection()`, `upsert_documents()`, `query_collection()` — batched, normalized cosine similarity
  - Files: `src/postura/knowledge/embedder.py`

- [x] **P4.2b** Hybrid retriever
  - Dense (ChromaDB cosine) + sparse (BM25Okapi) + Reciprocal Rank Fusion
  - `retrieve(query, k, sources)`, `retrieve_by_cwe(cwe_id)`, `invalidate_bm25_cache()`
  - Files: `src/postura/knowledge/retriever.py`

### P4.3 — Agent Tools (Implementation)
- [x] **P4.3a–f** All 6 tools implemented in `src/postura/reasoning/tools.py`:
  - `graph_query` — read-only Cypher with write-keyword safety guard
  - `knowledge_retrieve` — hybrid retrieval, CWE ID shortcut
  - `trace_dataflow` — variable-length path from endpoint/function to DataStore
  - `find_chains` — CHAINS_TO edge traversal for a specific finding or all
  - `assess_exploitability` — trust zone, public reachability, PII exposure, chain membership
  - `generate_remediation` — LLM-powered fix via Claude API + knowledge context

### P4.4 — Agent Orchestrator
- [x] **P4.4a+b** LangGraph ReAct agent + PR assessment reasoning chain
  - `StateGraph` with agent ↔ tools loop; ChatAnthropic + `bind_tools()`
  - `run_pr_review(commit_sha, diff_summary, pr_number, new_finding_uids)` → `PRSecurityReview`
  - Structured output parsing: RISK_LEVEL, TOP_ISSUES, REQUIRES_BLOCK extracted via regex
  - Files: `src/postura/reasoning/agent.py`
  - Wired into `tasks/analysis.py` — runs automatically when new findings or chains appear

### P4.5 — Contextual Severity (LLM-Enhanced)
- [ ] **P4.5a** LLM-enhanced severity scoring
  - Rule-based scorer (P2.7a) is complete; LLM enhancement deferred
  - The `generate_remediation` tool already uses LLM for per-finding assessment
  - Full LLM severity override pass can be added if accuracy of rule-based scores proves insufficient

### P4.6 — Phase 4 Milestone
- [ ] **P4.6a** End-to-end reasoning test
  - Files: `tests/test_reasoning/test_e2e_phase4.py` — TO BE WRITTEN
  - Requires: Neo4j + live Anthropic API key (integration test)
  - NOTE: 14 unit tests covering knowledge base and tool safety pass without Neo4j/LLM
  - **MILESTONE READY:** `POST /api/v1/knowledge/reload?sources=owasp` seeds knowledge base; `POST /api/v1/findings/{uid}/remediate` triggers agent

---

## Phase 5: Query Interface + Polish (Week 10–12)

> **Goal:** REST API, NL queries, GitHub integration, evaluation, demo.

### P5.1 — REST API
- [ ] **P5.1a** Core posture endpoints
  - `GET /posture` → current posture score + summary
  - `GET /posture/history` → score over time (list of score snapshots)
  - `GET /findings` → all findings with filters (severity, status, type)
  - `GET /findings/{uid}` → finding detail with graph context (trust zone, chains, reachability)
  - Files: `src/postura/api/routes.py`
  - Done when: all endpoints return correct data from Neo4j

- [ ] **P5.1b** Chain and endpoint endpoints
  - `GET /findings/{uid}/chains` → all chains involving this finding
  - `GET /endpoints` → all endpoints with exposure level, auth status
  - `GET /diff/{commit_sha}` → graph diff for a specific commit
  - Files: `src/postura/api/routes.py` (extend)
  - Done when: chain endpoint returns correct multi-hop chains with evidence

- [ ] **P5.1c** FastAPI app wiring
  - Mount all routes, configure CORS, add OpenAPI metadata
  - Health check endpoint (`GET /health`)
  - Error handling middleware
  - Files: `src/postura/api/app.py`
  - Done when: `uvicorn postura.api.app:app` starts, Swagger UI accessible at `/docs`

### P5.2 — Natural Language Query
- [x] **P5.2a** NL query engine
  - `POST /api/v1/query` with `{"question": "What's our SSRF exposure?"}`
  - Two-step LLM pipeline: (1) Cypher generation with full schema + few-shot examples, (2) answer synthesis from results
  - Write-keyword safety guard (rejects MERGE/DELETE/SET/CREATE)
  - Graceful fallback at every step (Cypher gen fail, execution error, LLM unavailable)
  - Files: `src/postura/api/nl_query.py`

### P5.3 — GitHub Integration
- [x] **P5.3a** PR comment posting
  - `post_pr_comment(repo, pr_number, review)` — GitHub-flavored markdown with risk badge, issues, truncated analysis
  - Files: `src/postura/delivery/github.py`

- [x] **P5.3b** GitHub check status + check run
  - `set_commit_status()` — simple Statuses API (works with PAT); failure/pending/success based on risk level
  - `create_check_run()` — full Check Run API (requires `checks:write` scope)
  - Files: `src/postura/delivery/github.py`
  - Wired into `tasks/analysis.py` Step 7 (non-fatal, skips if no token)

### P5.4 — Posture Tracking
- [x] **P5.4a** Posture snapshots
  - `:PostureSnapshot` nodes in Neo4j; stored after every analysis run
  - `record_snapshot()`, `get_posture_history()`, `get_posture_trend()`, `get_top_risk_findings()`
  - Files: `src/postura/delivery/history.py`
  - REST endpoints: `GET /api/v1/history`, `GET /api/v1/trend`, `GET /api/v1/dashboard`
  - Wired into `tasks/analysis.py` Step 8 (non-fatal)

### P5.5 — Evaluation (Research Track)
- [x] **P5.5a** Static tools baseline
  - Bandit runner + GT matcher + metrics (4/6 detected, 0/3 chains, 3/4 severity underrated)
  - Files: `evaluation/baseline_static.py`, `evaluation/ground_truth.py`
  - 32 unit tests in `tests/test_evaluation/test_baseline.py`

- [x] **P5.5b** POSTURA evaluation run
  - Graph queries vs GT; comparison table generator; static-only mode for offline use
  - Files: `evaluation/postura_eval.py`, `evaluation/report.py`

- [x] **P5.5c** Incremental vs full scan latency
  - Full fixture: 0.008s parse; self (228 nodes): 0.317s
  - Incremental: 1 file=0.002s, 3 files=0.003s, 6 files=0.005s
  - Files: `evaluation/latency_eval.py`

- [x] **P5.5d** Contextual severity evaluation
  - POSTURA: 100% accuracy, κ=+1.000; Bandit: 0% accuracy, κ=0.000
  - Upgrade recall=100%, precision=100%
  - Files: `evaluation/severity_eval.py`

### P5.6 — Dogfooding & Polish
- [x] **P5.6a** Self-analysis
  - `evaluation/self_analysis.py` — parse POSTURA's own source (228 nodes, 1311 edges, 8 data access events)
  - `--dry-run` mode works offline; `--full` mode needs Neo4j

- [x] **P5.6b** README and documentation
  - Architecture diagram, quickstart, full API table, benchmark table
  - Files: `README.md`

- [ ] **P5.6c** Demo video
  - Requires Docker + Anthropic API key to record live demo
  - Script: push commit → webhook → graph update → PR comment appears → NL query

- [x] **P5.6d** License and open-source prep
  - MIT license in `LICENSE`
  - `CONTRIBUTING.md` with dev setup, test commands, key invariants

---

## Summary: Task Counts by Phase

| Phase | Weeks | Tasks | Core Deliverable |
|-------|-------|-------|------------------|
| Phase 1 | 1–2 | 18 tasks | Call graph + findings in Neo4j |
| Phase 2 | 3–4 | 13 tasks | Full threat graph with CHAINS_TO |
| Phase 3 | 5–6 | 10 tasks | Incremental updates + diff |
| Phase 4 | 7–9 | 12 tasks | LLM agent PR security review |
| Phase 5 | 10–12 | 14 tasks | API, NL queries, eval, demo |
| **Total** | **12** | **67 tasks** | |

---

## How to Use This List

1. **Start each session:** Open this file, find the next unchecked task.
2. **Read the context:** Open `IMPLEMENTATION_CONTEXT.md`, find the relevant section.
3. **Build:** Implement the task, write tests.
4. **Check off:** Mark the task `[x]` when done.
5. **Update context:** If you made a decision or learned something, add it to the Decisions Log in `IMPLEMENTATION_CONTEXT.md`.
6. **Milestone check:** At the end of each phase, run the milestone test. If it passes, move to the next phase.
