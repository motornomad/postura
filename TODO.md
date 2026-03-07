# POSTURA — Build Task List

> Granular task list for the 12-week build.
> Each task is scoped to a single coding session (1–3 hours).
> Reference `IMPLEMENTATION_CONTEXT.md` for detailed specs on any task.
> Reference `POSTURA_ARCHITECTURE.md` for the high-level vision.

---

## Phase 1: Foundation (Week 1–2)

> **Goal:** Parse a Python repo, build a basic graph in Neo4j, visualize it.

### P1.1 — Project Scaffolding
- [ ] **P1.1a** Create `pyproject.toml` with core dependencies
  - Dependencies: fastapi, uvicorn, neo4j, pydantic, pydantic-settings, celery, redis, tree-sitter, tree-sitter-python, httpx, pytest, testcontainers
  - Dev dependencies: ruff, mypy, pytest-asyncio
  - Files: `pyproject.toml`
  - Done when: `pip install -e .` succeeds

- [ ] **P1.1b** Create project directory structure (empty `__init__.py` files)
  - All directories from repo structure in architecture doc
  - Files: `src/postura/**/__init__.py`
  - Done when: `from postura import config` doesn't error

- [ ] **P1.1c** Create `config.py` with pydantic-settings
  - See §1.3 in Implementation Context for exact schema
  - Create `.env.example` with all variables documented
  - Files: `src/postura/config.py`, `.env.example`
  - Done when: `Settings()` loads from env vars or `.env`

- [ ] **P1.1d** Create Docker Compose file
  - Services: neo4j (5-community), redis (7-alpine)
  - See §1.2 in Implementation Context for exact spec
  - Files: `docker-compose.yml`
  - Done when: `docker compose up -d` starts both services, Neo4j Browser accessible at localhost:7474

### P1.2 — Neo4j Connection & Schema
- [ ] **P1.2a** Neo4j driver wrapper
  - Connection class with context manager, connection pooling
  - Health check method (run a trivial query)
  - Files: `src/postura/graph/connection.py`
  - Done when: can connect to Neo4j from Python, run `RETURN 1`, get result

- [ ] **P1.2b** Schema initialization
  - Function to create all constraints and indexes (see §2.3 in Implementation Context)
  - Idempotent — safe to run multiple times (`IF NOT EXISTS`)
  - Files: `src/postura/graph/schema.py`
  - Done when: constraints and indexes visible in Neo4j Browser

### P1.3 — Pydantic Data Models
- [ ] **P1.3a** Ingest models
  - `ASTNode`, `CallEdge`, `SASTFinding`, `DepVulnerability`, `EndpointInfo`, `ConfigIssue`, `StructuredIngestResult`
  - See §3.1 in Implementation Context
  - Files: `src/postura/models/ingest.py`
  - Done when: all models instantiate and serialize to JSON

- [ ] **P1.3b** Graph models
  - Node/edge creation helpers: functions that take Pydantic models and produce Cypher parameter dicts
  - UID generation functions for each node type
  - Files: `src/postura/models/graph.py`
  - Done when: `create_function_uid("module", "func")` returns `"fn:module:func"`

### P1.4 — Tree-sitter Parser
- [ ] **P1.4a** Basic Python file parsing
  - Parse a `.py` file into a tree-sitter syntax tree
  - Extract function definitions: name, line, end_line, parameters, decorators
  - Extract class definitions: name, methods
  - Files: `src/postura/ingest/ast_parser.py`
  - Done when: parsing a sample Python file returns correct list of `ASTNode` objects

- [ ] **P1.4b** Import extraction
  - Parse `import X` and `from X import Y` statements
  - Build module → imported names map per file
  - Files: `src/postura/ingest/ast_parser.py` (extend)
  - Done when: import map for a multi-file project is correct

- [ ] **P1.4c** Call graph extraction
  - Walk function bodies, find `call` expression nodes
  - Resolve callee to qualified name using import map + local scope
  - Output: list of `CallEdge` objects
  - Depends on: P1.4a, P1.4b
  - Files: `src/postura/ingest/ast_parser.py` (extend)
  - Done when: call graph for a sample Python file has correct caller→callee pairs

### P1.5 — SAST Tool Integration
- [ ] **P1.5a** Semgrep runner
  - Subprocess wrapper: invoke semgrep with JSON output on a target directory
  - Parse JSON into list of `SASTFinding` objects
  - Handle: semgrep not installed (skip gracefully), empty results, error results
  - Files: `src/postura/ingest/sast_runner.py`
  - Done when: running on vulnerable Flask fixture returns findings

- [ ] **P1.5b** Bandit runner
  - Subprocess wrapper: invoke bandit with JSON output
  - Parse JSON into list of `SASTFinding` objects
  - Deduplication with Semgrep findings (same file + overlapping lines + same CWE)
  - Files: `src/postura/ingest/sast_runner.py` (extend)
  - Done when: running on vulnerable Flask fixture returns findings, deduped with Semgrep

### P1.6 — Graph Population
- [ ] **P1.6a** Graph builder: Function nodes + CALLS edges
  - Take `ASTNode` list → create `:Function` nodes in Neo4j via Cypher MERGE
  - Take `CallEdge` list → create `:CALLS` edges
  - Batch operations for performance
  - Depends on: P1.2a, P1.2b, P1.3b, P1.4c
  - Files: `src/postura/graph/builder.py`
  - Done when: Neo4j Browser shows function nodes connected by CALLS edges

- [ ] **P1.6b** Graph builder: Finding nodes + AFFECTS edges
  - Take `SASTFinding` list → create `:Finding` nodes
  - Map findings to functions by file + line range overlap → create `:AFFECTS` edges
  - Depends on: P1.5a, P1.6a
  - Files: `src/postura/graph/builder.py` (extend)
  - Done when: findings visible in Neo4j connected to the functions they affect

- [ ] **P1.6c** Graph builder: Endpoint nodes + HANDLED_BY edges
  - Take `EndpointInfo` list → create `:Endpoint` nodes
  - Create `:HANDLED_BY` edges to handler functions
  - Depends on: P1.6a
  - Files: `src/postura/graph/builder.py` (extend)
  - Done when: endpoints visible in Neo4j connected to their handler functions

### P1.7 — Endpoint Extraction
- [ ] **P1.7a** Flask endpoint extractor
  - Detect `@app.route`, `@blueprint.route`, `@app.get/post/put/delete` decorators
  - Extract: path, method(s), handler function, auth decorators
  - Files: `src/postura/ingest/endpoint_extractor.py`
  - Done when: correctly extracts all routes from vulnerable Flask fixture

- [ ] **P1.7b** FastAPI endpoint extractor
  - Detect `@app.get`, `@router.post`, etc. decorators
  - Detect `Depends()` for auth
  - Files: `src/postura/ingest/endpoint_extractor.py` (extend)
  - Done when: correctly extracts all routes from a sample FastAPI app

### P1.8 — Test Fixture & Phase 1 Milestone
- [ ] **P1.8a** Create vulnerable Flask app test fixture
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

---

## Phase 2: Threat Graph (Week 3–4)

> **Goal:** Full graph schema with all node/edge types. Compositional risk (CHAINS_TO).

### P2.1 — DataStore & Data Access Edges
- [ ] **P2.1a** DataStore detection
  - Detect database calls: SQLAlchemy session/query, raw SQL (sqlite3, psycopg2), Redis client calls
  - Detect file system operations: open(), Path operations
  - Create `:DataStore` nodes with type, name, contains_pii heuristic
  - PII heuristic: table/variable names containing `user`, `email`, `password`, `payment`, `profile`, `ssn`, `address`
  - Files: `src/postura/ingest/ast_parser.py` (extend), `src/postura/graph/builder.py` (extend)
  - Done when: DataStore nodes appear in graph for the Flask fixture

- [ ] **P2.1b** READS_FROM / WRITES_TO edges
  - From function call analysis: `cursor.execute("SELECT...")` → READS_FROM
  - Heuristic: SELECT/GET = read, INSERT/UPDATE/DELETE/SET = write
  - Files: `src/postura/graph/builder.py` (extend)
  - Done when: functions connected to data stores with correct read/write direction

### P2.2 — Trust Zones & Service Boundaries
- [ ] **P2.2a** TrustZone inference
  - Directory-based heuristic: map directory patterns to trust levels
    - `public/`, `api/`, no auth decorator → level 0 (public)
    - `auth/`, functions behind `@login_required` → level 1 (authenticated)
    - `admin/`, `@admin_only` → level 2 (privileged)
    - `internal/`, `system/` → level 3 (system)
  - Create `:TrustZone` nodes + `:IN_ZONE` edges from endpoints
  - Files: `src/postura/graph/builder.py` (extend)
  - Done when: endpoints in Flask fixture have correct trust zone assignments

- [ ] **P2.2b** Service boundary detection
  - For monolith: single `:Service` node, all endpoints `:BELONGS_TO` it
  - For multi-service: infer from top-level directories or explicit config
  - Start simple (monolith), extend later
  - Files: `src/postura/graph/builder.py` (extend)
  - Done when: Service node exists, endpoints connected to it

### P2.3 — Dependency Scanning
- [ ] **P2.3a** pip-audit integration
  - Subprocess wrapper: run pip-audit against requirements.txt
  - Parse JSON → `DepVulnerability` models
  - Files: `src/postura/ingest/dep_scanner.py`
  - Done when: running on Flask fixture's requirements.txt finds the known vulnerable dependency

- [ ] **P2.3b** Dependency nodes + edges
  - Parse requirements.txt/pyproject.toml → create `:Dependency` nodes
  - Map imports in code to dependency packages → create `:USES` edges (Function → Dependency)
  - Link `DepVulnerability` findings → create `:Finding` nodes with `:AFFECTS` → Dependency
  - Files: `src/postura/graph/builder.py` (extend)
  - Done when: dependency subgraph visible in Neo4j, CVE findings attached

### P2.4 — Config Analysis
- [ ] **P2.4a** Config analyzer
  - Scan for hardcoded secrets: regex patterns for API keys, passwords, tokens in Python string literals
  - Detect CORS misconfigurations: `CORS(app, origins="*")` or `Access-Control-Allow-Origin: *`
  - Detect debug mode: `DEBUG=True`, `app.run(debug=True)`
  - Detect exposed database URIs with credentials
  - Output: list of `ConfigIssue` → converted to `:Finding` nodes
  - Files: `src/postura/ingest/config_analyzer.py`
  - Done when: detects hardcoded secret in Flask fixture config.py

### P2.5 — Auth Detection
- [ ] **P2.5a** Endpoint auth classification
  - For each endpoint, determine auth status from decorators + function signatures
  - Decorator patterns: `@login_required`, `@auth_required`, `@admin_only`, `@requires_auth`, `Depends(get_current_user)`
  - No auth detected → `is_public: true, auth_required: false`
  - Update `:Endpoint` node properties
  - Files: `src/postura/ingest/endpoint_extractor.py` (extend)
  - Done when: the missing-auth endpoint in Flask fixture is correctly flagged as public

### P2.6 — Call-Graph Reachability & Chain Detection
- [ ] **P2.6a** Reachability analysis
  - Cypher query: from an endpoint handler, traverse CALLS edges up to N hops
  - For each finding, determine: is it reachable from any public endpoint?
  - Store result as property on Finding node: `reachable_from_public: true/false`
  - Files: `src/postura/graph/queries.py`
  - Done when: SQL injection finding in Flask fixture is marked as reachable from the public endpoint

- [ ] **P2.6b** CHAINS_TO edge computation (rule-based)
  - Rule 1: Public endpoint → HANDLED_BY → Function → CALLS*1..5 → Function with SQLi finding → READS_FROM/WRITES_TO → DataStore with PII = **chain**
  - Rule 2: Public endpoint with no auth → HANDLED_BY → Function → CALLS* → Function accessing sensitive data = **chain**
  - Rule 3: Dependency with known CVE → USES → Function → CALLS* → Function HANDLED_BY endpoint = **chain** (supply chain risk)
  - Create `:CHAINS_TO` edges between the constituent findings with evidence string
  - Files: `src/postura/reasoning/chain_discovery.py`
  - Done when: the PII exposure chain in Flask fixture is detected and stored as CHAINS_TO edges

### P2.7 — Posture Scoring
- [ ] **P2.7a** Contextual severity scoring (rule-based)
  - Input: Finding + its graph context (trust zone, reachability, PII exposure)
  - Rules:
    - Reachable from public + no auth + touches PII → raise severity by 2 levels (max CRITICAL)
    - Reachable from public + no auth → raise by 1 level
    - Behind strong auth + internal only → lower by 1 level
    - Part of a chain → raise by 1 level
  - Update `contextual_severity` property on Finding nodes
  - Files: `src/postura/reasoning/severity_scorer.py`
  - Done when: Flask fixture findings have contextual severity different from raw severity where appropriate

- [ ] **P2.7b** Aggregate posture score
  - Score = weighted sum of all open findings by contextual severity
  - Weights: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0
  - Normalize to 0–100 scale (100 = no findings)
  - Store as a graph property or dedicated node
  - Files: `src/postura/reasoning/severity_scorer.py` (extend)
  - Done when: posture score computed for Flask fixture, value is reasonable

### P2.8 — Phase 2 Milestone
- [ ] **P2.8a** Full graph population test
  - Run full pipeline on Flask fixture
  - Assert: all node types present (Service, Endpoint, Function, DataStore, Dependency, Finding, TrustZone)
  - Assert: all edge types present (CALLS, HANDLED_BY, BELONGS_TO, IN_ZONE, READS_FROM, WRITES_TO, USES, AFFECTS, CHAINS_TO)
  - Assert: the PII exposure chain is detected
  - Assert: contextual severity differs from raw severity for the chain-participating findings
  - Files: `tests/test_graph/test_e2e_phase2.py`
  - **MILESTONE:** Full threat graph with compositional risk for a sample repo

- [ ] **P2.8b** Document ground truth for evaluation
  - For the Flask fixture, write down: every real vulnerability, every chain, expert-labeled contextual severity
  - This is evaluation gold standard — needed for the research paper
  - Files: `tests/fixtures/vulnerable_flask_app/GROUND_TRUTH.md`
  - Done when: documented with finding IDs, chain descriptions, expected severity labels

---

## Phase 3: Incremental Updates (Week 5–6)

> **Goal:** Push a commit, graph updates incrementally, diff is computed.

### P3.1 — Webhook Infrastructure
- [ ] **P3.1a** GitHub webhook receiver
  - FastAPI endpoint: `POST /webhook/github`
  - Verify HMAC signature using `github_webhook_secret`
  - Accept `push` and `pull_request` events
  - Return 200 immediately, enqueue processing
  - Files: `src/postura/webhook/receiver.py`
  - Done when: can receive a test webhook from GitHub (use smee.io or ngrok for local dev)

- [ ] **P3.1b** Event router
  - Parse webhook payload → classify event type
  - Extract: commit SHA, changed files list, branch, PR number (if PR event)
  - Flag: is this a security-relevant change? (heuristic: changed files in security-sensitive paths, dependency file changes, config file changes)
  - Files: `src/postura/webhook/event_router.py`
  - Done when: correctly classifies push vs PR events, extracts metadata

### P3.2 — Change Scope Analysis
- [ ] **P3.2a** Git diff parsing
  - Given a repo path + commit SHA, compute changed files
  - Use `git diff --name-only HEAD~1 HEAD` or compare two SHAs
  - Categorize changes: code files, dependency files (requirements.txt, pyproject.toml), config files (.env, settings)
  - Files: `src/postura/webhook/scope_analyzer.py`
  - Done when: given a commit with 3 changed files, correctly identifies them and their categories

- [ ] **P3.2b** Affected module expansion
  - Given changed files, compute transitive dependents
  - Build a file-level import graph (which files import from which)
  - If `auth/middleware.py` changed, and `api/routes.py` imports from it, then `api/routes.py` is also affected
  - Expand scope to 1 hop of importers (not infinite — that's the whole repo)
  - Files: `src/postura/webhook/scope_analyzer.py` (extend)
  - Done when: changing a utility file correctly pulls in its importers as affected

### P3.3 — Git Repo Management
- [ ] **P3.3a** Repo checkout manager
  - Clone target repo to a temp directory (if not already cloned)
  - Checkout specific commit SHA for analysis
  - Provide the repo path to the ingest layer
  - Cleanup: keep the clone (for incremental), delete on explicit cleanup
  - Files: `src/postura/webhook/repo_manager.py`
  - Done when: can clone a repo, checkout a commit, return the path

### P3.4 — Incremental Graph Update
- [ ] **P3.4a** Subgraph identification
  - Given changed files, query Neo4j for all nodes where `file IN $changed_files`
  - Expand to 1-hop neighborhood (nodes directly connected to changed nodes)
  - Return the affected subgraph (nodes + edges)
  - Files: `src/postura/graph/updater.py`
  - Done when: changing 1 file returns the correct subgraph (its functions, their callers/callees, their findings)

- [ ] **P3.4b** Soft delete + rebuild
  - Mark affected nodes as `status: "stale"` (don't delete — needed for diff)
  - Re-run ingest pipeline on changed files only
  - Create new nodes/edges from fresh ingest result
  - Remove stale nodes that weren't rebuilt (they were deleted in the code)
  - Files: `src/postura/graph/updater.py` (extend)
  - Done when: modifying a file and re-running updates the graph correctly without full re-scan

- [ ] **P3.4c** Graph diff computation
  - Compare pre-update snapshot vs post-update state
  - Compute: new nodes, removed nodes, changed properties, new edges, removed edges
  - Special attention: new `:CHAINS_TO` edges (new risk) and removed `:CHAINS_TO` edges (resolved risk)
  - Re-run chain discovery on affected subgraph
  - Re-run contextual severity scoring on affected findings
  - Output: `GraphDiff` model (see §3.2 in Implementation Context)
  - Files: `src/postura/graph/differ.py`
  - Done when: adding a vulnerable endpoint to Flask fixture produces a diff showing the new finding and new chain

### P3.5 — Async Task Pipeline
- [ ] **P3.5a** Celery task definition
  - Task: `analyze_commit(repo_url, commit_sha, changed_files)`
  - Pipeline: scope analysis → ingest (changed files only) → graph update → diff → (later: reasoning)
  - Error handling: retry on transient failures, dead-letter on permanent failures
  - Files: `src/postura/tasks/analysis.py`
  - Done when: can enqueue a task via Redis, it runs the pipeline, graph is updated

- [ ] **P3.5b** Wire webhook to Celery
  - Webhook receiver enqueues `analyze_commit` task
  - Task processes asynchronously
  - Basic status tracking: task ID returned in webhook response
  - Files: `src/postura/webhook/receiver.py` (extend), `src/postura/tasks/analysis.py` (extend)
  - Done when: POST to webhook endpoint → Celery task runs → graph updated

### P3.6 — Phase 3 Milestone
- [ ] **P3.6a** Incremental update end-to-end test
  - Start with populated graph from Flask fixture
  - Simulate a commit that adds a new vulnerable endpoint
  - Trigger incremental update
  - Assert: graph diff shows new endpoint, new finding, new chain
  - Assert: existing unaffected nodes are untouched
  - Assert: posture score changed
  - Measure: time for incremental update vs full rebuild
  - Files: `tests/test_graph/test_e2e_phase3.py`
  - **MILESTONE:** Commit → graph updates incrementally → diff computed with correct new/removed/changed nodes

---

## Phase 4: Reasoning Layer (Week 7–9)

> **Goal:** LLM agent produces contextual PR security review with chain analysis.

### P4.1 — Knowledge Base
- [ ] **P4.1a** CWE data ingestion
  - Download MITRE CWE XML dataset
  - Parse into structured documents: ID, name, description, consequences, mitigations, related CWEs
  - Chunk (one doc per CWE, split long descriptions)
  - Embed with BGE-M3 and store in ChromaDB
  - Files: `src/postura/knowledge/cwe_loader.py`, `src/postura/knowledge/embedder.py`
  - Done when: ~900 CWE entries searchable in ChromaDB

- [ ] **P4.1b** CVE data ingestion
  - Use NVD API or download recent CVE JSON feeds
  - Parse: CVE-ID, description, CVSS, affected packages
  - Focus on CVEs relevant to Python ecosystem (filter by package names in pip)
  - Embed and store in ChromaDB
  - Files: `src/postura/knowledge/cve_loader.py`
  - Done when: CVE data for common Python packages searchable

- [ ] **P4.1c** OWASP data ingestion
  - OWASP Top 10 (2021) descriptions and examples
  - OWASP ASVS verification requirements (optional, prioritize Top 10)
  - Embed and store in ChromaDB
  - Files: `src/postura/knowledge/owasp_loader.py`
  - Done when: searching "SQL injection" returns relevant OWASP Top 10 entry

### P4.2 — Hybrid Retrieval
- [ ] **P4.2a** Embedding pipeline
  - BGE-M3 model loading and inference
  - Batch embedding function for knowledge base ingestion
  - Single-query embedding function for retrieval
  - Files: `src/postura/knowledge/embedder.py` (extend)
  - Done when: can embed a query and get a vector

- [ ] **P4.2b** Hybrid retriever
  - Dense search via ChromaDB
  - BM25 search via `rank-bm25` library over the same documents
  - Reciprocal Rank Fusion to merge ranked lists
  - Metadata filtering (by source: cwe/cve/owasp)
  - Files: `src/postura/knowledge/retriever.py`
  - Done when: `retrieve("SQL injection in Flask", k=5)` returns relevant CWE-89, OWASP A03 entries

### P4.3 — Agent Tools (Implementation)
- [ ] **P4.3a** Tool: graph_query
  - Execute read-only Cypher against Neo4j
  - Safety: reject queries containing `CREATE`, `MERGE`, `DELETE`, `SET`, `REMOVE`
  - Format results as readable text for the LLM
  - Files: `src/postura/reasoning/tools.py`
  - Done when: agent can query "show me all public endpoints" and get results

- [ ] **P4.3b** Tool: knowledge_retrieve
  - Wraps the hybrid retriever
  - Takes finding description + optional source filter
  - Returns top-k formatted knowledge entries
  - Files: `src/postura/reasoning/tools.py` (extend)
  - Done when: agent can ask about CWE-89 and get relevant info

- [ ] **P4.3c** Tool: trace_dataflow
  - Cypher: variable-length path query from source to sink via CALLS edges
  - Returns all paths with intermediate nodes, formatted as readable chains
  - Files: `src/postura/reasoning/tools.py` (extend)
  - Done when: agent can trace from a public endpoint to a SQL injection finding

- [ ] **P4.3d** Tool: find_chains
  - Traverse `:CHAINS_TO` edges from a finding
  - Return all chains with evidence and severity
  - Files: `src/postura/reasoning/tools.py` (extend)
  - Done when: agent can find chains involving the SQL injection in Flask fixture

- [ ] **P4.3e** Tool: assess_exploitability
  - Query finding's graph neighborhood: trust zone, reachability, PII exposure, auth protection
  - Return structured context for LLM to reason over
  - Files: `src/postura/reasoning/tools.py` (extend)
  - Done when: returns correct context for the SQL injection finding

- [ ] **P4.3f** Tool: generate_remediation
  - Given finding context, generate fix suggestion
  - Uses LLM to produce code diff + explanation
  - References knowledge base for best practices
  - Files: `src/postura/reasoning/tools.py` (extend)
  - Done when: produces a reasonable fix suggestion for SQL injection

### P4.4 — Agent Orchestrator
- [ ] **P4.4a** LangGraph agent definition
  - Define agent graph: nodes for each reasoning step, edges for flow control
  - System prompt for PR assessment mode (see §7.3 in Implementation Context)
  - Tool binding: connect all 6 tools to the agent
  - Files: `src/postura/reasoning/orchestrator.py`, `src/postura/reasoning/prompts.py`
  - Done when: agent can receive a graph diff and make tool calls

- [ ] **P4.4b** PR assessment reasoning chain
  - Input: `GraphDiff` from incremental update
  - Agent flow: for each new finding → assess exploitability → trace from public endpoints → find chains → retrieve knowledge → generate remediation
  - Output: `PRSecurityReview` model (see §3.3 in Implementation Context)
  - Files: `src/postura/reasoning/orchestrator.py` (extend)
  - Done when: agent produces a structured PR review for a commit that introduces a vulnerability

### P4.5 — Contextual Severity (LLM-Enhanced)
- [ ] **P4.5a** LLM-enhanced severity scoring
  - Upgrade the rule-based scorer (P2.7a) with LLM reasoning
  - Agent calls assess_exploitability → LLM evaluates contextual risk → assigns severity
  - Combine rule-based and LLM assessments (LLM can override rules with justification)
  - Files: `src/postura/reasoning/severity_scorer.py` (extend)
  - Done when: LLM produces severity assessments with reasoning strings that reference graph context

### P4.6 — Phase 4 Milestone
- [ ] **P4.6a** End-to-end reasoning test
  - Simulate a commit adding a vulnerable endpoint to Flask fixture
  - Full pipeline: ingest → graph update → diff → reasoning agent
  - Assert: agent discovers the chain, assesses severity contextually, generates remediation
  - Assert: PR review output is structured and grounded in graph evidence
  - Files: `tests/test_reasoning/test_e2e_phase4.py`
  - **MILESTONE:** Agent produces contextual PR security review with chain analysis

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
- [ ] **P5.2a** NL query engine
  - `POST /query` with `{"question": "What's our SSRF exposure?"}`
  - Classify query intent (posture question, finding lookup, blast radius, what-if)
  - Generate Cypher from natural language using LLM
  - Execute Cypher against Neo4j
  - Synthesize answer with evidence using LLM
  - Files: `src/postura/api/nl_query.py`
  - Done when: "What's our most critical vulnerability chain?" returns a grounded answer

### P5.3 — GitHub Integration
- [ ] **P5.3a** PR comment posting
  - After reasoning layer produces `PRSecurityReview`, format as GitHub PR comment
  - Use GitHub API to post comment on the PR
  - Include: posture delta badge, critical chains, prioritized findings, fix suggestions
  - Markdown formatted for GitHub rendering
  - Files: `src/postura/api/github_integration.py`
  - Done when: PR comment appears on a test PR with correct content

- [ ] **P5.3b** GitHub check status
  - Report check pass/warn/fail based on posture delta
  - Pass: no new critical/high findings, no new chains
  - Warn: new medium findings, no new chains
  - Fail: new critical/high findings or new chains
  - Configurable thresholds
  - Files: `src/postura/api/github_integration.py` (extend)
  - Done when: check status appears on test PR

### P5.4 — Posture Tracking
- [ ] **P5.4a** Posture snapshots
  - After each analysis, store a posture snapshot: commit SHA, timestamp, score, finding counts by severity
  - Store in Neo4j as `:PostureSnapshot` nodes (or in a simple SQLite if preferred)
  - Enable trend queries: is posture improving or degrading over last N commits?
  - Files: `src/postura/reasoning/severity_scorer.py` (extend), `src/postura/graph/queries.py` (extend)
  - Done when: can query posture history and see trend

### P5.5 — Evaluation (Research Track)
- [ ] **P5.5a** Static tools baseline
  - Run Semgrep + Bandit standalone on all test fixtures
  - Record: findings detected, severity assigned, time taken
  - No chain detection (static tools don't do this)
  - Files: `evaluation/baseline_static.py`
  - Done when: baseline results documented

- [ ] **P5.5b** POSTURA evaluation run
  - Run POSTURA full pipeline on all test fixtures
  - Record: findings detected, chains detected, contextual severity, time taken
  - Compare against ground truth (from P2.8b)
  - Files: `evaluation/postura_eval.py`
  - Done when: comparison table generated

- [ ] **P5.5c** Incremental vs full scan latency
  - Measure: full scan time on Flask fixture
  - Measure: incremental update time for 1-file, 3-file, 10-file changes
  - Plot latency vs change size
  - Files: `evaluation/latency_eval.py`
  - Done when: latency numbers documented

- [ ] **P5.5d** Contextual severity evaluation
  - Compare POSTURA's contextual severity vs raw CVSS vs expert labels
  - Compute: accuracy, Cohen's kappa
  - Document where POSTURA agrees/disagrees with CVSS and why
  - Files: `evaluation/severity_eval.py`
  - Done when: severity comparison documented with examples

### P5.6 — Dogfooding & Polish
- [ ] **P5.6a** Self-analysis
  - Point POSTURA at its own repo
  - Run full analysis, review results
  - Fix any bugs discovered during self-analysis
  - Document self-analysis results in README as a demo
  - Done when: POSTURA successfully analyzes itself

- [ ] **P5.6b** README and documentation
  - Clean README with: project description, architecture diagram, quickstart (`docker compose up`), demo screenshots/GIF, API docs link
  - Keep it concise — the README is the recruiter-facing artifact
  - Files: `README.md`
  - Done when: someone can clone the repo, run `docker compose up`, and see it work

- [ ] **P5.6c** Demo video
  - 2-minute screencast: push a commit → POSTURA processes it → graph updates → PR comment appears
  - Show Neo4j Browser with the threat graph
  - Show a natural language query and its answer
  - Host on YouTube or as a GIF in the README
  - Done when: video recorded and linked in README

- [ ] **P5.6d** License and open-source prep
  - Choose license (Apache 2.0 or MIT recommended for OSS visibility)
  - Add CONTRIBUTING.md (brief)
  - Add GitHub issue templates
  - Clean git history if needed
  - Done when: repo is ready to make public

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
