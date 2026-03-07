# POSTURA — Attack Surface Posture Agent

> An agentic attack surface intelligence system that maintains a living security posture graph of your codebase, updates incrementally on every commit, and reasons about compositional risk that static tools miss.

---

## 1. What Is POSTURA

POSTURA is not a static analysis tool. Static tools (Semgrep, Bandit, Snyk) find individual vulnerabilities in isolation. POSTURA builds a **persistent, queryable graph** of your codebase's attack surface and reasons about **compositional risk** — how vulnerabilities chain together across service boundaries, data flows, and trust zones.

### The Core Insight

A SQL injection in an admin-only internal tool behind 3 layers of auth is a **low** risk.
The same SQL injection in a public-facing unauthenticated endpoint that touches PII is **critical**.

Static tools score both the same. POSTURA doesn't — because it knows the topology.

### What Makes It Agentic

1. **Stateful** — maintains a persistent threat graph (not re-scanned from scratch)
2. **Reactive** — updates incrementally on every PR/commit via webhooks
3. **Reasoning** — LLM layer reasons about exploitability given actual architecture context
4. **Queryable** — answer natural language questions about your security posture in real time
5. **Autonomous** — discovers threat chains that no individual tool or rule can express

---

## 2. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         POSTURA SYSTEM                              │
│                                                                     │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │  INGEST  │───▶│  GRAPH       │───▶│  REASONING   │              │
│  │  LAYER   │    │  ENGINE      │    │  LAYER       │              │
│  └──────────┘    └──────────────┘    └──────────────┘              │
│       ▲               ▲  │                │                        │
│       │               │  ▼                ▼                        │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │  WEBHOOK │    │  NEO4J       │    │  QUERY       │              │
│  │  TRIGGER │    │  THREAT      │    │  INTERFACE   │              │
│  │  LAYER   │    │  GRAPH       │    │  (NL + API)  │              │
│  └──────────┘    └──────────────┘    └──────────────┘              │
│                       ▲                                            │
│                       │                                            │
│                  ┌──────────────┐                                   │
│                  │  KNOWLEDGE   │                                   │
│                  │  BASE        │                                   │
│                  │  (CWE/CVE)   │                                   │
│                  └──────────────┘                                   │
└─────────────────────────────────────────────────────────────────────┘
```

The system has **6 core blocks**:

| Block | Responsibility | Key Tech |
|-------|---------------|----------|
| Webhook Trigger Layer | Listens for git events, determines scope of change | GitHub/GitLab webhooks, FastAPI |
| Ingest Layer | Parses code, extracts structure, runs tool scans | Tree-sitter, Semgrep, Bandit, pip-audit |
| Graph Engine | Builds/updates the threat graph incrementally | Neo4j, custom graph diff algorithm |
| Knowledge Base | CWE/CVE/OWASP reference data for enrichment | Vector store (ChromaDB/Qdrant), embeddings |
| Reasoning Layer | LLM-powered contextual risk assessment + chain discovery | Claude/GPT-4 via tool-calling, LangGraph |
| Query Interface | Natural language + API access to posture state | FastAPI, RAG over graph |

---

## 3. Block-by-Block Architecture

### 3.1 Webhook Trigger Layer

**Purpose:** Detect code changes and determine the minimal scope of re-analysis.

```
GitHub/GitLab Webhook
        │
        ▼
┌─────────────────────┐
│  Event Router        │
│  ─────────────────── │
│  • PR opened/updated │
│  • Push to branch    │
│  • Dependency update │
│  • Config change     │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Change Scope        │
│  Analyzer            │
│  ─────────────────── │
│  • Git diff parsing  │
│  • Affected files    │
│  • Affected modules  │
│  • Dependency delta  │
└─────────┬───────────┘
          │
          ▼
    Scoped Analysis
    Request (to Ingest)
```

**Key components:**
- **Event Router** — FastAPI endpoint receiving webhook payloads. Classifies event type (code change, dependency update, config change, new endpoint added).
- **Change Scope Analyzer** — Parses the git diff to determine the *minimal affected subgraph*. This is critical — a change to `auth/middleware.py` affects a different subgraph than a change to `utils/string_helpers.py`. Uses file-level dependency tracking to expand scope to transitive dependents.

**Output:** A `ScopedAnalysisRequest` object containing:
- Changed files and their AST diffs
- Affected module boundaries
- Dependency changes (added/removed/version-bumped packages)
- Flag: is this a security-relevant change? (heuristic pre-filter)

---

### 3.2 Ingest Layer

**Purpose:** Parse code into structured representations and run tool-based scans. This is the data extraction layer — it does NOT reason, it collects.

```
Scoped Analysis Request
        │
        ▼
┌───────────────────────────────────────────────────┐
│                  INGEST LAYER                      │
│                                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
│  │  AST Parser  │  │  SAST Tools │  │  Dep      │ │
│  │  (Tree-sitter)│  │  (Semgrep,  │  │  Scanner  │ │
│  │             │  │   Bandit)   │  │  (pip-audit│ │
│  │  Extracts:  │  │             │  │   npm audit│ │
│  │  • Functions │  │  Extracts:  │  │   trivy)  │ │
│  │  • Classes  │  │  • Raw      │  │           │ │
│  │  • Imports  │  │    findings │  │  Extracts:│ │
│  │  • Calls    │  │  • Rule IDs │  │  • Known  │ │
│  │  • Data flow│  │  • Locations│  │    CVEs   │ │
│  │  • Endpoints│  │             │  │  • License│ │
│  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘ │
│         │                │               │        │
│         └────────┬───────┴───────┬───────┘        │
│                  ▼               ▼                 │
│         ┌──────────────┐ ┌────────────────┐       │
│         │  Endpoint    │ │  Config        │       │
│         │  Extractor   │ │  Analyzer      │       │
│         │  ───────────  │ │  ────────────  │       │
│         │  • Routes    │ │  • .env files  │       │
│         │  • Auth      │ │  • CORS        │       │
│         │    decorators│ │  • DB configs  │       │
│         │  • Input     │ │  • Secrets     │       │
│         │    params    │ │    exposure    │       │
│         └──────┬───────┘ └───────┬────────┘       │
│                └────────┬────────┘                 │
│                         ▼                          │
│              Structured Ingest Output              │
│              (ready for graph engine)              │
└───────────────────────────────────────────────────┘
```

**Key components:**

- **AST Parser (Tree-sitter):** Language-agnostic parsing. Extracts function signatures, class hierarchies, import chains, call graphs, and critically — **data flow paths** (which variables flow from input to output through which functions). Tree-sitter is chosen because it supports incremental re-parsing — you don't re-parse the entire codebase on a 3-file diff.

- **SAST Tool Runner:** Invokes Semgrep and Bandit (Python) / ESLint-security (JS) as *subprocess tools*. These are not the product — they're **inputs** to the agent. Raw findings with rule IDs and locations.

- **Dependency Scanner:** Runs `pip-audit`, `npm audit`, or `trivy` against the dependency manifest. Maps pinned versions to known CVEs. Tracks transitive dependency depth.

- **Endpoint Extractor:** Framework-aware extraction of HTTP endpoints, their auth decorators (or lack thereof), input parameters, response types. Supports Flask, FastAPI, Django, Express initially.

- **Config Analyzer:** Scans for `.env` files, hardcoded secrets, CORS misconfigurations, debug flags in production configs, DB connection strings with credentials.

**Output:** A `StructuredIngestResult`:
```python
@dataclass
class StructuredIngestResult:
    ast_nodes: List[ASTNode]           # functions, classes with metadata
    call_graph: Dict[str, List[str]]   # function -> [functions it calls]
    data_flows: List[DataFlowPath]     # input -> ... -> output traces
    endpoints: List[Endpoint]          # HTTP routes with auth/params
    sast_findings: List[SASTFinding]   # raw tool findings
    dep_vulnerabilities: List[CVE]     # known CVEs in dependencies
    config_issues: List[ConfigIssue]   # misconfigurations
    change_scope: ChangeScope          # what changed in this commit
```

---

### 3.3 Graph Engine

**Purpose:** Build and maintain the persistent threat graph in Neo4j. This is the core data structure of the entire system.

#### 3.3.1 Graph Schema

```
NODE TYPES:
═══════════════════════════════════════════════════════

  ┌─────────────┐
  │  :Service    │  Top-level service/microservice boundary
  │  ───────────  │  Properties: name, type, exposure_level
  └─────────────┘

  ┌─────────────┐
  │  :Endpoint   │  HTTP route / API endpoint
  │  ───────────  │  Properties: path, method, auth_required,
  └─────────────┘  auth_type, input_params, is_public

  ┌─────────────┐
  │  :Function   │  Code function/method
  │  ───────────  │  Properties: name, file, line, module,
  └─────────────┘  is_entry_point, handles_user_input

  ┌─────────────┐
  │  :DataStore  │  Database, file system, cache, external API
  │  ───────────  │  Properties: type, contains_pii,
  └─────────────┘  encryption_at_rest, access_pattern

  ┌─────────────┐
  │  :Dependency │  Third-party package
  │  ───────────  │  Properties: name, version, pinned,
  └─────────────┘  known_cves, last_updated, depth

  ┌─────────────┐
  │  :Finding    │  A specific vulnerability or issue
  │  ───────────  │  Properties: type, cwe_id, raw_severity,
  └─────────────┘  contextual_severity, status, evidence

  ┌─────────────┐
  │  :TrustZone  │  Logical trust boundary
  │  ───────────  │  Properties: name, level (public/internal/
  └─────────────┘  admin/system), auth_mechanism


EDGE TYPES:
═══════════════════════════════════════════════════════

  (Function)  ─[:CALLS]──────────▶  (Function)
  (Function)  ─[:READS_FROM]─────▶  (DataStore)
  (Function)  ─[:WRITES_TO]──────▶  (DataStore)
  (Endpoint)  ─[:HANDLED_BY]─────▶  (Function)
  (Endpoint)  ─[:BELONGS_TO]─────▶  (Service)
  (Endpoint)  ─[:IN_ZONE]────────▶  (TrustZone)
  (Function)  ─[:USES]───────────▶  (Dependency)
  (Finding)   ─[:AFFECTS]────────▶  (Function | Endpoint | Dependency)
  (Finding)   ─[:CHAINS_TO]──────▶  (Finding)     ← THIS IS THE KEY EDGE
  (DataFlow)  ─[:PASSES_THROUGH]─▶  (Function)
  (TrustZone) ─[:TRUSTS]─────────▶  (TrustZone)
```

The **`:CHAINS_TO`** edge between findings is the core innovation. This is where compositional risk lives — the agent discovers that Finding A (missing input validation on a public endpoint) chains to Finding B (unsanitized SQL query in an internal function) because there exists a data flow path from A's endpoint through to B's function.

#### 3.3.2 Incremental Update Algorithm

```
On new commit/PR:
│
├─ 1. Receive ChangeScope from webhook layer
│     (which files changed, which modules affected)
│
├─ 2. Identify affected subgraph
│     MATCH (n) WHERE n.file IN $changed_files
│     WITH n, [(n)-[r]->(m) | {node: m, rel: r}] AS neighborhood
│     → Returns all nodes/edges within 2 hops of changed code
│
├─ 3. Soft-delete affected subgraph
│     (mark as STALE, don't hard delete — needed for diff)
│
├─ 4. Ingest new code for changed files
│     (AST parse, SAST scan, dep scan — only changed files)
│
├─ 5. Rebuild affected subgraph from new ingest
│     (create/update nodes and edges)
│
├─ 6. Compute graph diff
│     • New nodes/edges (attack surface expanded)
│     • Removed nodes/edges (attack surface contracted)
│     • Changed properties (severity shifts)
│     • New :CHAINS_TO edges (new compositional risks)
│     • Broken :CHAINS_TO edges (risks resolved)
│
├─ 7. Send graph diff to Reasoning Layer
│     (only the delta, not the full graph)
│
└─ 8. Update posture score
      (aggregate metric — did this commit make us safer or less safe?)
```

---

### 3.4 Knowledge Base

**Purpose:** Provide the reasoning layer with structured security knowledge for enrichment and contextual assessment.

```
┌───────────────────────────────────────────────┐
│              KNOWLEDGE BASE                    │
│                                                │
│  ┌──────────────────┐  ┌───────────────────┐  │
│  │  CWE Database     │  │  CVE Database     │  │
│  │  ────────────────  │  │  ───────────────  │  │
│  │  • Weakness types │  │  • Known vulns   │  │
│  │  • Attack patterns│  │  • CVSS scores   │  │
│  │  • Mitigations    │  │  • Exploitability│  │
│  │  • Relationships  │  │  • Affected      │  │
│  │    between CWEs   │  │    versions      │  │
│  └──────────────────┘  └───────────────────┘  │
│                                                │
│  ┌──────────────────┐  ┌───────────────────┐  │
│  │  OWASP Top 10    │  │  Framework-       │  │
│  │  + ASVS          │  │  Specific Rules   │  │
│  │  ────────────────  │  │  ───────────────  │  │
│  │  • Category       │  │  • Django gotchas│  │
│  │    mappings       │  │  • Flask pitfalls│  │
│  │  • Verification  │  │  • Express anti- │  │
│  │    requirements   │  │    patterns      │  │
│  └──────────────────┘  └───────────────────┘  │
│                                                │
│  Storage: ChromaDB / Qdrant                    │
│  Embedding: BGE-M3 or similar                  │
│  Retrieval: Hybrid (BM25 + dense)              │
└───────────────────────────────────────────────┘
```

**This is where your RAG expertise directly applies.** The knowledge base isn't a flat lookup — it's a retrieval system that, given a finding + its graph context, retrieves the most relevant:
- CWE descriptions and known attack patterns
- Historical CVE data for similar vulnerability classes
- Framework-specific remediation guidance
- OWASP verification requirements

Use hybrid retrieval (BM25 + dense embeddings) — same architecture you built at Imagine Learning, applied to security knowledge.

---

### 3.5 Reasoning Layer

**Purpose:** The "brain" — LLM-powered reasoning over the threat graph + knowledge base. This is where POSTURA becomes an agent, not a tool.

```
┌────────────────────────────────────────────────────────┐
│                   REASONING LAYER                       │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │              AGENT ORCHESTRATOR                    │  │
│  │              (LangGraph / custom)                  │  │
│  │                                                    │  │
│  │  Tools available to the agent:                     │  │
│  │  ┌────────────────┐  ┌─────────────────────┐      │  │
│  │  │ graph_query     │  │ knowledge_retrieve  │      │  │
│  │  │ ──────────────  │  │ ─────────────────── │      │  │
│  │  │ Run Cypher      │  │ RAG over CWE/CVE   │      │  │
│  │  │ queries against│  │ knowledge base      │      │  │
│  │  │ Neo4j          │  │                     │      │  │
│  │  └────────────────┘  └─────────────────────┘      │  │
│  │  ┌────────────────┐  ┌─────────────────────┐      │  │
│  │  │ trace_dataflow  │  │ assess_exploitability│     │  │
│  │  │ ──────────────  │  │ ─────────────────── │      │  │
│  │  │ Follow data    │  │ Given a finding +   │      │  │
│  │  │ flow paths in  │  │ context, assess     │      │  │
│  │  │ the graph      │  │ real-world risk     │      │  │
│  │  └────────────────┘  └─────────────────────┘      │  │
│  │  ┌────────────────┐  ┌─────────────────────┐      │  │
│  │  │ find_chains     │  │ generate_remediation│      │  │
│  │  │ ──────────────  │  │ ─────────────────── │      │  │
│  │  │ Discover multi-│  │ Produce fix with   │      │  │
│  │  │ hop vuln chains│  │ code diff          │      │  │
│  │  │ via graph      │  │                     │      │  │
│  │  │ traversal      │  │                     │      │  │
│  │  └────────────────┘  └─────────────────────┘      │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │              REASONING MODES                       │  │
│  │                                                    │  │
│  │  1. PR_ASSESSMENT                                  │  │
│  │     Triggered by: new commit/PR                    │  │
│  │     Input: graph diff from Graph Engine            │  │
│  │     Output: PR security review with contextual     │  │
│  │             risk scores + chain analysis            │  │
│  │                                                    │  │
│  │  2. FULL_POSTURE_REPORT                            │  │
│  │     Triggered by: manual / scheduled               │  │
│  │     Input: full threat graph                       │  │
│  │     Output: comprehensive posture report with      │  │
│  │             prioritized findings + trend analysis   │  │
│  │                                                    │  │
│  │  3. INTERACTIVE_QUERY                              │  │
│  │     Triggered by: user question                    │  │
│  │     Input: natural language question               │  │
│  │     Output: answer grounded in graph + evidence    │  │
│  │                                                    │  │
│  │  4. CHAIN_DISCOVERY                                │  │
│  │     Triggered by: graph update                     │  │
│  │     Input: newly added/modified findings           │  │
│  │     Output: new :CHAINS_TO edges with evidence     │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

**The 6 agent tools in detail:**

| Tool | Input | Output | Why It's Needed |
|------|-------|--------|-----------------|
| `graph_query` | Cypher query string | Neo4j result set | Agent needs to explore the graph freely — "show me all public endpoints that reach a data store with PII" |
| `knowledge_retrieve` | Finding description + context | Relevant CWE/CVE/OWASP entries | Enriches findings with known attack patterns and mitigations |
| `trace_dataflow` | Source node ID, sink node ID | All paths between them with intermediate nodes | Core of chain discovery — does user input reach this vulnerable function? |
| `assess_exploitability` | Finding + graph neighborhood | Contextual severity score + reasoning | The key differentiator — same finding gets different scores based on topology |
| `find_chains` | Finding node ID | List of compositional chains involving this finding | Discovers multi-hop vulnerability paths |
| `generate_remediation` | Finding + chain context | Code fix suggestion with diff | Actionable output, not just findings |

**Reasoning flow for PR assessment:**

```
1. Receive graph diff (new/changed/removed nodes and edges)
2. For each new or changed Finding:
   a. Call assess_exploitability with finding + its graph neighborhood
   b. Call trace_dataflow from all public endpoints to this finding
   c. If reachable from public surface → call find_chains
   d. For critical chains → call knowledge_retrieve for context
   e. For actionable findings → call generate_remediation
3. Aggregate into PR review:
   - Net posture change (safer / less safe / neutral)
   - Critical chains introduced
   - Prioritized findings with contextual severity
   - Suggested fixes
```

---

### 3.6 Query Interface

**Purpose:** Allow humans to interact with the posture state — both programmatically and via natural language.

```
┌───────────────────────────────────────────────────┐
│               QUERY INTERFACE                      │
│                                                    │
│  ┌─────────────────────────────────────────────┐  │
│  │  REST API (FastAPI)                          │  │
│  │  ─────────────────────────────────────────── │  │
│  │  GET  /posture                → current score│  │
│  │  GET  /posture/history        → score trend  │  │
│  │  GET  /findings               → all findings │  │
│  │  GET  /findings/{id}/chains   → chains for   │  │
│  │                                  a finding   │  │
│  │  GET  /endpoints              → all endpoints│  │
│  │                                  + exposure  │  │
│  │  GET  /diff/{commit_sha}      → what changed │  │
│  │  POST /query                  → NL question  │  │
│  └─────────────────────────────────────────────┘  │
│                                                    │
│  ┌─────────────────────────────────────────────┐  │
│  │  Natural Language Query Engine               │  │
│  │  ─────────────────────────────────────────── │  │
│  │  "What's our SSRF exposure right now?"       │  │
│  │       │                                      │  │
│  │       ▼                                      │  │
│  │  1. Classify query intent                    │  │
│  │  2. Generate Cypher query(s) from NL         │  │
│  │  3. Execute against threat graph             │  │
│  │  4. LLM synthesizes answer with evidence     │  │
│  │                                              │  │
│  │  "What happens if lodash gets compromised?"  │  │
│  │       │                                      │  │
│  │       ▼                                      │  │
│  │  1. Find :Dependency node for lodash         │  │
│  │  2. Trace all paths from lodash to endpoints │  │
│  │  3. Compute blast radius                     │  │
│  │  4. LLM explains impact in business terms    │  │
│  └─────────────────────────────────────────────┘  │
│                                                    │
│  ┌─────────────────────────────────────────────┐  │
│  │  GitHub Integration                          │  │
│  │  ─────────────────────────────────────────── │  │
│  │  • PR comments with posture delta            │  │
│  │  • Check status (pass/fail/warn)             │  │
│  │  • Weekly posture digest as GitHub Issue      │  │
│  └─────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────┘
```

---

## 4. Data Flow — End to End

```
Developer pushes code
        │
        ▼
GitHub Webhook fires ──────────────────────────┐
        │                                       │
        ▼                                       │
Webhook Layer: parse event, compute scope       │
        │                                       │
        ▼                                       │
Ingest Layer: AST parse + SAST scan + dep scan  │
  (only changed files + transitive dependents)  │
        │                                       │
        ▼                                       │
Graph Engine: update subgraph, compute diff     │
        │                                       │
        ├──▶ Graph diff: "3 nodes added,        │
        │    1 edge removed, 2 findings new"    │
        │                                       │
        ▼                                       │
Reasoning Layer:                                │
  • assess new findings in context              │
  • discover chains via graph traversal         │
  • score contextual severity                   │
  • retrieve relevant CWE/CVE knowledge         │
  • generate remediation suggestions            │
        │                                       │
        ▼                                       │
Output:                                         │
  • PR comment with posture delta               │
  • Updated posture score                       │
  • New findings with contextual severity       │
  • Chain alerts if critical paths found         │
  • GitHub check status (pass/warn/fail)        │
        │                                       │
        ▼                                       │
Posture graph updated ◀────────────────────────┘
  (ready for next commit)
```

---

## 5. Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Core Language** | Python 3.11+ | Ecosystem for ML/security tooling |
| **API Framework** | FastAPI | Async, webhook handling, OpenAPI docs |
| **Graph Database** | Neo4j (Community Edition) | Native graph traversal, Cypher queries, mature ecosystem |
| **AST Parsing** | Tree-sitter (py-tree-sitter) | Incremental, language-agnostic, fast |
| **SAST Tools** | Semgrep, Bandit | Subprocess calls — these are tools, not the product |
| **Dep Scanning** | pip-audit, npm audit, trivy | Standard tooling per ecosystem |
| **Vector Store** | ChromaDB or Qdrant | Knowledge base for CWE/CVE/OWASP retrieval |
| **Embeddings** | BGE-M3 | Multilingual, strong on technical text |
| **LLM** | Claude (via API) or GPT-4 | Reasoning layer — tool-calling mode |
| **Agent Framework** | LangGraph or custom tool loop | Orchestrates multi-step reasoning |
| **Task Queue** | Celery + Redis | Async processing of webhook events |
| **Containerization** | Docker Compose | Neo4j + Redis + API in single compose |
| **CI/CD** | GitHub Actions | Dogfooding — POSTURA analyzes itself |

---

## 6. Graph Queries — Examples

These illustrate the kind of reasoning the graph enables:

**Find all public endpoints that can reach PII data stores:**
```cypher
MATCH (e:Endpoint {is_public: true})-[:HANDLED_BY]->(f:Function)
MATCH path = (f)-[:CALLS*1..5]->(g:Function)-[:READS_FROM|WRITES_TO]->(d:DataStore {contains_pii: true})
RETURN e.path, e.method, [n IN nodes(path) | n.name] AS call_chain, d.type
```

**Find all vulnerability chains (compositional risk):**
```cypher
MATCH chain = (f1:Finding)-[:CHAINS_TO*1..3]->(f2:Finding)
WHERE f1.contextual_severity >= 'HIGH' OR f2.contextual_severity >= 'HIGH'
RETURN f1, f2, length(chain) AS chain_length,
       [n IN nodes(chain) | n.type + ': ' + n.cwe_id] AS chain_description
ORDER BY chain_length DESC
```

**Blast radius of a compromised dependency:**
```cypher
MATCH (d:Dependency {name: $dep_name})
MATCH path = (d)<-[:USES]-(f:Function)<-[:CALLS*0..4]-(g:Function)<-[:HANDLED_BY]-(e:Endpoint)
RETURN d.name, count(DISTINCT e) AS exposed_endpoints,
       collect(DISTINCT e.path) AS endpoint_paths,
       any(node IN nodes(path) WHERE node:DataStore AND node.contains_pii) AS reaches_pii
```

**Posture delta for a specific commit:**
```cypher
MATCH (f:Finding {introduced_in: $commit_sha})
WITH count(f) AS new_findings,
     sum(CASE f.contextual_severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
         WHEN 'MEDIUM' THEN 2 ELSE 1 END) AS risk_added

MATCH (f2:Finding {resolved_in: $commit_sha})
WITH new_findings, risk_added, count(f2) AS resolved_findings,
     sum(CASE f2.contextual_severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
         WHEN 'MEDIUM' THEN 2 ELSE 1 END) AS risk_removed

RETURN new_findings, resolved_findings,
       risk_added - risk_removed AS net_risk_delta,
       CASE WHEN risk_added > risk_removed THEN 'DEGRADED'
            WHEN risk_added < risk_removed THEN 'IMPROVED'
            ELSE 'NEUTRAL' END AS posture_change
```

---

## 7. Phased Build Plan

### Phase 1: Foundation (Week 1-2)
- [ ] Project scaffolding: FastAPI app, Docker Compose (Neo4j + Redis + API)
- [ ] Tree-sitter integration: parse Python files into AST nodes
- [ ] Basic graph schema in Neo4j: Function, Endpoint, DataStore nodes
- [ ] CALLS and READS_FROM/WRITES_TO edge extraction from AST
- [ ] Semgrep/Bandit integration as subprocess tools
- [ ] Initial graph population from a sample repo
- **Milestone:** Can ingest a Python repo and visualize the call graph in Neo4j Browser

### Phase 2: Threat Graph (Week 3-4)
- [ ] Full graph schema: all node and edge types
- [ ] Endpoint extraction for Flask/FastAPI (auth detection)
- [ ] TrustZone inference from directory structure + auth decorators
- [ ] Dependency scanning integration (pip-audit)
- [ ] Finding nodes created from SAST + dep scan results
- [ ] Basic data flow tracking (function params → return values)
- **Milestone:** Full threat graph for a sample repo with findings placed in context

### Phase 3: Incremental Updates (Week 5-6)
- [ ] GitHub webhook receiver
- [ ] Change scope analyzer (git diff → affected files → affected subgraph)
- [ ] Incremental graph update algorithm (soft delete, rebuild, diff)
- [ ] Graph diff computation (what changed between commits)
- [ ] Celery task queue for async processing
- **Milestone:** Push a commit, graph updates incrementally, diff is computed

### Phase 4: Reasoning Layer (Week 7-9)
- [ ] Knowledge base: CWE/CVE/OWASP data ingested into vector store
- [ ] Hybrid retrieval over knowledge base (BM25 + dense)
- [ ] Agent tool definitions: graph_query, trace_dataflow, find_chains, etc.
- [ ] PR assessment reasoning chain
- [ ] Chain discovery algorithm (graph traversal + LLM validation)
- [ ] Contextual severity scoring
- [ ] Remediation generation
- **Milestone:** Agent produces contextual PR security review with chain analysis

### Phase 5: Query Interface + Polish (Week 10-12)
- [ ] REST API endpoints
- [ ] Natural language query engine (NL → Cypher → answer)
- [ ] GitHub PR comment integration
- [ ] Posture score tracking over time
- [ ] Dashboard (optional — even a simple CLI/API is fine)
- [ ] Dogfooding: point POSTURA at its own repo
- [ ] README, architecture docs, demo video
- **Milestone:** Complete system, demo-ready, open-sourced

---

## 8. What Makes This Impressive

| Dimension | What POSTURA Demonstrates |
|-----------|--------------------------|
| **Graph reasoning** | Not flat analysis — compositional risk via graph traversal |
| **Incremental architecture** | Doesn't re-scan from scratch — real-world scalability |
| **Multi-tool orchestration** | Agent decides which tools to call based on findings |
| **RAG application** | Hybrid retrieval over security knowledge base |
| **LLM reasoning** | Contextual severity that static tools can't compute |
| **Production patterns** | Webhooks, async processing, persistent state, API |
| **Domain depth** | Speaks the language of CISOs, not just developers |

---

## 9. Key Design Decisions to Defend in Interviews

1. **Why Neo4j over a relational DB?** — Vulnerability chains are graph traversals. A SQL JOIN across 5 tables for a 5-hop chain is O(n^5). Cypher does this natively.

2. **Why Tree-sitter over AST modules?** — Language-agnostic + incremental parsing. Python's `ast` module works but doesn't extend to JS/TS/Go. Tree-sitter gives you multi-language support for free.

3. **Why not just use Semgrep?** — Semgrep finds individual issues. It cannot reason about whether a finding is reachable from a public endpoint, or whether two medium findings compose into a critical chain. That's the graph + LLM layer.

4. **Why incremental updates instead of full re-scan?** — A production codebase with 100K+ LOC takes minutes to fully scan. Incremental updates on a 3-file diff take seconds. This is the difference between "CI check that blocks your PR for 5 minutes" and "instant feedback."

5. **Why an LLM reasoning layer?** — Contextual severity assessment requires judgment. "Is this SQL injection exploitable given the auth context?" is not a rule you can write — it requires understanding the architecture. LLMs with the right tools (graph queries, knowledge retrieval) can approximate this judgment.

---

## 10. Repository Structure

```
postura/
├── README.md
├── docker-compose.yml
├── pyproject.toml
│
├── src/
│   ├── postura/
│   │   ├── __init__.py
│   │   ├── config.py                 # Settings, env vars
│   │   │
│   │   ├── webhook/                  # Block 1: Webhook Trigger Layer
│   │   │   ├── __init__.py
│   │   │   ├── receiver.py           # FastAPI webhook endpoints
│   │   │   ├── event_router.py       # Classify webhook events
│   │   │   └── scope_analyzer.py     # Git diff → affected scope
│   │   │
│   │   ├── ingest/                   # Block 2: Ingest Layer
│   │   │   ├── __init__.py
│   │   │   ├── ast_parser.py         # Tree-sitter based parsing
│   │   │   ├── endpoint_extractor.py # Framework-aware route extraction
│   │   │   ├── sast_runner.py        # Semgrep/Bandit subprocess wrapper
│   │   │   ├── dep_scanner.py        # pip-audit/npm audit wrapper
│   │   │   ├── config_analyzer.py    # .env, CORS, secrets scanning
│   │   │   └── data_flow.py          # Intra-function data flow tracking
│   │   │
│   │   ├── graph/                    # Block 3: Graph Engine
│   │   │   ├── __init__.py
│   │   │   ├── schema.py             # Node/edge type definitions
│   │   │   ├── builder.py            # Full graph construction
│   │   │   ├── updater.py            # Incremental graph updates
│   │   │   ├── differ.py             # Graph diff computation
│   │   │   └── queries.py            # Common Cypher query templates
│   │   │
│   │   ├── knowledge/                # Block 4: Knowledge Base
│   │   │   ├── __init__.py
│   │   │   ├── cwe_loader.py         # CWE database ingestion
│   │   │   ├── cve_loader.py         # CVE data ingestion
│   │   │   ├── owasp_loader.py       # OWASP guidelines ingestion
│   │   │   ├── embedder.py           # Embedding pipeline
│   │   │   └── retriever.py          # Hybrid BM25 + dense retrieval
│   │   │
│   │   ├── reasoning/                # Block 5: Reasoning Layer
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py       # Agent loop / LangGraph definition
│   │   │   ├── tools.py              # Tool definitions for the agent
│   │   │   ├── prompts.py            # System prompts for each reasoning mode
│   │   │   ├── chain_discovery.py    # Vulnerability chain detection
│   │   │   ├── severity_scorer.py    # Contextual severity assessment
│   │   │   └── remediation.py        # Fix generation
│   │   │
│   │   ├── api/                      # Block 6: Query Interface
│   │   │   ├── __init__.py
│   │   │   ├── routes.py             # REST API endpoints
│   │   │   ├── nl_query.py           # Natural language → Cypher
│   │   │   └── github_integration.py # PR comments, check statuses
│   │   │
│   │   └── models/                   # Shared data models
│   │       ├── __init__.py
│   │       ├── ingest.py             # StructuredIngestResult, etc.
│   │       ├── graph.py              # Graph node/edge models
│   │       └── findings.py           # Finding, Chain, PostureScore
│   │
│   └── tasks/                        # Celery async tasks
│       ├── __init__.py
│       └── analysis.py               # Webhook → full pipeline task
│
├── knowledge_data/                   # Raw CWE/CVE/OWASP data
│   ├── cwe/
│   ├── cve/
│   └── owasp/
│
├── tests/
│   ├── test_ingest/
│   ├── test_graph/
│   ├── test_reasoning/
│   └── fixtures/                     # Sample repos for testing
│       └── vulnerable_flask_app/
│
└── docs/
    ├── architecture.md               # This document
    ├── graph_schema.md               # Detailed schema reference
    └── reasoning_modes.md            # How the agent reasons
```
