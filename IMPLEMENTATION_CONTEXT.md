# POSTURA — Implementation Context

> Living reference document. Updated as decisions are made and components are built.
> For the high-level vision, see `POSTURA_ARCHITECTURE.md`.
> For the task list, see `TODO.md`.

---

## 1. Environment & Infrastructure

### 1.1 Python Environment

- **Python 3.11+** (3.12 preferred for performance improvements)
- Package management: `pyproject.toml` with `pip` or `uv`
- Virtual environment: `.venv/` at project root

### 1.2 Docker Compose Services

```yaml
services:
  neo4j:
    image: neo4j:5-community
    ports:
      - "7474:7474"   # Browser UI
      - "7687:7687"   # Bolt protocol
    environment:
      NEO4J_AUTH: neo4j/postura_dev
      NEO4J_PLUGINS: '["apoc"]'
    volumes:
      - neo4j_data:/data
      - neo4j_logs:/logs

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  api:
    build: .
    ports:
      - "8000:8000"
    depends_on:
      - neo4j
      - redis
    environment:
      NEO4J_URI: bolt://neo4j:7687
      NEO4J_USER: neo4j
      NEO4J_PASSWORD: postura_dev
      REDIS_URL: redis://redis:6379/0
    command: uvicorn postura.api.app:app --host 0.0.0.0 --port 8000 --reload

  worker:
    build: .
    depends_on:
      - neo4j
      - redis
    environment:
      NEO4J_URI: bolt://neo4j:7687
      NEO4J_USER: neo4j
      NEO4J_PASSWORD: postura_dev
      REDIS_URL: redis://redis:6379/0
    command: celery -A postura.tasks worker --loglevel=info

volumes:
  neo4j_data:
  neo4j_logs:
```

### 1.3 Configuration (pydantic-settings)

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "postura_dev"
    redis_url: str = "redis://localhost:6379/0"

    github_webhook_secret: str = ""
    github_token: str = ""

    llm_provider: str = "anthropic"         # "anthropic" | "openai"
    llm_model: str = "claude-sonnet-4-20250514"
    llm_api_key: str = ""

    vector_store: str = "chromadb"          # "chromadb" | "qdrant"
    embedding_model: str = "BAAI/bge-m3"

    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"

    log_level: str = "INFO"

    class Config:
        env_file = ".env"
        env_prefix = "POSTURA_"
```

---

## 2. Neo4j Graph Schema — Exact Specification

### 2.1 Node Labels & Properties

#### :Service
| Property | Type | Required | Description |
|----------|------|----------|-------------|
| uid | String | yes | Unique ID: `svc:{name}` |
| name | String | yes | Service/app name |
| type | String | yes | `"web"` \| `"api"` \| `"worker"` \| `"monolith"` |
| exposure_level | String | yes | `"public"` \| `"internal"` \| `"system"` |
| repo_path | String | yes | Root path of this service in the repo |

#### :Endpoint
| Property | Type | Required | Description |
|----------|------|----------|-------------|
| uid | String | yes | Unique ID: `ep:{method}:{path}` |
| path | String | yes | Route path, e.g. `/api/users/<id>` |
| method | String | yes | `"GET"` \| `"POST"` \| `"PUT"` \| `"DELETE"` etc. |
| auth_required | Boolean | yes | Whether auth decorator/middleware is present |
| auth_type | String | no | `"session"` \| `"jwt"` \| `"api_key"` \| `"basic"` \| `"none"` |
| input_params | String[] | no | Parameter names from path/query/body |
| is_public | Boolean | yes | Reachable without authentication |
| framework | String | yes | `"flask"` \| `"fastapi"` \| `"django"` \| `"express"` |
| file | String | yes | Source file path |
| line | Integer | yes | Line number of route definition |

#### :Function
| Property | Type | Required | Description |
|----------|------|----------|-------------|
| uid | String | yes | Unique ID: `fn:{module}:{qualified_name}` |
| name | String | yes | Function/method name |
| qualified_name | String | yes | `module.ClassName.method` or `module.function` |
| file | String | yes | Source file path (relative to repo root) |
| line | Integer | yes | Start line |
| end_line | Integer | yes | End line |
| module | String | yes | Python module path |
| is_entry_point | Boolean | yes | Is this an endpoint handler? |
| handles_user_input | Boolean | yes | Does this function receive external input? |
| decorators | String[] | no | List of decorator names |

#### :DataStore
| Property | Type | Required | Description |
|----------|------|----------|-------------|
| uid | String | yes | Unique ID: `ds:{type}:{name}` |
| name | String | yes | Database name, table name, or file path |
| type | String | yes | `"postgresql"` \| `"sqlite"` \| `"redis"` \| `"filesystem"` \| `"external_api"` |
| contains_pii | Boolean | yes | Heuristic: tables named `users`, `profiles`, `payments`, etc. |
| encryption_at_rest | Boolean | no | From config analysis |
| access_pattern | String | no | `"read_heavy"` \| `"write_heavy"` \| `"mixed"` |

#### :Dependency
| Property | Type | Required | Description |
|----------|------|----------|-------------|
| uid | String | yes | Unique ID: `dep:{name}:{version}` |
| name | String | yes | Package name |
| version | String | yes | Pinned version |
| pinned | Boolean | yes | Is version pinned (not `>=` or `*`) |
| known_cves | String[] | no | List of CVE IDs from pip-audit |
| depth | Integer | yes | 0 = direct dependency, 1+ = transitive |

#### :Finding
| Property | Type | Required | Description |
|----------|------|----------|-------------|
| uid | String | yes | Unique ID: `find:{tool}:{rule_id}:{file}:{line}` |
| type | String | yes | `"sast"` \| `"dependency"` \| `"config"` \| `"chain"` |
| tool | String | yes | `"semgrep"` \| `"bandit"` \| `"pip-audit"` \| `"config_analyzer"` |
| rule_id | String | yes | Tool-specific rule ID |
| cwe_id | String | no | CWE identifier, e.g. `"CWE-89"` |
| title | String | yes | Human-readable finding title |
| description | String | yes | Finding description |
| raw_severity | String | yes | `"CRITICAL"` \| `"HIGH"` \| `"MEDIUM"` \| `"LOW"` \| `"INFO"` |
| contextual_severity | String | no | Set by reasoning layer — same scale |
| status | String | yes | `"open"` \| `"resolved"` \| `"suppressed"` \| `"stale"` |
| evidence | String | no | Code snippet or explanation |
| file | String | yes | Source file |
| line | Integer | yes | Line number |
| introduced_in | String | no | Commit SHA that introduced this finding |
| resolved_in | String | no | Commit SHA that resolved this finding |

#### :TrustZone
| Property | Type | Required | Description |
|----------|------|----------|-------------|
| uid | String | yes | Unique ID: `tz:{name}` |
| name | String | yes | Zone name, e.g. `"public"`, `"authenticated"`, `"admin"` |
| level | Integer | yes | 0=public, 1=authenticated, 2=privileged, 3=system |
| auth_mechanism | String | no | How auth is enforced in this zone |

### 2.2 Edge Types & Properties

| Edge | From | To | Properties |
|------|------|----|------------|
| :CALLS | Function | Function | — |
| :READS_FROM | Function | DataStore | query_type: String? (`"select"`, `"get"`, `"read"`) |
| :WRITES_TO | Function | DataStore | query_type: String? (`"insert"`, `"update"`, `"delete"`) |
| :HANDLED_BY | Endpoint | Function | — |
| :BELONGS_TO | Endpoint | Service | — |
| :IN_ZONE | Endpoint | TrustZone | — |
| :USES | Function | Dependency | via_import: String (import statement) |
| :AFFECTS | Finding | Function \| Endpoint \| Dependency | — |
| :CHAINS_TO | Finding | Finding | evidence: String, confidence: Float, path_length: Integer |
| :TRUSTS | TrustZone | TrustZone | — |

### 2.3 Constraints & Indexes

```cypher
-- Unique constraints (enforce data integrity)
CREATE CONSTRAINT unique_service_uid IF NOT EXISTS FOR (s:Service) REQUIRE s.uid IS UNIQUE;
CREATE CONSTRAINT unique_endpoint_uid IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.uid IS UNIQUE;
CREATE CONSTRAINT unique_function_uid IF NOT EXISTS FOR (f:Function) REQUIRE f.uid IS UNIQUE;
CREATE CONSTRAINT unique_datastore_uid IF NOT EXISTS FOR (d:DataStore) REQUIRE d.uid IS UNIQUE;
CREATE CONSTRAINT unique_dependency_uid IF NOT EXISTS FOR (d:Dependency) REQUIRE d.uid IS UNIQUE;
CREATE CONSTRAINT unique_finding_uid IF NOT EXISTS FOR (f:Finding) REQUIRE f.uid IS UNIQUE;
CREATE CONSTRAINT unique_trustzone_uid IF NOT EXISTS FOR (t:TrustZone) REQUIRE t.uid IS UNIQUE;

-- Performance indexes
CREATE INDEX idx_function_file IF NOT EXISTS FOR (f:Function) ON (f.file);
CREATE INDEX idx_function_module IF NOT EXISTS FOR (f:Function) ON (f.module);
CREATE INDEX idx_finding_status IF NOT EXISTS FOR (f:Finding) ON (f.status);
CREATE INDEX idx_finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.contextual_severity);
CREATE INDEX idx_finding_cwe IF NOT EXISTS FOR (f:Finding) ON (f.cwe_id);
CREATE INDEX idx_endpoint_public IF NOT EXISTS FOR (e:Endpoint) ON (e.is_public);
CREATE INDEX idx_dependency_name IF NOT EXISTS FOR (d:Dependency) ON (d.name);
```

---

## 3. Pydantic Data Models

These are the internal Python models, separate from the Neo4j schema but mapped to it.

### 3.1 Ingest Models

```python
from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional

class ASTNode(BaseModel):
    name: str
    qualified_name: str
    node_type: str                          # "function", "class", "method"
    file: str
    line: int
    end_line: int
    module: str
    decorators: list[str] = []
    parameters: list[str] = []
    return_type: Optional[str] = None
    docstring: Optional[str] = None

class CallEdge(BaseModel):
    caller: str                              # qualified_name of calling function
    callee: str                              # qualified_name of called function
    file: str
    line: int                                # line of the call site

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class SASTFinding(BaseModel):
    tool: str                                # "semgrep" | "bandit"
    rule_id: str
    title: str
    description: str
    severity: Severity
    cwe_id: Optional[str] = None
    file: str
    line: int
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None

class DepVulnerability(BaseModel):
    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    cve_id: str
    severity: Severity
    description: str

class EndpointInfo(BaseModel):
    path: str
    method: str
    handler_function: str                    # qualified_name of handler
    auth_required: bool
    auth_type: Optional[str] = None
    input_params: list[str] = []
    framework: str
    file: str
    line: int

class ConfigIssue(BaseModel):
    issue_type: str                          # "hardcoded_secret", "cors_misconfiguration", etc.
    description: str
    severity: Severity
    file: str
    line: Optional[int] = None
    evidence: str

class StructuredIngestResult(BaseModel):
    ast_nodes: list[ASTNode]
    call_edges: list[CallEdge]
    endpoints: list[EndpointInfo]
    sast_findings: list[SASTFinding]
    dep_vulnerabilities: list[DepVulnerability]
    config_issues: list[ConfigIssue]
    # Data flow is represented through call_edges + endpoint → handler mapping
    # Full taint tracking is out of scope — we use call-graph reachability
```

### 3.2 Graph Diff Models

```python
class GraphDiff(BaseModel):
    commit_sha: str
    new_nodes: list[dict]                    # nodes added
    removed_nodes: list[dict]                # nodes removed (were stale, not rebuilt)
    changed_nodes: list[dict]                # nodes with changed properties
    new_edges: list[dict]                    # edges added
    removed_edges: list[dict]               # edges removed
    new_chains: list[dict]                   # new CHAINS_TO relationships
    broken_chains: list[dict]               # removed CHAINS_TO relationships
    posture_delta: float                     # positive = degraded, negative = improved
    summary: str                             # human-readable summary
```

### 3.3 Reasoning Output Models

```python
class ChainLink(BaseModel):
    finding_uid: str
    title: str
    severity: Severity
    cwe_id: Optional[str] = None

class VulnerabilityChain(BaseModel):
    chain_id: str
    links: list[ChainLink]
    overall_severity: Severity
    evidence: str
    attack_narrative: str                    # "An attacker could..."
    remediation_priority: int                # 1 = fix first

class ContextualAssessment(BaseModel):
    finding_uid: str
    raw_severity: Severity
    contextual_severity: Severity
    reasoning: str
    reachable_from_public: bool
    touches_pii: bool
    auth_protection_level: int               # 0=none, 1=basic, 2=strong
    in_chains: list[str]                     # chain IDs this finding participates in

class RemediationSuggestion(BaseModel):
    finding_uid: str
    title: str
    description: str
    code_diff: Optional[str] = None
    effort_estimate: str                     # "low", "medium", "high"
    references: list[str]                    # CWE/OWASP URLs

class PRSecurityReview(BaseModel):
    commit_sha: str
    posture_change: str                      # "IMPROVED" | "DEGRADED" | "NEUTRAL"
    posture_delta: float
    critical_chains: list[VulnerabilityChain]
    assessments: list[ContextualAssessment]
    remediations: list[RemediationSuggestion]
    summary: str
```

---

## 4. Tree-sitter Integration

### 4.1 Setup

```bash
pip install tree-sitter tree-sitter-python tree-sitter-javascript
```

Tree-sitter 0.21+ uses the pre-built language bindings directly — no need to build `.so` files manually.

```python
import tree_sitter_python as tspython
from tree_sitter import Language, Parser

PY_LANGUAGE = Language(tspython.language())
parser = Parser(PY_LANGUAGE)
```

### 4.2 What to Extract

From each Python file, extract:

1. **Function definitions** — `function_definition` and `decorated_definition` nodes
   - Name, parameters, return type annotation, decorators, line range
2. **Class definitions** — `class_definition` nodes
   - Name, base classes, methods (nested function_definitions)
3. **Import statements** — `import_statement` and `import_from_statement`
   - Maps module → imported names (for resolving call targets)
4. **Function calls** — `call` expression nodes within function bodies
   - Caller (enclosing function) → callee (called function name)
   - Resolve callee to qualified name using import map
5. **Decorator usage** — `decorator` nodes
   - Critical for auth detection (`@login_required`, `@app.route`, etc.)
6. **String literals with patterns** — for detecting hardcoded secrets, SQL strings, etc.

### 4.3 Call Resolution Strategy

Call resolution (mapping `foo()` to the actual function `mymodule.foo`) uses a tiered approach:

1. **Local scope** — function defined in the same file
2. **Import resolution** — `from mymodule import foo` → `mymodule.foo`
3. **Attribute access** — `self.method()` → `ClassName.method` (via class context)
4. **Unresolved** — if we can't resolve, create edge to a placeholder node. Don't drop it.

This is deliberately imprecise. We're building a conservative call graph (may include false edges) rather than an unsound one (may miss real edges). For security analysis, over-approximation is safer.

### 4.4 Endpoint Detection Patterns

**Flask:**
```python
# Direct route decorator
@app.route("/users", methods=["GET", "POST"])
@blueprint.route("/api/items/<int:item_id>")

# Method-specific shortcuts
@app.get("/users")
@app.post("/users")
```

**FastAPI:**
```python
@app.get("/users/{user_id}")
@app.post("/users/")
@router.get("/items/", dependencies=[Depends(verify_token)])
```

Detection: look for `decorator` nodes where the decorator expression matches `*.route`, `*.get`, `*.post`, `*.put`, `*.delete`, `*.patch`.

**Auth detection heuristics:**
- Decorator names containing: `login_required`, `auth`, `permission`, `require`, `protect`, `Depends` (FastAPI)
- Function parameters with type annotations including: `current_user`, `token`, `credentials`
- If no auth decorator and no auth parameter → `is_public: true`

---

## 5. SAST Tool Integration

### 5.1 Semgrep

```bash
semgrep scan --config auto --json --quiet <target_dir>
```

Or with specific rulesets for controlled, reproducible results:

```bash
semgrep scan \
  --config p/python \
  --config p/security-audit \
  --config p/owasp-top-ten \
  --json --quiet <target_dir>
```

**JSON output parsing:** Each result has:
- `check_id` → rule_id
- `extra.severity` → raw_severity
- `extra.metadata.cwe` → CWE mapping
- `path`, `start.line`, `end.line` → location
- `extra.message` → description
- `extra.lines` → code_snippet

### 5.2 Bandit

```bash
bandit -r <target_dir> -f json -q
```

**JSON output parsing:** Each result has:
- `test_id` → rule_id (e.g., `B101`, `B608`)
- `issue_severity` → `"HIGH"` / `"MEDIUM"` / `"LOW"`
- `issue_confidence` → `"HIGH"` / `"MEDIUM"` / `"LOW"`
- `issue_cwe.id` → CWE number
- `filename`, `line_number` → location
- `issue_text` → description
- `code` → code_snippet

### 5.3 Deduplication

Semgrep and Bandit may report the same issue. Deduplicate by:
1. Same file + overlapping line range + same CWE → merge, keep the one with more detail
2. Same file + same line + different CWE → keep both (different vulnerability classes)

### 5.4 pip-audit

```bash
pip-audit -r requirements.txt --format=json
```

**JSON output parsing:** Each vulnerability has:
- `name` → package name
- `version` → installed version
- `vulns[].id` → CVE ID
- `vulns[].fix_versions` → fixed versions
- `vulns[].description` → description

---

## 6. Knowledge Base Setup

### 6.1 Data Sources

| Source | URL | Format | Update Frequency |
|--------|-----|--------|------------------|
| MITRE CWE | https://cwe.mitre.org/data/xml/cwec_latest.xml.zip | XML | Quarterly |
| NVD CVE | https://services.nvd.nist.gov/rest/json/cves/2.0 | JSON API | Daily |
| OWASP Top 10 | https://owasp.org/Top10/ | Markdown/HTML | Yearly |
| OWASP ASVS | https://github.com/OWASP/ASVS | CSV/Markdown | Yearly |

### 6.2 Chunking Strategy

Each knowledge entry becomes a document in the vector store:

- **CWE entries:** One document per CWE. Fields: ID, name, description, extended_description, common_consequences, potential_mitigations, related_weaknesses. Chunk by section if long.
- **CVE entries:** One document per CVE. Fields: ID, description, CVSS score, affected packages, references.
- **OWASP:** One document per category/requirement. Include examples and remediation guidance.

Metadata on each chunk:
```python
{
    "source": "cwe",           # "cwe" | "cve" | "owasp"
    "id": "CWE-89",
    "category": "injection",   # normalized category for filtering
    "severity": "high",
}
```

### 6.3 Vector Store Schema (ChromaDB)

```python
import chromadb

client = chromadb.PersistentClient(path="./knowledge_store")

collection = client.get_or_create_collection(
    name="security_knowledge",
    metadata={"hnsw:space": "cosine"},
)
```

### 6.4 Hybrid Retrieval

1. **Dense search:** Embed the query with BGE-M3, search the vector store.
2. **BM25 search:** Full-text keyword search over the same documents (ChromaDB `where_document` or a separate BM25 index via `rank-bm25`).
3. **Fusion:** Reciprocal Rank Fusion (RRF) to merge ranked lists.

```python
def hybrid_retrieve(query: str, k: int = 5) -> list[Document]:
    dense_results = vector_search(query, k=k*2)
    bm25_results = bm25_search(query, k=k*2)
    return reciprocal_rank_fusion(dense_results, bm25_results, k=k)
```

---

## 7. LLM Integration & Agent Tools

### 7.1 Provider Configuration

Using Anthropic Python SDK with tool use:

```python
from anthropic import Anthropic

client = Anthropic(api_key=settings.llm_api_key)
```

### 7.2 Agent Tool Definitions

Each tool is defined as a JSON schema for the LLM's tool_use interface and backed by a Python function.

```python
TOOLS = [
    {
        "name": "graph_query",
        "description": "Execute a read-only Cypher query against the threat graph. Use to explore the graph structure, find nodes, traverse relationships.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cypher": {"type": "string", "description": "Cypher query (read-only)"},
            },
            "required": ["cypher"],
        },
    },
    {
        "name": "knowledge_retrieve",
        "description": "Search the security knowledge base (CWE/CVE/OWASP) for information relevant to a finding or vulnerability class.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query describing the vulnerability or security concept"},
                "source_filter": {"type": "string", "enum": ["cwe", "cve", "owasp", "all"], "description": "Filter by knowledge source"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "trace_dataflow",
        "description": "Find all call-graph paths between two nodes in the threat graph. Used to determine if user input can reach a vulnerable function.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_uid": {"type": "string", "description": "UID of the source node (typically an endpoint or its handler)"},
                "sink_uid": {"type": "string", "description": "UID of the sink node (typically a vulnerable function or data store)"},
                "max_hops": {"type": "integer", "description": "Maximum path length", "default": 6},
            },
            "required": ["source_uid", "sink_uid"],
        },
    },
    {
        "name": "find_chains",
        "description": "Find all vulnerability chains involving a specific finding. Returns multi-hop chains connected via CHAINS_TO edges.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_uid": {"type": "string", "description": "UID of the finding to search chains for"},
            },
            "required": ["finding_uid"],
        },
    },
    {
        "name": "assess_exploitability",
        "description": "Get the graph neighborhood of a finding for exploitability assessment. Returns the finding, its affected node, trust zone, reachability from public endpoints, and PII exposure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_uid": {"type": "string", "description": "UID of the finding to assess"},
            },
            "required": ["finding_uid"],
        },
    },
    {
        "name": "generate_remediation",
        "description": "Generate a remediation suggestion for a finding, including code fix and explanation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "finding_uid": {"type": "string", "description": "UID of the finding to remediate"},
                "chain_context": {"type": "string", "description": "Optional context about vulnerability chains this finding participates in"},
            },
            "required": ["finding_uid"],
        },
    },
]
```

### 7.3 System Prompt (PR Assessment Mode)

```
You are POSTURA, an expert security analyst agent. You are assessing the security impact of a code change (commit/PR) on a codebase.

You have access to:
1. A threat graph in Neo4j representing the codebase's attack surface — endpoints, functions, data stores, dependencies, trust zones, and their relationships.
2. A security knowledge base with CWE, CVE, and OWASP reference data.
3. A graph diff showing what changed in this commit.

Your task:
- For each new or changed finding, assess its contextual severity (not just raw CVSS).
- Determine if findings are reachable from public endpoints.
- Discover vulnerability chains — sequences of findings that compose into a larger risk.
- Prioritize findings by real-world exploitability, not just raw severity.
- Generate remediation suggestions for critical findings.

Use your tools systematically. Do not guess — query the graph to verify claims.

Output a structured security review.
```

---

## 8. Testing Strategy

### 8.1 Test Fixture: Vulnerable Flask App

Located at `tests/fixtures/vulnerable_flask_app/`. A deliberately vulnerable Flask application with known, documented vulnerabilities.

**Structure:**
```
vulnerable_flask_app/
├── app.py              # Main Flask app with routes
├── auth.py             # Authentication middleware (with gaps)
├── db.py               # Database access layer (with SQL injection)
├── models.py           # Data models
├── utils.py            # Utility functions
├── config.py           # Configuration (with hardcoded secrets)
├── requirements.txt    # Dependencies (with vulnerable versions)
└── README.md           # Documents the intentional vulnerabilities
```

**Intentional vulnerabilities:**
1. **SQL Injection (CWE-89):** `db.py:get_user_by_name()` uses f-string in SQL query
2. **Hardcoded Secret (CWE-798):** `config.py` has `SECRET_KEY = "super_secret_123"`
3. **Missing Auth (CWE-306):** `app.py:/admin/users` endpoint has no `@login_required`
4. **SSRF (CWE-918):** `utils.py:fetch_url()` takes user input as URL without validation
5. **Vulnerable Dependency:** `requirements.txt` pins an old `requests` or `flask` version with known CVE
6. **PII Exposure Chain:** Public endpoint → `get_user_by_name()` (SQLi) → `users` table (contains email, password hash) — this is the multi-hop chain POSTURA should detect

### 8.2 Test Levels

| Level | What | Framework | When |
|-------|------|-----------|------|
| Unit | Individual functions (parser, extractors) | pytest | Every task |
| Integration | Component interactions (ingest → graph) | pytest + Neo4j testcontainer | End of each phase |
| End-to-end | Full pipeline (webhook → PR comment) | pytest + Docker Compose | Phase milestones |

### 8.3 Neo4j Test Strategy

Use `testcontainers` for integration tests:

```python
from testcontainers.neo4j import Neo4jContainer

@pytest.fixture(scope="session")
def neo4j_container():
    with Neo4jContainer("neo4j:5-community") as neo4j:
        yield neo4j
```

For unit tests that touch graph logic, use a shared test Neo4j instance (Docker Compose test profile) and clear the database between tests.

---

## 9. Evaluation Plan (Research Track)

### 9.1 Target Applications

| Application | Type | Language | Known Vulnerabilities |
|-------------|------|----------|-----------------------|
| OWASP Juice Shop | Web app | Node.js/TypeScript | 100+ documented |
| Damn Vulnerable Web App | Web app | PHP | 10+ categories |
| Sample Microservices | Custom fixture | Python | Manually seeded |
| Vulnerable Flask App | Custom fixture | Python | 6 seeded (see §8.1) |

**Note:** Juice Shop and DVWA are non-Python. For the 12-week scope, evaluation focuses on the Python fixtures. Juice Shop/DVWA can be used for the paper if JS/TS support is added, or analyzed at the endpoint/dependency level only (no AST parsing).

### 9.2 Metrics

| Metric | Definition | Measurement |
|--------|-----------|-------------|
| Individual finding detection | Findings detected by tool | Count, compare POSTURA vs Semgrep+Bandit standalone |
| Chain detection | Multi-hop vulnerability chains identified | Count (static tools detect 0 by design) |
| Contextual severity accuracy | Agreement with expert-labeled severity | Accuracy, Cohen's kappa vs expert labels |
| False positive rate | Findings that are not real vulnerabilities | Manual review of sample |
| Incremental update latency | Time for graph update on a commit | Seconds, compare full scan vs incremental |
| Posture score correlation | Does posture score track with real risk? | Correlation with expert assessment |

### 9.3 Ground Truth Labeling

For the Python test fixtures, manually document:
- Every real vulnerability (true positives)
- Every vulnerability chain (multi-hop paths)
- Contextual severity for each finding (expert judgment)

This becomes the gold standard for evaluation. Do this early (Phase 2), not at the end.

---

## 10. Decisions Log

> Record key technical decisions here as they're made. Format: date, decision, rationale, alternatives considered.

| Date | Decision | Rationale | Alternatives |
|------|----------|-----------|--------------|
| — | Neo4j Community Edition (not AuraDB) | Free, local, full control. AuraDB for production later. | AuraDB, Memgraph, FalkorDB |
| — | ChromaDB over Qdrant for knowledge base | Simpler setup, embedded mode, good enough for the knowledge base size (~10K docs). Switch to Qdrant if scale needed. | Qdrant, Weaviate, Pinecone |
| — | Call-graph reachability, not taint analysis | Taint analysis (tracking exact data flow through variables) is a research problem. Call-graph reachability (can this function be reached from that endpoint?) is practical and sufficient for chain detection. | Full taint analysis via CodeQL, Joern |
| — | Python-only for 12-week scope | Endpoint extractors, auth detection, and framework patterns are per-language. Ship Python (Flask + FastAPI), document extension points. | Multi-language from start |
| — | Semgrep + Bandit as SAST, not CodeQL | Semgrep and Bandit are lightweight, fast, easy to invoke as subprocesses. CodeQL is powerful but heavy (requires database build step). | CodeQL, SonarQube |
| — | LangGraph over raw tool loop | LangGraph provides state management, checkpointing, and structured agent flow. Less boilerplate than a custom loop. | Custom tool loop, CrewAI, AutoGen |
| — | BGE-M3 for embeddings | Strong on technical/security text, multilingual, open-source. Can run locally. | OpenAI ada-002, Cohere embed, E5 |
| — | Celery + Redis over bare asyncio | Webhook processing should be async and retriable. Celery gives us task queues, retries, monitoring (Flower) for free. | asyncio tasks, Dramatiq, Huey |

---

## 11. Key File → Responsibility Map

Quick reference: which file does what. Updated as code is written.

| File | Block | Responsibility |
|------|-------|---------------|
| `src/postura/config.py` | Core | Settings, env vars via pydantic-settings |
| `src/postura/webhook/receiver.py` | Webhook | FastAPI endpoint for GitHub webhooks |
| `src/postura/webhook/event_router.py` | Webhook | Classify events, extract metadata |
| `src/postura/webhook/scope_analyzer.py` | Webhook | Git diff → affected files → affected modules |
| `src/postura/ingest/ast_parser.py` | Ingest | Tree-sitter parsing → ASTNode, CallEdge |
| `src/postura/ingest/endpoint_extractor.py` | Ingest | Framework-aware route extraction |
| `src/postura/ingest/sast_runner.py` | Ingest | Semgrep + Bandit subprocess wrapper |
| `src/postura/ingest/dep_scanner.py` | Ingest | pip-audit wrapper |
| `src/postura/ingest/config_analyzer.py` | Ingest | Secrets, CORS, debug flag detection |
| `src/postura/graph/schema.py` | Graph | Cypher templates, constraint initialization |
| `src/postura/graph/builder.py` | Graph | Full graph construction from ingest results |
| `src/postura/graph/updater.py` | Graph | Incremental update (stale → rebuild → diff) |
| `src/postura/graph/differ.py` | Graph | Graph diff computation |
| `src/postura/graph/queries.py` | Graph | Reusable Cypher query functions |
| `src/postura/knowledge/embedder.py` | Knowledge | Embedding pipeline for CWE/CVE/OWASP |
| `src/postura/knowledge/retriever.py` | Knowledge | Hybrid BM25 + dense retrieval |
| `src/postura/reasoning/orchestrator.py` | Reasoning | LangGraph agent definition |
| `src/postura/reasoning/tools.py` | Reasoning | Tool implementations (graph_query, etc.) |
| `src/postura/reasoning/prompts.py` | Reasoning | System prompts per reasoning mode |
| `src/postura/reasoning/chain_discovery.py` | Reasoning | CHAINS_TO edge computation |
| `src/postura/reasoning/severity_scorer.py` | Reasoning | Contextual severity logic |
| `src/postura/api/routes.py` | API | REST endpoints |
| `src/postura/api/nl_query.py` | API | Natural language → Cypher |
| `src/postura/api/github_integration.py` | API | PR comments, check statuses |
| `src/postura/tasks/analysis.py` | Tasks | Celery task: full pipeline |
