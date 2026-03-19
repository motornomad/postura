from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional


class TaintFlow(BaseModel):
    """Evidence of a data-flow path from a taint source to a dangerous sink
    detected within a single function body (intraprocedural)."""
    function_qualified_name: str
    source_param: str       # variable/param name carrying tainted data
    source_type: str        # "request_param" | "function_param"
    sink_call: str          # dangerous call text, e.g. "cursor.execute"
    sink_type: str          # "sql_injection" | "command_injection" | "code_eval" | "path_traversal" | "ssrf"
    sanitized: bool         # True if a sanitizer was detected before the sink
    source_line: int        # line where taint was introduced (0 if unknown)
    sink_line: int          # line of the sink call
    file: str


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
    taint_sources: list[str] = []          # vars confirmed derived from HTTP request sources


class CallEdge(BaseModel):
    caller: str                              # qualified_name of calling function
    callee: str                              # qualified_name of called function (may be unresolved)
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


class DataAccessEvent(BaseModel):
    """A detected database/filesystem access within a function."""
    function_qualified_name: str    # which function did the access
    datastore_name: str             # table name, redis key pattern, file path, etc.
    datastore_type: str             # "sqlite" | "postgresql" | "redis" | "filesystem" | "sqlalchemy"
    access_type: str                # "read" | "write"
    file: str
    line: int
    raw_query: Optional[str] = None  # SQL string if detected


class StructuredIngestResult(BaseModel):
    ast_nodes: list[ASTNode] = []
    call_edges: list[CallEdge] = []
    endpoints: list[EndpointInfo] = []
    sast_findings: list[SASTFinding] = []
    dep_vulnerabilities: list[DepVulnerability] = []
    config_issues: list[ConfigIssue] = []
    data_accesses: list[DataAccessEvent] = []
    # Maps relative file path → list of top-level package names imported in that file.
    # Used to create (Function)-[:USES]->(Dependency) edges.
    file_imports: dict[str, list[str]] = Field(default_factory=dict)
    # Intraprocedural taint flows detected during AST parsing.
    taint_flows: list[TaintFlow] = []
