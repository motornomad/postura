"""Neo4j schema initialization — constraints and indexes."""
from postura.graph.connection import run_write

CONSTRAINTS = [
    "CREATE CONSTRAINT unique_service_uid IF NOT EXISTS FOR (s:Service) REQUIRE s.uid IS UNIQUE",
    "CREATE CONSTRAINT unique_endpoint_uid IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.uid IS UNIQUE",
    "CREATE CONSTRAINT unique_function_uid IF NOT EXISTS FOR (f:Function) REQUIRE f.uid IS UNIQUE",
    "CREATE CONSTRAINT unique_datastore_uid IF NOT EXISTS FOR (d:DataStore) REQUIRE d.uid IS UNIQUE",
    "CREATE CONSTRAINT unique_dependency_uid IF NOT EXISTS FOR (d:Dependency) REQUIRE d.uid IS UNIQUE",
    "CREATE CONSTRAINT unique_finding_uid IF NOT EXISTS FOR (f:Finding) REQUIRE f.uid IS UNIQUE",
    "CREATE CONSTRAINT unique_trustzone_uid IF NOT EXISTS FOR (t:TrustZone) REQUIRE t.uid IS UNIQUE",
]

INDEXES = [
    "CREATE INDEX idx_function_file IF NOT EXISTS FOR (f:Function) ON (f.file)",
    "CREATE INDEX idx_function_module IF NOT EXISTS FOR (f:Function) ON (f.module)",
    "CREATE INDEX idx_finding_status IF NOT EXISTS FOR (f:Finding) ON (f.status)",
    "CREATE INDEX idx_finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.contextual_severity)",
    "CREATE INDEX idx_finding_cwe IF NOT EXISTS FOR (f:Finding) ON (f.cwe_id)",
    "CREATE INDEX idx_endpoint_public IF NOT EXISTS FOR (e:Endpoint) ON (e.is_public)",
    "CREATE INDEX idx_dependency_name IF NOT EXISTS FOR (d:Dependency) ON (d.name)",
]


def init_schema() -> None:
    """Create all constraints and indexes. Idempotent — safe to call multiple times."""
    for stmt in CONSTRAINTS:
        run_write(stmt)
    for stmt in INDEXES:
        run_write(stmt)


def drop_all_data() -> None:
    """Delete all nodes and relationships. Use only in tests."""
    run_write("MATCH (n) DETACH DELETE n")
