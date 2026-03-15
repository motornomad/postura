"""Graph builder — constructs Neo4j nodes and edges from StructuredIngestResult.

Handles:
- Function nodes + CALLS edges (P1.6a)
- Finding nodes + AFFECTS edges (P1.6b)
- Endpoint nodes + HANDLED_BY edges (P1.6c)
- DataStore nodes + READS_FROM/WRITES_TO edges (P2.1)
- TrustZone nodes + IN_ZONE edges (P2.2)
- Service node + BELONGS_TO edges (P2.2b)
- Dependency nodes + USES edges (P2.3b)
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from postura.graph.connection import run_write, run_query
from postura.models.ingest import (
    ASTNode, CallEdge, SASTFinding, DepVulnerability,
    EndpointInfo, ConfigIssue, StructuredIngestResult, DataAccessEvent,
)
from postura.models.graph import (
    make_function_uid, make_endpoint_uid, make_finding_uid,
    make_datastore_uid, make_dependency_uid, make_trustzone_uid,
    make_service_uid,
    function_node_params, endpoint_node_params, finding_node_params,
    datastore_node_params, dependency_node_params, trustzone_node_params,
)
from postura.ingest.dep_scanner import parse_requirements_txt
from postura.ingest.ast_parser import _is_pii_datastore

logger = logging.getLogger(__name__)

# Auth decorator patterns
_AUTH_DEC_PATTERNS = re.compile(
    r"login_required|auth_required|requires_auth|admin_only|jwt_required|token_required",
    re.IGNORECASE,
)

# Paths that are intentionally public — skip CWE-306 for these
_INTENTIONALLY_PUBLIC_PATHS = re.compile(
    r"^/(health|ping|status|metrics|favicon"
    r"|api/auth/|auth/|login|logout|register|signup|reset-password|verify)",
    re.IGNORECASE,
)

# PII heuristic: table/variable names that suggest personal data
_PII_KEYWORDS = {
    "user", "users", "email", "emails", "password", "passwords",
    "profile", "profiles", "payment", "payments", "ssn", "address",
    "addresses", "credit_card", "phone", "dob", "date_of_birth",
    "personal", "pii",
}

# DataStore type detection from call patterns
_DB_CALL_PATTERNS = {
    "sqlite3": re.compile(r"sqlite3\.(connect|cursor|execute)", re.IGNORECASE),
    "psycopg2": re.compile(r"psycopg2\.(connect|cursor)", re.IGNORECASE),
    "sqlalchemy": re.compile(r"(session|db)\.(query|execute|add|commit|delete)", re.IGNORECASE),
    "redis": re.compile(r"redis\.(get|set|hget|hset|lpush|rpush)", re.IGNORECASE),
}

_SQL_READ_PATTERN = re.compile(r"\b(SELECT|GET|FETCH|READ)\b", re.IGNORECASE)
_SQL_WRITE_PATTERN = re.compile(r"\b(INSERT|UPDATE|DELETE|SET|CREATE|DROP)\b", re.IGNORECASE)


class GraphBuilder:
    """Builds or merges a full threat graph from a StructuredIngestResult."""

    def __init__(self, service_name: str = "app", repo_root: str = "") -> None:
        self.service_name = service_name
        self.repo_root = repo_root
        self._function_uid_map: dict[str, str] = {}  # qualified_name → uid

    def build(
        self,
        result: StructuredIngestResult,
        requirements_file: str = "",
        run_post_processing: bool = True,
    ) -> None:
        """Full graph build: all node/edge types.

        Args:
            result: Parsed ingest result to build from.
            requirements_file: Optional path to requirements.txt for dep scanning.
            run_post_processing: If True (default), runs chain discovery and
                contextual severity scoring after building. Set to False when
                called from updater.py since differ.py will run these anyway.
        """
        self._create_service_node()
        self._create_trustzones()
        self._create_function_nodes(result.ast_nodes)
        self._create_calls_edges(result.call_edges)
        self._create_endpoint_nodes(result.endpoints)
        self._create_datastore_nodes(result.data_accesses)
        self._create_sast_finding_nodes(result.sast_findings, result.ast_nodes)
        self._create_config_finding_nodes(result.config_issues)
        self._create_dependency_nodes(result.dep_vulnerabilities, requirements_file)
        self._create_uses_edges(result)

        if run_post_processing:
            from postura.reasoning.chain_discovery import discover_chains
            from postura.reasoning.severity_scorer import score_all_findings
            discover_chains()
            score_all_findings()

    # ------------------------------------------------------------------
    # Service node
    # ------------------------------------------------------------------

    def _create_service_node(self) -> None:
        uid = make_service_uid(self.service_name)
        run_write(
            """
            MERGE (s:Service {uid: $uid})
            SET s.name = $name, s.type = $type, s.exposure_level = $exposure_level,
                s.repo_path = $repo_path
            """,
            {
                "uid": uid,
                "name": self.service_name,
                "type": "monolith",
                "exposure_level": "public",
                "repo_path": self.repo_root,
            },
        )

    # ------------------------------------------------------------------
    # Trust zones
    # ------------------------------------------------------------------

    def _create_trustzones(self) -> None:
        zones = [
            ("public", 0, "none"),
            ("authenticated", 1, "session/jwt"),
            ("admin", 2, "admin role check"),
            ("system", 3, "internal only"),
        ]
        for name, level, auth_mechanism in zones:
            uid = make_trustzone_uid(name)
            params = trustzone_node_params(uid, name, level, auth_mechanism)
            run_write(
                """
                MERGE (t:TrustZone {uid: $uid})
                SET t.name = $name, t.level = $level, t.auth_mechanism = $auth_mechanism
                """,
                params,
            )

    # ------------------------------------------------------------------
    # Function nodes
    # ------------------------------------------------------------------

    def _create_function_nodes(self, ast_nodes: list[ASTNode]) -> None:
        if not ast_nodes:
            return

        batch = []
        for node in ast_nodes:
            uid = make_function_uid(node.module, node.qualified_name)
            self._function_uid_map[node.qualified_name] = uid

            is_entry = any(
                re.search(r"route|get|post|put|delete|patch", dec, re.IGNORECASE)
                for dec in node.decorators
            )
            handles_input = is_entry or bool(node.parameters)

            params = function_node_params(
                uid=uid,
                name=node.name,
                qualified_name=node.qualified_name,
                file=node.file,
                line=node.line,
                end_line=node.end_line,
                module=node.module,
                is_entry_point=is_entry,
                handles_user_input=handles_input,
                decorators=node.decorators,
            )
            batch.append(params)

        run_write(
            """
            UNWIND $batch AS p
            MERGE (f:Function {uid: p.uid})
            SET f.name = p.name, f.qualified_name = p.qualified_name,
                f.file = p.file, f.line = p.line, f.end_line = p.end_line,
                f.module = p.module, f.is_entry_point = p.is_entry_point,
                f.handles_user_input = p.handles_user_input, f.decorators = p.decorators
            """,
            {"batch": batch},
        )
        logger.info("Created/updated %d Function nodes", len(batch))

    # ------------------------------------------------------------------
    # CALLS edges
    # ------------------------------------------------------------------

    def _create_calls_edges(self, call_edges: list[CallEdge]) -> None:
        if not call_edges:
            return

        batch = []
        for edge in call_edges:
            caller_uid = self._function_uid_map.get(edge.caller)
            callee_uid = self._function_uid_map.get(edge.callee)

            if not caller_uid:
                continue  # caller function not in graph — skip

            if not callee_uid:
                # Create a placeholder node for unresolved callees
                if edge.callee.startswith("unresolved."):
                    short = edge.callee.replace("unresolved.", "")
                    callee_uid = f"fn:unresolved:{short}"
                    run_write(
                        """
                        MERGE (f:Function {uid: $uid})
                        SET f.name = $name, f.qualified_name = $qn,
                            f.file = '', f.line = 0, f.end_line = 0,
                            f.module = 'unresolved', f.is_entry_point = false,
                            f.handles_user_input = false, f.decorators = []
                        """,
                        {"uid": callee_uid, "name": short, "qn": edge.callee},
                    )
                else:
                    continue

            batch.append({"caller_uid": caller_uid, "callee_uid": callee_uid})

        if batch:
            run_write(
                """
                UNWIND $batch AS e
                MATCH (caller:Function {uid: e.caller_uid})
                MATCH (callee:Function {uid: e.callee_uid})
                MERGE (caller)-[:CALLS]->(callee)
                """,
                {"batch": batch},
            )
        logger.info("Created/updated %d CALLS edges", len(batch))

    # ------------------------------------------------------------------
    # Endpoint nodes + HANDLED_BY + BELONGS_TO + IN_ZONE
    # ------------------------------------------------------------------

    def _create_endpoint_nodes(self, endpoints: list[EndpointInfo]) -> None:
        if not endpoints:
            return

        service_uid = make_service_uid(self.service_name)

        for ep in endpoints:
            uid = make_endpoint_uid(ep.method, ep.path)
            is_public = not ep.auth_required

            params = endpoint_node_params(
                uid=uid,
                path=ep.path,
                method=ep.method,
                auth_required=ep.auth_required,
                is_public=is_public,
                framework=ep.framework,
                file=ep.file,
                line=ep.line,
                auth_type=ep.auth_type,
                input_params=ep.input_params,
            )
            run_write(
                """
                MERGE (e:Endpoint {uid: $uid})
                SET e.path = $path, e.method = $method, e.auth_required = $auth_required,
                    e.auth_type = $auth_type, e.input_params = $input_params,
                    e.is_public = $is_public, e.framework = $framework,
                    e.file = $file, e.line = $line
                """,
                params,
            )

            # BELONGS_TO Service
            run_write(
                """
                MATCH (e:Endpoint {uid: $ep_uid})
                MATCH (s:Service {uid: $svc_uid})
                MERGE (e)-[:BELONGS_TO]->(s)
                """,
                {"ep_uid": uid, "svc_uid": service_uid},
            )

            # HANDLED_BY Function
            handler_uid = self._function_uid_map.get(ep.handler_function)
            if handler_uid:
                run_write(
                    """
                    MATCH (e:Endpoint {uid: $ep_uid})
                    MATCH (f:Function {uid: $fn_uid})
                    MERGE (e)-[:HANDLED_BY]->(f)
                    """,
                    {"ep_uid": uid, "fn_uid": handler_uid},
                )

            # IN_ZONE TrustZone
            zone_name = self._infer_trust_zone(ep)
            zone_uid = make_trustzone_uid(zone_name)
            run_write(
                """
                MATCH (e:Endpoint {uid: $ep_uid})
                MATCH (t:TrustZone {uid: $tz_uid})
                MERGE (e)-[:IN_ZONE]->(t)
                """,
                {"ep_uid": uid, "tz_uid": zone_uid},
            )

            # CWE-306: create a missing-auth finding for public unauthenticated endpoints
            # Skip paths that are intentionally public (health checks, auth endpoints)
            if is_public and not ep.auth_required and not _INTENTIONALLY_PUBLIC_PATHS.match(ep.path):
                self._create_missing_auth_finding(uid, ep)

        logger.info("Created/updated %d Endpoint nodes", len(endpoints))

    def _create_missing_auth_finding(self, ep_uid: str, ep: "EndpointInfo") -> None:
        """Create a CWE-306 Missing Authentication finding and link it to the handler function."""
        f_uid = make_finding_uid("postura", "CWE-306", ep.file, ep.line)
        params = finding_node_params(
            uid=f_uid,
            finding_type="sast",
            tool="postura",
            rule_id="CWE-306",
            title="Missing Authentication on Public Endpoint",
            description=(
                f"Endpoint {ep.method} {ep.path} is publicly accessible with no "
                "authentication requirement. Any unauthenticated caller can invoke it."
            ),
            raw_severity="HIGH",
            file=ep.file,
            line=ep.line,
            cwe_id="CWE-306",
        )
        run_write(
            """
            MERGE (f:Finding {uid: $uid})
            SET f.type = $type, f.tool = $tool, f.rule_id = $rule_id,
                f.cwe_id = $cwe_id, f.title = $title, f.description = $description,
                f.raw_severity = $raw_severity, f.contextual_severity = $contextual_severity,
                f.status = $status, f.evidence = $evidence,
                f.file = $file, f.line = $line
            """,
            params,
        )
        # AFFECTS the handler function (not the endpoint) — matches GROUND_TRUTH F2
        handler_uid = self._function_uid_map.get(ep.handler_function)
        if handler_uid:
            run_write(
                """
                MATCH (finding:Finding {uid: $f_uid})
                MATCH (fn:Function {uid: $fn_uid})
                MERGE (finding)-[:AFFECTS]->(fn)
                """,
                {"f_uid": f_uid, "fn_uid": handler_uid},
            )

    def _infer_trust_zone(self, ep: EndpointInfo) -> str:
        """Infer trust zone from path and auth status."""
        path_lower = ep.path.lower()
        file_lower = ep.file.lower()

        if "admin" in path_lower or "admin" in file_lower:
            return "admin"
        if ep.auth_required:
            return "authenticated"
        if "internal" in path_lower or "system" in path_lower:
            return "system"
        return "public"

    # ------------------------------------------------------------------
    # DataStore nodes + READS_FROM / WRITES_TO edges  (P2.1)
    # ------------------------------------------------------------------

    def _create_datastore_nodes(self, data_accesses: list[DataAccessEvent]) -> None:
        if not data_accesses:
            return

        # Deduplicate datastores: (type, name) → DataAccessEvent as representative
        seen: dict[tuple[str, str], bool] = {}

        for access in data_accesses:
            ds_key = (access.datastore_type, access.datastore_name)
            contains_pii = _is_pii_datastore(access.datastore_name)

            if ds_key not in seen:
                seen[ds_key] = contains_pii
                uid = make_datastore_uid(access.datastore_type, access.datastore_name)
                params = datastore_node_params(
                    uid=uid,
                    name=access.datastore_name,
                    ds_type=access.datastore_type,
                    contains_pii=contains_pii,
                )
                run_write(
                    """
                    MERGE (d:DataStore {uid: $uid})
                    SET d.name = $name, d.type = $type, d.contains_pii = $contains_pii
                    """,
                    params,
                )

            # Create READS_FROM or WRITES_TO edge from Function → DataStore
            fn_uid = self._function_uid_map.get(access.function_qualified_name)
            if not fn_uid:
                continue

            ds_uid = make_datastore_uid(access.datastore_type, access.datastore_name)
            edge_type = "READS_FROM" if access.access_type == "read" else "WRITES_TO"
            query_type = access.access_type

            run_write(
                f"""
                MATCH (f:Function {{uid: $fn_uid}})
                MATCH (d:DataStore {{uid: $ds_uid}})
                MERGE (f)-[r:{edge_type}]->(d)
                SET r.query_type = $query_type
                """,
                {"fn_uid": fn_uid, "ds_uid": ds_uid, "query_type": query_type},
            )

        logger.info(
            "Created/updated %d DataStore nodes from %d access events",
            len(seen), len(data_accesses),
        )

    # ------------------------------------------------------------------
    # SAST Finding nodes + AFFECTS edges
    # ------------------------------------------------------------------

    def _create_sast_finding_nodes(
        self, findings: list[SASTFinding], ast_nodes: list[ASTNode]
    ) -> None:
        if not findings:
            return

        # Build a lookup: file → sorted list of (line, end_line, uid)
        func_ranges: dict[str, list[tuple[int, int, str]]] = {}
        for node in ast_nodes:
            uid = make_function_uid(node.module, node.qualified_name)
            func_ranges.setdefault(node.file, []).append((node.line, node.end_line, uid))

        for finding in findings:
            uid = make_finding_uid(finding.tool, finding.rule_id, finding.file, finding.line)
            params = finding_node_params(
                uid=uid,
                finding_type="sast",
                tool=finding.tool,
                rule_id=finding.rule_id,
                title=finding.title,
                description=finding.description,
                raw_severity=finding.severity.value,
                file=finding.file,
                line=finding.line,
                cwe_id=finding.cwe_id,
                evidence=finding.code_snippet,
            )
            run_write(
                """
                MERGE (f:Finding {uid: $uid})
                SET f.type = $type, f.tool = $tool, f.rule_id = $rule_id,
                    f.cwe_id = $cwe_id, f.title = $title, f.description = $description,
                    f.raw_severity = $raw_severity, f.contextual_severity = $contextual_severity,
                    f.status = $status, f.evidence = $evidence,
                    f.file = $file, f.line = $line
                """,
                params,
            )

            # AFFECTS: link finding to functions that contain this line
            affected_uid = self._find_containing_function(
                finding.file, finding.line, func_ranges
            )
            if affected_uid:
                run_write(
                    """
                    MATCH (finding:Finding {uid: $f_uid})
                    MATCH (func:Function {uid: $fn_uid})
                    MERGE (finding)-[:AFFECTS]->(func)
                    """,
                    {"f_uid": uid, "fn_uid": affected_uid},
                )

        logger.info("Created/updated %d SAST Finding nodes", len(findings))

    def _find_containing_function(
        self,
        file: str,
        line: int,
        func_ranges: dict[str, list[tuple[int, int, str]]],
    ) -> str | None:
        """Find the function UID that contains the given file:line."""
        for fn_file, ranges in func_ranges.items():
            # Try exact file match, then basename match
            if fn_file == file or Path(fn_file).name == Path(file).name:
                best = None
                best_span = float("inf")
                for start, end, uid in ranges:
                    if start <= line <= end:
                        span = end - start
                        if span < best_span:
                            best_span = span
                            best = uid
                if best:
                    return best
        return None

    # ------------------------------------------------------------------
    # Config issue Finding nodes
    # ------------------------------------------------------------------

    def _create_config_finding_nodes(self, issues: list[ConfigIssue]) -> None:
        if not issues:
            return

        for issue in issues:
            line = issue.line or 0
            uid = make_finding_uid("config_analyzer", issue.issue_type, issue.file, line)
            params = finding_node_params(
                uid=uid,
                finding_type="config",
                tool="config_analyzer",
                rule_id=issue.issue_type,
                title=issue.issue_type.replace("_", " ").title(),
                description=issue.description,
                raw_severity=issue.severity.value,
                file=issue.file,
                line=line,
                evidence=issue.evidence,
            )
            run_write(
                """
                MERGE (f:Finding {uid: $uid})
                SET f.type = $type, f.tool = $tool, f.rule_id = $rule_id,
                    f.cwe_id = $cwe_id, f.title = $title, f.description = $description,
                    f.raw_severity = $raw_severity, f.contextual_severity = $contextual_severity,
                    f.status = $status, f.evidence = $evidence,
                    f.file = $file, f.line = $line
                """,
                params,
            )

        logger.info("Created/updated %d config Finding nodes", len(issues))

    # ------------------------------------------------------------------
    # Dependency nodes + USES edges + CVE Finding nodes
    # ------------------------------------------------------------------

    def _create_dependency_nodes(
        self, dep_vulns: list[DepVulnerability], requirements_file: str
    ) -> None:
        # Parse requirements to get all dependencies (not just vulnerable ones)
        all_deps = parse_requirements_txt(requirements_file) if requirements_file else []

        vuln_map: dict[str, list[DepVulnerability]] = {}
        for vuln in dep_vulns:
            vuln_map.setdefault(vuln.package_name.lower(), []).append(vuln)

        for name, version, pinned in all_deps:
            known_cves = [v.cve_id for v in vuln_map.get(name.lower(), [])]
            uid = make_dependency_uid(name, version)
            params = dependency_node_params(uid, name, version, pinned, depth=0, known_cves=known_cves)
            run_write(
                """
                MERGE (d:Dependency {uid: $uid})
                SET d.name = $name, d.version = $version, d.pinned = $pinned,
                    d.depth = $depth, d.known_cves = $known_cves
                """,
                params,
            )

            # Create CVE Finding nodes for vulnerable deps
            for vuln in vuln_map.get(name.lower(), []):
                f_uid = make_finding_uid("pip-audit", vuln.cve_id, name, 0)
                f_params = finding_node_params(
                    uid=f_uid,
                    finding_type="dependency",
                    tool="pip-audit",
                    rule_id=vuln.cve_id,
                    title=f"{vuln.cve_id} in {name}",
                    description=vuln.description,
                    raw_severity=vuln.severity.value,
                    file=requirements_file or name,
                    line=0,
                    cwe_id=None,
                )
                run_write(
                    """
                    MERGE (f:Finding {uid: $uid})
                    SET f.type = $type, f.tool = $tool, f.rule_id = $rule_id,
                        f.cwe_id = $cwe_id, f.title = $title, f.description = $description,
                        f.raw_severity = $raw_severity, f.contextual_severity = $contextual_severity,
                        f.status = $status, f.evidence = $evidence,
                        f.file = $file, f.line = $line
                    """,
                    f_params,
                )
                # AFFECTS the Dependency node
                run_write(
                    """
                    MATCH (finding:Finding {uid: $f_uid})
                    MATCH (dep:Dependency {uid: $dep_uid})
                    MERGE (finding)-[:AFFECTS]->(dep)
                    """,
                    {"f_uid": f_uid, "dep_uid": uid},
                )

        logger.info("Created/updated %d Dependency nodes", len(all_deps))

    # ------------------------------------------------------------------
    # USES edges (Function → Dependency)  — Gap 1 fix
    # ------------------------------------------------------------------

    def _create_uses_edges(self, result: StructuredIngestResult) -> None:
        """Create (Function)-[:USES {via_import}]->(Dependency) edges from file_imports."""
        if not result.file_imports:
            return

        # Fetch all known dependency names from the graph (case-insensitive lookup)
        dep_rows = run_query("MATCH (d:Dependency) RETURN d.name AS name, d.uid AS uid")
        dep_lookup: dict[str, str] = {
            r["name"].lower(): r["uid"] for r in dep_rows if r.get("name")
        }
        if not dep_lookup:
            return

        # Build file → list of function UIDs from what we just created
        file_to_fn_uids: dict[str, list[str]] = {}
        for node in result.ast_nodes:
            fn_uid = self._function_uid_map.get(node.qualified_name)
            if fn_uid:
                file_to_fn_uids.setdefault(node.file, []).append(fn_uid)

        edges: list[dict] = []
        for file, imported_pkgs in result.file_imports.items():
            fn_uids = file_to_fn_uids.get(file, [])
            if not fn_uids:
                continue
            for pkg in imported_pkgs:
                dep_uid = dep_lookup.get(pkg.lower())
                if not dep_uid:
                    continue
                for fn_uid in fn_uids:
                    edges.append({"fn_uid": fn_uid, "dep_uid": dep_uid, "pkg": pkg})

        if edges:
            run_write(
                """
                UNWIND $edges AS e
                MATCH (f:Function {uid: e.fn_uid})
                MATCH (d:Dependency {uid: e.dep_uid})
                MERGE (f)-[r:USES]->(d)
                SET r.via_import = e.pkg
                """,
                {"edges": edges},
            )
        logger.info("Created/updated %d USES edges (Function → Dependency)", len(edges))


def build_graph_from_result(
    result: StructuredIngestResult,
    service_name: str = "app",
    repo_root: str = "",
    requirements_file: str = "",
) -> None:
    """Convenience function: build the full graph from a StructuredIngestResult."""
    builder = GraphBuilder(service_name=service_name, repo_root=repo_root)
    builder.build(result, requirements_file=requirements_file)
