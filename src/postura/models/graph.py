"""Graph node/edge models and UID generation helpers."""


def make_service_uid(name: str) -> str:
    return f"svc:{name}"


def make_endpoint_uid(method: str, path: str) -> str:
    return f"ep:{method.upper()}:{path}"


def make_function_uid(module: str, qualified_name: str) -> str:
    return f"fn:{module}:{qualified_name}"


def make_datastore_uid(ds_type: str, name: str) -> str:
    return f"ds:{ds_type}:{name}"


def make_dependency_uid(name: str, version: str) -> str:
    return f"dep:{name}:{version}"


def make_finding_uid(tool: str, rule_id: str, file: str, line: int) -> str:
    # Normalize file path to be relative-friendly
    return f"find:{tool}:{rule_id}:{file}:{line}"


def make_trustzone_uid(name: str) -> str:
    return f"tz:{name}"


# Cypher parameter dict builders — convert structured data to Neo4j-ready dicts

def function_node_params(
    uid: str,
    name: str,
    qualified_name: str,
    file: str,
    line: int,
    end_line: int,
    module: str,
    is_entry_point: bool = False,
    handles_user_input: bool = False,
    decorators: list[str] | None = None,
) -> dict:
    return {
        "uid": uid,
        "name": name,
        "qualified_name": qualified_name,
        "file": file,
        "line": line,
        "end_line": end_line,
        "module": module,
        "is_entry_point": is_entry_point,
        "handles_user_input": handles_user_input,
        "decorators": decorators or [],
    }


def endpoint_node_params(
    uid: str,
    path: str,
    method: str,
    auth_required: bool,
    is_public: bool,
    framework: str,
    file: str,
    line: int,
    auth_type: str | None = None,
    input_params: list[str] | None = None,
) -> dict:
    return {
        "uid": uid,
        "path": path,
        "method": method,
        "auth_required": auth_required,
        "auth_type": auth_type or "none",
        "input_params": input_params or [],
        "is_public": is_public,
        "framework": framework,
        "file": file,
        "line": line,
    }


def finding_node_params(
    uid: str,
    finding_type: str,
    tool: str,
    rule_id: str,
    title: str,
    description: str,
    raw_severity: str,
    file: str,
    line: int,
    cwe_id: str | None = None,
    evidence: str | None = None,
) -> dict:
    return {
        "uid": uid,
        "type": finding_type,
        "tool": tool,
        "rule_id": rule_id,
        "cwe_id": cwe_id or "",
        "title": title,
        "description": description,
        "raw_severity": raw_severity,
        "contextual_severity": raw_severity,  # set by reasoning layer later
        "status": "open",
        "evidence": evidence or "",
        "file": file,
        "line": line,
    }


def datastore_node_params(
    uid: str,
    name: str,
    ds_type: str,
    contains_pii: bool = False,
) -> dict:
    return {
        "uid": uid,
        "name": name,
        "type": ds_type,
        "contains_pii": contains_pii,
    }


def dependency_node_params(
    uid: str,
    name: str,
    version: str,
    pinned: bool,
    depth: int = 0,
    known_cves: list[str] | None = None,
) -> dict:
    return {
        "uid": uid,
        "name": name,
        "version": version,
        "pinned": pinned,
        "depth": depth,
        "known_cves": known_cves or [],
    }


def trustzone_node_params(
    uid: str,
    name: str,
    level: int,
    auth_mechanism: str | None = None,
) -> dict:
    return {
        "uid": uid,
        "name": name,
        "level": level,
        "auth_mechanism": auth_mechanism or "",
    }
