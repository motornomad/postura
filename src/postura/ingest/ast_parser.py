"""Tree-sitter based Python AST parser.

Extracts:
- Function/method definitions (ASTNode)
- Class definitions (with methods)
- Import statements (for call resolution)
- Function calls (CallEdge)

Call resolution uses a tiered approach:
  1. Local scope (function defined in same file)
  2. Import resolution (from X import Y → X.Y)
  3. Attribute access (self.method → ClassName.method)
  4. Unresolved → placeholder qualified name (keeps the edge, conservative)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node

from postura.models.ingest import ASTNode, CallEdge, DataAccessEvent

PY_LANGUAGE = Language(tspython.language())
_parser = Parser(PY_LANGUAGE)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_file(
    file_path: str, repo_root: str = ""
) -> tuple[list[ASTNode], list[CallEdge], list[DataAccessEvent], list[str]]:
    """Parse a Python file and return (ast_nodes, call_edges, data_accesses, imported_packages)."""
    path = Path(file_path)
    source_bytes = path.read_bytes()
    tree = _parser.parse(source_bytes)

    rel_path = str(Path(file_path).relative_to(repo_root)) if repo_root else file_path
    module = _path_to_module(rel_path)

    collector = _FileCollector(source_bytes, rel_path, module)
    collector.visit(tree.root_node)
    return collector.nodes, collector.call_edges, collector.data_accesses, collector.imports.top_level_packages()


def parse_directory(
    dir_path: str, repo_root: str = ""
) -> tuple[list[ASTNode], list[CallEdge], list[DataAccessEvent]]:
    """Recursively parse all .py files in a directory."""
    root = repo_root or dir_path
    all_nodes: list[ASTNode] = []
    all_edges: list[CallEdge] = []
    all_accesses: list[DataAccessEvent] = []
    for py_file in Path(dir_path).rglob("*.py"):
        nodes, edges, accesses, _pkgs = parse_file(str(py_file), root)
        all_nodes.extend(nodes)
        all_edges.extend(edges)
        all_accesses.extend(accesses)
    return all_nodes, all_edges, all_accesses


# ---------------------------------------------------------------------------
# DataStore detection patterns
# ---------------------------------------------------------------------------

# SQL keywords for read vs write classification
_SQL_READ = re.compile(r"\b(SELECT|FETCH|GET)\b", re.IGNORECASE)
_SQL_WRITE = re.compile(r"\b(INSERT|UPDATE|DELETE|REPLACE|TRUNCATE|DROP|CREATE)\b", re.IGNORECASE)

# Extract table name from SQL — handles common patterns
_SQL_FROM_TABLE = re.compile(r"\bFROM\s+[`\"']?(\w+)[`\"']?", re.IGNORECASE)
_SQL_INTO_TABLE = re.compile(r"\bINTO\s+[`\"']?(\w+)[`\"']?", re.IGNORECASE)
_SQL_UPDATE_TABLE = re.compile(r"\bUPDATE\s+[`\"']?(\w+)[`\"']?", re.IGNORECASE)
_SQL_DELETE_TABLE = re.compile(r"\bDELETE\s+FROM\s+[`\"']?(\w+)[`\"']?", re.IGNORECASE)

# Known DB call patterns: (obj_pattern, method_pattern, db_type, default_access)
_DB_CALL_PATTERNS: list[tuple[re.Pattern, re.Pattern, str, str]] = [
    # sqlite3 / psycopg2: cursor.execute(...)
    (re.compile(r"cursor|conn|connection", re.I), re.compile(r"^execute$", re.I), "sqlite", "read"),
    (re.compile(r"cursor|conn|connection", re.I), re.compile(r"^executemany$", re.I), "sqlite", "write"),
    # SQLAlchemy session
    (re.compile(r"session|db", re.I), re.compile(r"^(query|get|first|all|one)$", re.I), "sqlalchemy", "read"),
    (re.compile(r"session|db", re.I), re.compile(r"^(add|merge|flush|commit)$", re.I), "sqlalchemy", "write"),
    (re.compile(r"session|db", re.I), re.compile(r"^(delete|remove)$", re.I), "sqlalchemy", "write"),
    # Redis
    (re.compile(r"redis|cache|r\b", re.I), re.compile(r"^(get|hget|lrange|smembers|zrange|mget)$", re.I), "redis", "read"),
    (re.compile(r"redis|cache|r\b", re.I), re.compile(r"^(set|hset|lpush|rpush|sadd|zadd|mset|delete|expire)$", re.I), "redis", "write"),
    # filesystem
    (re.compile(r".*", re.I), re.compile(r"^open$", re.I), "filesystem", "read"),
]

_PII_KEYWORDS = frozenset({
    "user", "users", "account", "accounts", "profile", "profiles",
    "email", "emails", "password", "passwords", "credentials",
    "payment", "payments", "card", "cards", "ssn", "address",
    "addresses", "phone", "personal", "pii", "customer", "customers",
})


def _is_pii_datastore(name: str) -> bool:
    return any(kw in name.lower() for kw in _PII_KEYWORDS)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _path_to_module(rel_path: str) -> str:
    p = rel_path.replace("\\", "/")
    if p.endswith(".py"):
        p = p[:-3]
    if p.endswith("/__init__"):
        p = p[:-9]
    return p.replace("/", ".")


def _node_text(node: Node, source_bytes: bytes) -> str:
    """Extract text for a node using byte offsets into the original source bytes."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _get_docstring(body_node: Node, source_bytes: bytes) -> Optional[str]:
    for child in body_node.children:
        if child.type == "expression_statement":
            for grandchild in child.children:
                if grandchild.type in ("string", "concatenated_string"):
                    raw = _node_text(grandchild, source_bytes).strip()
                    if raw.startswith('"""') or raw.startswith("'''"):
                        return raw[3:-3].strip()
                    if raw.startswith('"') or raw.startswith("'"):
                        return raw[1:-1].strip()
        break
    return None


# ---------------------------------------------------------------------------
# Import map
# ---------------------------------------------------------------------------

class _ImportMap:
    def __init__(self) -> None:
        self._map: dict[str, str] = {}       # local_name → qualified name
        self._modules: dict[str, str] = {}   # alias → module

    def add_import(self, module: str, alias: str | None = None) -> None:
        key = alias or module.split(".")[0]
        self._modules[key] = module

    def add_from_import(self, module: str, name: str, alias: str | None = None) -> None:
        key = alias or name
        self._map[key] = f"{module}.{name}"

    def resolve(self, name: str) -> str | None:
        if name in self._map:
            return self._map[name]
        if name in self._modules:
            return self._modules[name]
        return None

    def resolve_attribute(self, obj: str, attr: str) -> str | None:
        if obj in self._modules:
            return f"{self._modules[obj]}.{attr}"
        if obj in self._map:
            return f"{self._map[obj]}.{attr}"
        return None

    def top_level_packages(self) -> list[str]:
        """Return deduplicated top-level package names seen in all import statements."""
        pkgs: set[str] = set()
        for module in self._modules.values():
            pkgs.add(module.split(".")[0])
        for qualified in self._map.values():
            pkgs.add(qualified.split(".")[0])
        return sorted(pkgs)


# ---------------------------------------------------------------------------
# Main file collector
# ---------------------------------------------------------------------------

class _FileCollector:
    def __init__(self, source_bytes: bytes, file: str, module: str) -> None:
        self.src = source_bytes
        self.file = file
        self.module = module
        self.nodes: list[ASTNode] = []
        self.call_edges: list[CallEdge] = []
        self.data_accesses: list[DataAccessEvent] = []
        self.imports = _ImportMap()
        self._class_stack: list[str] = []   # stack of qualified class names
        self._func_stack: list[str] = []    # stack of current function qualified names
        self._local_funcs: set[str] = set() # all functions in this file

    def visit(self, node: Node) -> None:
        self._collect_imports(node)
        self._visit_node(node)

    def _collect_imports(self, node: Node) -> None:
        if node.type == "import_statement":
            self._handle_import(node)
        elif node.type == "import_from_statement":
            self._handle_from_import(node)
        for child in node.children:
            self._collect_imports(child)

    def _visit_node(self, node: Node) -> None:
        for child in node.children:
            if child.type == "class_definition":
                self._handle_class(child)
            elif child.type == "decorated_definition":
                self._handle_decorated(child)
            elif child.type == "function_definition":
                self._handle_function(child, decorators=[])
            elif child.type not in ("import_statement", "import_from_statement"):
                self._visit_node(child)

    # ------------------------------------------------------------------
    # Import handlers
    # ------------------------------------------------------------------

    def _handle_import(self, node: Node) -> None:
        # import X [as Y]
        children = [c for c in node.children if c.type not in ("import", ",")]
        i = 0
        while i < len(children):
            c = children[i]
            module = _node_text(c, self.src)
            if i + 1 < len(children) and children[i + 1].type == "as":
                alias = _node_text(children[i + 2], self.src) if i + 2 < len(children) else None
                self.imports.add_import(module, alias)
                i += 3
            else:
                self.imports.add_import(module)
                i += 1

    def _handle_from_import(self, node: Node) -> None:
        # from X import Y [as Z], ...
        children = node.children
        module = ""
        idx = 0
        # skip "from"
        while idx < len(children) and children[idx].type == "from":
            idx += 1
        # get module
        if idx < len(children) and children[idx].type in ("dotted_name", "relative_import", "identifier"):
            module = _node_text(children[idx], self.src)
            idx += 1
        # skip "import"
        while idx < len(children) and children[idx].type == "import":
            idx += 1

        while idx < len(children):
            child = children[idx]
            if child.type == "aliased_import":
                subs = [c for c in child.children if c.type not in ("as",)]
                name = _node_text(subs[0], self.src)
                alias = _node_text(subs[-1], self.src) if len(subs) > 1 else name
                self.imports.add_from_import(module, name, alias)
            elif child.type in ("identifier", "dotted_name"):
                name = _node_text(child, self.src)
                self.imports.add_from_import(module, name)
            elif child.type == "wildcard_import":
                pass
            idx += 1

    # ------------------------------------------------------------------
    # Class / Function handlers
    # ------------------------------------------------------------------

    def _handle_class(self, node: Node) -> None:
        name_node = node.child_by_field_name("name")
        if not name_node:
            return
        class_name = _node_text(name_node, self.src)
        if self._class_stack:
            qualified = f"{self._class_stack[-1]}.{class_name}"
        else:
            qualified = f"{self.module}.{class_name}"
        self._class_stack.append(qualified)

        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                if child.type == "decorated_definition":
                    self._handle_decorated(child)
                elif child.type == "function_definition":
                    self._handle_function(child, decorators=[])
                elif child.type == "class_definition":
                    self._handle_class(child)

        self._class_stack.pop()

    def _handle_decorated(self, node: Node) -> None:
        decorators: list[str] = []
        inner = None
        for child in node.children:
            if child.type == "decorator":
                decorators.append(self._decorator_name(child))
            elif child.type == "function_definition":
                inner = child
            elif child.type == "class_definition":
                self._handle_class(child)
                return
        if inner:
            self._handle_function(inner, decorators=decorators)

    def _handle_function(self, node: Node, decorators: list[str]) -> None:
        name_node = node.child_by_field_name("name")
        if not name_node:
            return
        name = _node_text(name_node, self.src)

        # Build qualified name
        if self._class_stack:
            qualified_name = f"{self._class_stack[-1]}.{name}"
        else:
            qualified_name = f"{self.module}.{name}"

        # Parameters
        params_node = node.child_by_field_name("parameters")
        parameters = self._extract_params(params_node) if params_node else []

        # Return type annotation
        ret_node = node.child_by_field_name("return_type")
        return_type = _node_text(ret_node, self.src).lstrip("->").strip() if ret_node else None

        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1

        body = node.child_by_field_name("body")
        docstring = _get_docstring(body, self.src) if body else None

        node_type = "method" if self._class_stack else "function"

        ast_node = ASTNode(
            name=name,
            qualified_name=qualified_name,
            node_type=node_type,
            file=self.file,
            line=start_line,
            end_line=end_line,
            module=self.module,
            decorators=decorators,
            parameters=parameters,
            return_type=return_type,
            docstring=docstring,
        )
        self.nodes.append(ast_node)
        self._local_funcs.add(qualified_name)

        # Collect calls from the function body
        self._func_stack.append(qualified_name)
        if body:
            self._collect_calls(body, qualified_name)
            # Handle nested function definitions
            for child in body.children:
                if child.type == "decorated_definition":
                    self._handle_decorated(child)
                elif child.type == "function_definition":
                    self._handle_function(child, decorators=[])
        self._func_stack.pop()

    def _decorator_name(self, node: Node) -> str:
        """Return decorator name as a string like 'app.route' or 'login_required'."""
        # The decorator node: @<expression>
        # children[0] = '@', children[1] = expression
        expr = None
        for child in node.children:
            if child.type not in ("@",):
                expr = child
                break
        if expr is None:
            return _node_text(node, self.src).lstrip("@").split("(")[0].strip()

        if expr.type == "call":
            func = expr.child_by_field_name("function")
            return _node_text(func, self.src) if func else _node_text(expr, self.src).split("(")[0]
        return _node_text(expr, self.src)

    def _extract_params(self, node: Node) -> list[str]:
        params = []
        for child in node.children:
            if child.type == "identifier":
                name = _node_text(child, self.src)
                if name not in ("self", "cls"):
                    params.append(name)
            elif child.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
                if child.children:
                    name = _node_text(child.children[0], self.src)
                    if name not in ("self", "cls", "*", "**"):
                        params.append(name)
        return params

    # ------------------------------------------------------------------
    # Call collection
    # ------------------------------------------------------------------

    def _collect_calls(self, node: Node, caller: str) -> None:
        if node.type == "call":
            callee = self._resolve_call(node)
            if callee:
                self.call_edges.append(CallEdge(
                    caller=caller,
                    callee=callee,
                    file=self.file,
                    line=node.start_point[0] + 1,
                ))
            # DataStore detection
            self._detect_data_access(node, caller)
            # Still recurse into arguments
            args = node.child_by_field_name("arguments")
            if args:
                self._collect_calls(args, caller)
        else:
            for child in node.children:
                if child.type not in ("function_definition", "decorated_definition"):
                    self._collect_calls(child, caller)

    def _detect_data_access(self, call_node: Node, caller: str) -> None:
        """Detect if this call is a database/filesystem access and record it."""
        func_node = call_node.child_by_field_name("function")
        if not func_node or func_node.type != "attribute":
            # Check for bare open() call
            if func_node and func_node.type == "identifier":
                name = _node_text(func_node, self.src)
                if name == "open":
                    args = call_node.child_by_field_name("arguments")
                    filename = self._extract_first_string_arg(args) or "file"
                    self.data_accesses.append(DataAccessEvent(
                        function_qualified_name=caller,
                        datastore_name=filename,
                        datastore_type="filesystem",
                        access_type="read",
                        file=self.file,
                        line=call_node.start_point[0] + 1,
                    ))
            return

        obj_node = func_node.child_by_field_name("object")
        attr_node = func_node.child_by_field_name("attribute")
        if not obj_node or not attr_node:
            return

        obj = _node_text(obj_node, self.src)
        method = _node_text(attr_node, self.src)
        line = call_node.start_point[0] + 1

        for obj_pat, method_pat, db_type, default_access in _DB_CALL_PATTERNS:
            if obj_pat.search(obj) and method_pat.match(method):
                args = call_node.child_by_field_name("arguments")
                sql_str = self._extract_first_string_arg(args)
                datastore_name, access_type = self._classify_sql_access(
                    sql_str, method, db_type, default_access
                )
                self.data_accesses.append(DataAccessEvent(
                    function_qualified_name=caller,
                    datastore_name=datastore_name,
                    datastore_type=db_type,
                    access_type=access_type,
                    file=self.file,
                    line=line,
                    raw_query=sql_str,
                ))
                break

    def _classify_sql_access(
        self, sql: str | None, method: str, db_type: str, default_access: str
    ) -> tuple[str, str]:
        """Return (datastore_name, access_type) from an SQL string."""
        if sql is None:
            return db_type, default_access

        # Determine access type from SQL keywords
        if _SQL_READ.search(sql):
            access_type = "read"
        elif _SQL_WRITE.search(sql):
            access_type = "write"
        else:
            access_type = default_access

        # Extract table name
        for pattern in (_SQL_FROM_TABLE, _SQL_INTO_TABLE, _SQL_UPDATE_TABLE, _SQL_DELETE_TABLE):
            m = pattern.search(sql)
            if m:
                return m.group(1), access_type

        return db_type, access_type

    def _extract_first_string_arg(self, args_node: Node | None) -> str | None:
        """Extract the value of the first string literal argument."""
        if not args_node:
            return None
        for child in args_node.children:
            if child.type == "string":
                raw = _node_text(child, self.src).strip()
                for q in ('"""', "'''", '"', "'"):
                    if raw.startswith(q) and raw.endswith(q) and len(raw) >= 2 * len(q):
                        return raw[len(q):-len(q)]
                return raw
            elif child.type == "concatenated_string":
                return _node_text(child, self.src)
        return None

    def _resolve_call(self, call_node: Node) -> str | None:
        func_node = call_node.child_by_field_name("function")
        if not func_node:
            return None

        if func_node.type == "identifier":
            name = _node_text(func_node, self.src)
            # 1. Local
            local = f"{self.module}.{name}"
            if local in self._local_funcs:
                return local
            # Check class method
            if self._class_stack:
                cls_candidate = f"{self._class_stack[-1]}.{name}"
                if cls_candidate in self._local_funcs:
                    return cls_candidate
            # 2. Import
            resolved = self.imports.resolve(name)
            if resolved:
                return resolved
            # 3. Unresolved
            return f"unresolved.{name}"

        elif func_node.type == "attribute":
            obj_node = func_node.child_by_field_name("object")
            attr_node = func_node.child_by_field_name("attribute")
            if not obj_node or not attr_node:
                return None
            obj = _node_text(obj_node, self.src)
            attr = _node_text(attr_node, self.src)

            # self.method
            if obj == "self" and self._class_stack:
                candidate = f"{self._class_stack[-1]}.{attr}"
                return candidate

            # module.func
            resolved = self.imports.resolve_attribute(obj, attr)
            if resolved:
                return resolved

            return f"unresolved.{obj}.{attr}"

        return None
