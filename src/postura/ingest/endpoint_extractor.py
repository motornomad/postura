"""Framework-aware HTTP endpoint extractor.

Detects Flask and FastAPI route decorators and extracts:
- path, method, handler function, auth decorators
- Sets auth_required, auth_type, is_public
"""
from __future__ import annotations

import re
from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node

from postura.models.ingest import EndpointInfo

PY_LANGUAGE = Language(tspython.language())
_parser = Parser(PY_LANGUAGE)

_METHOD_SHORTCUTS = {"get", "post", "put", "delete", "patch", "head", "options"}

_AUTH_DECORATOR_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"login_required",
        r"auth_required",
        r"require_auth",
        r"requires_auth",
        r"admin_only",
        r"permission_required",
        r"protect",
        r"authenticated",
        r"jwt_required",
        r"token_required",
    ]
]

_FASTAPI_DEPENDS_AUTH_PATTERN = re.compile(
    r"Depends\s*\(\s*(get_current_user|verify_token|authenticate|oauth2_scheme|security)",
    re.IGNORECASE,
)


def extract_endpoints(file_path: str, module: str, repo_root: str = "") -> list[EndpointInfo]:
    path = Path(file_path)
    source_bytes = path.read_bytes()
    tree = _parser.parse(source_bytes)
    rel_path = str(Path(file_path).relative_to(repo_root)) if repo_root else file_path

    extractor = _EndpointExtractor(source_bytes, rel_path, module)
    extractor.visit(tree.root_node)
    return extractor.endpoints


def extract_endpoints_from_directory(dir_path: str, repo_root: str = "") -> list[EndpointInfo]:
    root = repo_root or dir_path
    all_endpoints: list[EndpointInfo] = []
    for py_file in Path(dir_path).rglob("*.py"):
        rel = str(py_file.relative_to(root))
        module = rel.replace("/", ".").replace("\\", ".")
        if module.endswith(".py"):
            module = module[:-3]
        eps = extract_endpoints(str(py_file), module, root)
        all_endpoints.extend(eps)
    return all_endpoints


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _extract_string_value(node: Node, src: bytes) -> str | None:
    raw = _text(node, src).strip()
    for q in ('"""', "'''", '"', "'"):
        if raw.startswith(q) and raw.endswith(q) and len(raw) >= 2 * len(q):
            return raw[len(q):-len(q)]
    return raw


class _EndpointExtractor:
    def __init__(self, src: bytes, file: str, module: str) -> None:
        self.src = src
        self.file = file
        self.module = module
        self.endpoints: list[EndpointInfo] = []
        self._class_stack: list[str] = []

    def visit(self, node: Node) -> None:
        for child in node.children:
            if child.type == "class_definition":
                name_node = child.child_by_field_name("name")
                cname = _text(name_node, self.src) if name_node else "Unknown"
                self._class_stack.append(cname)
                self.visit(child)
                self._class_stack.pop()
            elif child.type == "decorated_definition":
                self._handle_decorated(child)
            else:
                self.visit(child)

    def _handle_decorated(self, node: Node) -> None:
        decorators: list[Node] = []
        inner = None
        for child in node.children:
            if child.type == "decorator":
                decorators.append(child)
            elif child.type == "function_definition":
                inner = child
            elif child.type == "class_definition":
                self.visit(child)
                return

        if not inner:
            return

        route_info = None
        for dec in decorators:
            route_info = self._parse_route_decorator(dec)
            if route_info:
                break

        if not route_info:
            return

        path, methods, framework = route_info

        name_node = inner.child_by_field_name("name")
        if not name_node:
            return
        func_name = _text(name_node, self.src)
        if self._class_stack:
            qualified_name = f"{self.module}.{self._class_stack[-1]}.{func_name}"
        else:
            qualified_name = f"{self.module}.{func_name}"

        auth_required, auth_type = self._detect_auth(decorators, inner)
        input_params = self._extract_route_params(path)
        params_node = inner.child_by_field_name("parameters")
        if params_node:
            input_params.extend(self._extract_func_params(params_node))
        input_params = list(dict.fromkeys(input_params))

        start_line = inner.start_point[0] + 1

        for method in methods:
            self.endpoints.append(EndpointInfo(
                path=path,
                method=method,
                handler_function=qualified_name,
                auth_required=auth_required,
                auth_type=auth_type,
                input_params=input_params,
                framework=framework,
                file=self.file,
                line=start_line,
            ))

    def _parse_route_decorator(self, dec_node: Node) -> tuple[str, list[str], str] | None:
        """Return (path, [methods], framework) if this is a route decorator."""
        # Find the call node in the decorator (skip the '@')
        call_node = None
        for child in dec_node.children:
            if child.type == "call":
                call_node = child
                break

        if not call_node:
            return None

        func = call_node.child_by_field_name("function")
        args = call_node.child_by_field_name("arguments")
        if not func:
            return None

        func_text = _text(func, self.src)
        parts = func_text.split(".")
        if len(parts) < 2:
            return None

        method_or_action = parts[-1].lower()

        if method_or_action == "route":
            framework = "flask"
            path = self._extract_first_string_arg(args) or "/"
            methods = self._extract_flask_methods(args) if args else ["GET"]
            return path, methods, framework
        elif method_or_action in _METHOD_SHORTCUTS:
            framework = "fastapi" if "router" in parts[0].lower() else "flask"
            path = self._extract_first_string_arg(args) or "/"
            return path, [method_or_action.upper()], framework

        return None

    def _extract_first_string_arg(self, args_node: Node | None) -> str | None:
        if not args_node:
            return None
        for child in args_node.children:
            if child.type == "string":
                return _extract_string_value(child, self.src)
            elif child.type == "concatenated_string":
                return _extract_string_value(child, self.src)
        return None

    def _extract_flask_methods(self, args_node: Node) -> list[str]:
        for child in args_node.children:
            if child.type == "keyword_argument":
                children = list(child.children)
                if not children:
                    continue
                key = _text(children[0], self.src)
                if key != "methods":
                    continue
                # Find the list node
                for sub in children:
                    if sub.type == "list":
                        methods = []
                        for item in sub.children:
                            if item.type == "string":
                                m = _extract_string_value(item, self.src)
                                if m:
                                    methods.append(m.upper())
                        return methods if methods else ["GET"]
        return ["GET"]

    def _detect_auth(self, decorators: list[Node], func_node: Node) -> tuple[bool, str | None]:
        for dec in decorators:
            dec_text = _text(dec, self.src)
            for pattern in _AUTH_DECORATOR_PATTERNS:
                if pattern.search(dec_text):
                    return True, self._classify_auth_type(dec_text)
            if _FASTAPI_DEPENDS_AUTH_PATTERN.search(dec_text):
                return True, "jwt"

        params_node = func_node.child_by_field_name("parameters")
        if params_node:
            params_text = _text(params_node, self.src)
            if _FASTAPI_DEPENDS_AUTH_PATTERN.search(params_text):
                return True, "jwt"
            if "current_user" in params_text or "token:" in params_text:
                return True, "jwt"

        return False, None

    def _classify_auth_type(self, dec_text: str) -> str:
        t = dec_text.lower()
        if "jwt" in t or "token" in t:
            return "jwt"
        if "session" in t or "login" in t:
            return "session"
        if "api_key" in t or "apikey" in t:
            return "api_key"
        if "basic" in t:
            return "basic"
        return "session"

    def _extract_route_params(self, path: str) -> list[str]:
        flask_params = re.findall(r"<(?:\w+:)?(\w+)>", path)
        fastapi_params = re.findall(r"\{(\w+)\}", path)
        return flask_params + fastapi_params

    def _extract_func_params(self, params_node: Node) -> list[str]:
        params = []
        for child in params_node.children:
            if child.type == "identifier":
                name = _text(child, self.src)
                if name not in ("self", "cls"):
                    params.append(name)
            elif child.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
                if child.children:
                    name = _text(child.children[0], self.src)
                    if name not in ("self", "cls", "*", "**"):
                        params.append(name)
        return params
