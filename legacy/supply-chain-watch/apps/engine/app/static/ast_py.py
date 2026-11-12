"""파이썬 AST 데이터 흐름 보정 (docs/03 §3.4 2차, Phase 3-7).

정규식은 "같은 줄·몇 줄 안"만 본다. 여기서는 구문 트리로 값이 어디서 와서 어디로 가는지 추적한다(함수 안 지역 흐름,
변수 대입·f-string·연산·호출 인자를 따라 전파하는 가벼운 오염 추적). 다음 세 흐름을 찾는다.

- sensitive → net : 환경변수·시스템 정보·자격증명 파일 내용이 네트워크 전송 인자로 들어감
- decode → exec   : base64·hex·zlib 등으로 푼 값이 exec/eval/os.system/subprocess 로 들어감
- download → exec : 내려받은 내용이 실행되거나, 파일로 쓴 뒤 그 파일이 실행됨

추가된 줄을 파일 전체로 파싱할 수 있을 때만 동작한다(새 파일·큰 변경). 파싱이 안 되면 조용히 건너뛴다.
"""
from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field

SENSITIVE_PATH_HINTS = (".ssh", ".aws", ".npmrc", ".pypirc", ".docker/config", ".git-credentials", ".kube",
                        "/etc/passwd", "/etc/shadow", "Login Data", "Local State", "Cookies", "leveldb")

# 호출 이름(점 표기 꼬리) → 오염 종류
SOURCE_CALLS = {
    # 환경변수 "하나"를 읽는 것은 설정 읽기라 출처로 보지 않는다 — 환경 전체·시스템 정보·자격증명 파일만
    "sensitive": {"socket.gethostname", "gethostname",
                  "getpass.getuser", "getuser", "os.getlogin", "getlogin", "platform.node", "platform.uname",
                  "os.uname", "uname", "socket.getfqdn"},
    "decode": {"base64.b64decode", "b64decode", "base64.b32decode", "base64.a85decode", "base64.decodebytes",
               "codecs.decode", "bytes.fromhex", "binascii.unhexlify", "unhexlify", "zlib.decompress",
               "marshal.loads", "lzma.decompress", "bz2.decompress", "gzip.decompress"},
    "download": {"urllib.request.urlopen", "urlopen", "requests.get", "requests.post", "httpx.get", "urllib.request.urlretrieve",
                 "urlretrieve", "http.client.HTTPSConnection", "http.client.HTTPConnection"},
}
NET_MODULES = ("requests", "httpx", "urllib3", "aiohttp", "session", "client", "http")
NET_SINK_TAILS = {"urlopen", "Request", "sendall", "sendto", "send", "gethostbyname", "getaddrinfo", "sendmail"}
NET_SINK_METHODS = {"post", "put", "patch", "get", "request", "resolve", "query"}
# 코드 실행 — compile/eval/exec 는 내장 함수(점 없이)일 때만 (re.compile 등 제외)
EXEC_BUILTINS = {"exec", "eval", "compile", "__import__"}
EXEC_SINKS = {"os.system", "system", "os.popen", "popen", "subprocess.run", "subprocess.call", "subprocess.Popen",
              "subprocess.check_output", "subprocess.check_call", "subprocess.getoutput", "Popen", "check_output",
              "check_call", "os.startfile", "startfile", "os.execv", "os.execve", "os.spawnv",
              "importlib.import_module", "types.FunctionType", "FunctionType"}


def _is_net_sink(name: str) -> bool:
    head, _, tail = name.rpartition(".")
    if tail in NET_SINK_TAILS:
        return True
    # requests.post / session.post / dns.resolver.resolve 처럼 네트워크 객체의 메서드일 때만
    return tail in NET_SINK_METHODS and (any(m in head.lower() for m in NET_MODULES) or head.endswith("resolver"))


def _is_exec_sink(name: str) -> bool:
    return name in EXEC_BUILTINS or (name not in EXEC_BUILTINS and _matches(name, EXEC_SINKS))


WRITE_CALLS = {"write", "write_bytes", "write_text"}


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(_dotted(node.func) + "()")
    return ".".join(reversed(parts))


def _matches(name: str, table: set[str]) -> bool:
    """os.system 은 'os.system' 또는 꼬리 'system' 으로 맞춘다 (import 별칭 대응)."""
    return name in table or name.rsplit(".", 1)[-1] in table


@dataclass
class Flow:
    kind: str  # sensitive_to_net | decode_to_exec | download_to_exec
    line: int
    snippet: str


@dataclass
class _Scope:
    taint: dict[str, set[str]] = field(default_factory=dict)
    written_files: dict[str, set[str]] = field(default_factory=dict)  # 경로 표현 → 오염 종류


class _Visitor(ast.NodeVisitor):
    def __init__(self, src_lines: list[str]):
        self.lines = src_lines
        self.flows: list[Flow] = []
        self.scopes = [_Scope()]

    # ---- 오염 계산 ----
    @property
    def scope(self) -> _Scope:
        return self.scopes[-1]

    def taint_of(self, node: ast.AST | None) -> set[str]:
        if node is None:
            return set()
        if isinstance(node, ast.Name):
            out: set[str] = set()
            for sc in self.scopes:
                out |= sc.taint.get(node.id, set())
            return out
        if isinstance(node, ast.Attribute):
            if _dotted(node) in ("os.environ", "environ"):
                return {"sensitive"}
            return self.taint_of(node.value)
        if isinstance(node, ast.Subscript):
            if _dotted(node.value) in ("os.environ", "environ"):
                return set()  # 환경변수 하나 읽기 = 설정
            return self.taint_of(node.value)
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in ("os.environ.get", "environ.get", "os.getenv", "getenv"):
                return set()  # 환경변수 하나 읽기 = 설정
            kinds = {k for k, names in SOURCE_CALLS.items() if _matches(name, names)}
            if name in ("open", "io.open", "pathlib.Path", "Path") and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str) and any(h in first.value for h in SENSITIVE_PATH_HINTS):
                    kinds.add("sensitive")
            if name in ("dict", "str", "json.dumps", "dumps", "repr") and node.args and _dotted(node.args[0]) in ("os.environ", "environ"):
                kinds.add("sensitive")
            # 메서드 호출은 받는 객체의 오염을, 일반 호출은 인자의 오염을 이어받는다
            if isinstance(node.func, ast.Attribute):
                kinds |= self.taint_of(node.func.value)
            for a in node.args:
                kinds |= self.taint_of(a)
            for kw in node.keywords:
                kinds |= self.taint_of(kw.value)
            return kinds
        if isinstance(node, (ast.BinOp,)):
            return self.taint_of(node.left) | self.taint_of(node.right)
        if isinstance(node, ast.JoinedStr):
            return set().union(*(self.taint_of(v.value) for v in node.values if isinstance(v, ast.FormattedValue))) if node.values else set()
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return set().union(*(self.taint_of(e) for e in node.elts)) if node.elts else set()
        if isinstance(node, ast.Dict):
            return set().union(*(self.taint_of(v) for v in node.values if v is not None)) if node.values else set()
        if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.DictComp)):
            return set().union(*(self.taint_of(g.iter) for g in node.generators))
        if isinstance(node, ast.IfExp):
            return self.taint_of(node.body) | self.taint_of(node.orelse)
        if isinstance(node, ast.Await):
            return self.taint_of(node.value)
        return set()

    def _assign(self, target: ast.AST, kinds: set[str]) -> None:
        if not kinds:
            return
        if isinstance(target, ast.Name):
            self.scope.taint.setdefault(target.id, set()).update(kinds)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t in target.elts:
                self._assign(t, kinds)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = target.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name):
                self.scope.taint.setdefault(base.id, set()).update(kinds)

    def _flow(self, kind: str, node: ast.AST) -> None:
        line = getattr(node, "lineno", 1)
        text = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        if not any(f.kind == kind and f.line == line for f in self.flows):
            self.flows.append(Flow(kind, line, text[:160]))

    # ---- 방문 ----
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.scopes.append(_Scope())
        self.generic_visit(node)
        self.scopes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        kinds = self.taint_of(node.value)
        for t in node.targets:
            self._assign(t, kinds)
        # f = open(path, 'wb') → f에 쓰인 내용은 path 파일이 된다
        v = node.value
        if (isinstance(v, ast.Call) and _dotted(v.func) in ("open", "io.open") and len(v.args) >= 2
                and isinstance(v.args[1], ast.Constant) and isinstance(v.args[1].value, str) and "w" in v.args[1].value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.scope.taint.setdefault("__file__" + t.id, set()).add("path:" + ast.unparse(v.args[0]))

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        self._assign(node.target, self.taint_of(node.value))

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node)
        self._assign(node.target, self.taint_of(node.value))

    def visit_For(self, node: ast.For) -> None:
        self._assign(node.target, self.taint_of(node.iter))
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._assign(item.optional_vars, self.taint_of(item.context_expr))
                # with open(path, 'wb') as f: … f.write(downloaded) → 그 경로를 "내려받은 파일"로 기억
                ce = item.context_expr
                if isinstance(ce, ast.Call) and _dotted(ce.func) in ("open", "io.open") and len(ce.args) >= 2:
                    mode = ce.args[1]
                    if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and "w" in mode.value:
                        if isinstance(item.optional_vars, ast.Name):
                            self.scope.taint.setdefault("__file__" + item.optional_vars.id, set()).add("path:" + ast.unparse(ce.args[0]))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        name = _dotted(node.func)
        arg_taint = set().union(*(self.taint_of(a) for a in node.args)) if node.args else set()
        for kw in node.keywords:
            arg_taint |= self.taint_of(kw.value)

        if _is_net_sink(name) and "sensitive" in arg_taint:
            self._flow("sensitive_to_net", node)
        if _is_exec_sink(name):
            if "decode" in arg_taint:
                self._flow("decode_to_exec", node)
            if "download" in arg_taint:
                self._flow("download_to_exec", node)
            # 내려받은 내용을 쓴 파일 경로(변수·식)가 실행 인자에 다시 나오면 (단어 단위 비교)
            rendered = " ".join(ast.unparse(a) for a in node.args)
            for sc in self.scopes:
                for path in sc.written_files:
                    if path and re.search(r"(?<![\w.])" + re.escape(path) + r"(?![\w(])", rendered):
                        self._flow("download_to_exec", node)
        # urlretrieve(url, dest) → dest는 내려받은 파일
        if name.rsplit(".", 1)[-1] == "urlretrieve" and len(node.args) >= 2:
            self.scope.written_files[ast.unparse(node.args[1])] = {"download"}
        # f.write(downloaded) / Path(p).write_bytes(downloaded)
        if isinstance(node.func, ast.Attribute) and node.func.attr in WRITE_CALLS and "download" in arg_taint:
            target = node.func.value
            path = None
            if isinstance(target, ast.Name):
                marks = [t for sc in self.scopes for t in sc.taint.get("__file__" + target.id, set()) if t.startswith("path:")]
                path = marks[0][5:] if marks else None
            elif isinstance(target, ast.Call) and target.args:
                path = ast.unparse(target.args[0])
            if path:
                self.scope.written_files[path] = {"download"}


def analyze_python(source: str) -> list[Flow]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # 분석 대상 코드의 잘못된 이스케이프 경고는 무시
            tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return []
    v = _Visitor(source.split("\n"))
    try:
        v.visit(tree)
    except RecursionError:
        return v.flows
    return v.flows
