"""Deterministic code analysis: find places in a business project that deserve monitoring.

Python is analysed with the AST (import aliases and simple `x = Client()` variable types are
resolved); JavaScript/TypeScript with line patterns. Findings are *candidates*; they are merged
into `MonitoringPoint`s keyed by (category, kind, file, enclosing symbol), so ids survive line
shifts. Points inside a function that an LLM can invoke as a tool get their risk raised one level.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from sentinel.sdk.models import (
    RISK_ORDER,
    Category,
    Location,
    MonitoringPoint,
    Risk,
    bump,
    make_point_id,
)
from sentinel.sdk.scanner import SourceFile, redact

SENSITIVE_WORDS = re.compile(
    r"(ssn|social[_ ]?security|passport|credit[_ ]?card|card[_ ]?number|cvv|iban|salary|payroll|"
    r"patient|medical|diagnos|password|customers?|\bpii\b|birth[_ ]?date|\bdob\b|tax[_ ]?id|"
    r"employee|credential)", re.I)
SECRET_NAME = re.compile(r"(secret|token|passw|api[_-]?key|private[_-]?key|credential|auth)", re.I)
SQL_WRITE = re.compile(
    r"\b(insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|truncate|alter\s+table)\b", re.I)
SQL_ANY = re.compile(r"\b(select|insert|update|delete|drop|truncate|alter)\b", re.I)
DEST_ARGS = ("to", "recipient", "recipients", "email", "address", "url", "endpoint", "host",
             "destination", "channel", "webhook")

LLM_CALL = re.compile(r"(chat\.completions\.create|\.messages\.create|responses\.create|"
                      r"generate_content|litellm\.a?completion|ollama\.(chat|generate)|"
                      r"\.completions\.create)$")
LLM_CTORS = ("openai.OpenAI", "openai.AsyncOpenAI", "anthropic.Anthropic", "anthropic.AsyncAnthropic",
             "groq.Groq", "groq.AsyncGroq", "ollama.Client", "cohere.Client", "mistralai.Mistral")
LLM_OBJ_METHODS = {"invoke", "ainvoke", "generate", "predict", "chat", "stream", "astream"}
HTTP_MODULES = ("requests.", "httpx.", "urllib.request.", "aiohttp.", "urllib3.")
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "request", "urlopen", "head", "send", "fetch"}
HTTP_CTORS = ("requests.Session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession")
EXEC_CALLS = {"eval", "exec", "os.system", "os.popen", "subprocess.run", "subprocess.Popen",
              "subprocess.call", "subprocess.check_output", "subprocess.check_call",
              "pickle.loads", "pickle.load", "marshal.loads", "__import__",
              "importlib.import_module"}
MESSAGING_METHODS = {"sendmail", "send_message", "send_mail", "send_email", "chat_postMessage",
                     "post_message", "send_sms"}
MESSAGING_CTORS = ("smtplib.SMTP", "smtplib.SMTP_SSL", "twilio.rest.Client", "slack_sdk.WebClient",
                   "sendgrid.SendGridAPIClient")
DB_CTORS = ("sqlite3.connect", "psycopg2.connect", "pymysql.connect", "sqlalchemy.create_engine",
            "pymongo.MongoClient", "redis.Redis", "asyncpg.connect")
FS_DELETE = {"shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.removedirs"}
FS_MOVE = {"shutil.move", "shutil.copy", "shutil.copyfile", "shutil.copytree", "os.rename"}
INTER_AGENT_CTORS = {"Agent", "AssistantAgent", "UserProxyAgent", "Crew", "GroupChat",
                     "GroupChatManager", "StateGraph", "Swarm", "create_react_agent",
                     "ConversableAgent", "Supervisor"}
INTER_AGENT_CALLS = {"initiate_chat", "kickoff", "handoff", "delegate", "run_agent", "a2a_send"}
TOOL_DECORATORS = {"tool", "function_tool", "kernel_function", "structured_tool"}
TOOL_CTORS = {"Tool", "StructuredTool", "FunctionTool", "StructuredTool.from_function"}


@dataclass
class Candidate:
    category: Category
    kind: str
    risk: Risk
    title: str
    description: str
    reason: str
    file: str
    line: int
    symbol: str
    snippet: str
    arg_names: list[str] = field(default_factory=list)


def _snippet(lines: list[str], line: int) -> str:
    text = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    text = redact(text)
    return text if len(text) <= 140 else text[:139] + "…"


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):  # chained: a().b().c -> resolve receiver
        inner = _dotted(node.func)
        if inner:
            return ".".join([inner + "()", *reversed(parts)])
    return None


def _is_dynamic_str(node: ast.AST) -> bool:
    """f-string, concatenation, %-format or .format(): the SQL/command is built from variables."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return True
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format")


def _const_text(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value for v in node.values if isinstance(v, ast.Constant)
                       and isinstance(v.value, str))
    return ""


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, f: SourceFile, tool_funcs: set[str]):
        self.f = f
        self.tool_funcs = tool_funcs
        self.alias: dict[str, str] = {}
        self.vartype: dict[str, str] = {}
        self.stack: list[str] = []
        self.args_stack: list[list[str]] = []
        self.out: list[Candidate] = []
        self.defined_tools: list[dict[str, object]] = []

    # ---- helpers ---------------------------------------------------------------------------
    @property
    def symbol(self) -> str:
        return ".".join(self.stack) or "<module>"

    def add(self, node: ast.AST, cat: Category, kind: str, risk: Risk, title: str, desc: str,
            reason: str) -> None:
        line = getattr(node, "lineno", 1)
        self.out.append(Candidate(
            cat, kind, risk, title, desc, reason, self.f.rel, line, self.symbol,
            _snippet(self.f.lines, line), list(self.args_stack[-1]) if self.args_stack else []))

    def resolve(self, node: ast.AST) -> str | None:
        name = _dotted(node)
        if not name:
            return None
        head, _, rest = name.partition(".")
        if name in self.vartype:
            return self.vartype[name]
        # longest variable-type prefix, e.g. self.client.chat.completions.create
        parts = name.split(".")
        for i in range(len(parts) - 1, 0, -1):
            pref = ".".join(parts[:i])
            if pref in self.vartype:
                return self.vartype[pref] + "." + ".".join(parts[i:])
        if head in self.alias:
            return self.alias[head] + ("." + rest if rest else "")
        return name

    # ---- imports / assignments / scopes ----------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for a in node.names:
            self.alias[a.asname or a.name] = f"{node.module or ''}.{a.name}".strip(".")

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            ctor = self.resolve(node.value.func)
            if ctor:
                for t in node.targets:
                    key = _dotted(t)
                    if key:
                        self.vartype[key] = ctor
        self.generic_visit(node)

    def _scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, args: bool) -> None:
        self.stack.append(node.name)
        self.args_stack.append([a.arg for a in node.args.args + node.args.kwonlyargs
                                if a.arg not in {"self", "cls"}] if args else [])
        self.generic_visit(node)
        self.args_stack.pop()
        self.stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope(node, False)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            name = _dotted(target) or ""
            if name.split(".")[-1] in TOOL_DECORATORS:
                self.tool_funcs.add(node.name)
                self.defined_tools.append({"name": node.name, "file": self.f.rel,
                                           "line": node.lineno})
                self.stack.append(node.name)
                self.args_stack.append([a.arg for a in node.args.args if a.arg != "self"])
                self.add(node, Category.TOOL_CALL, "tool_definition", Risk.MEDIUM,
                         f"LLM-callable tool '{node.name}'",
                         "A function exposed to an LLM/agent as a tool: the model decides when "
                         "and with what arguments it runs.",
                         "Tool calls are the main route from model output to real side effects.")
                self.args_stack.pop()
                self.stack.pop()
                break
        low = node.name.lower()
        if re.match(r"(get|read|fetch|load|export|list|search|query|dump|lookup)_", low) \
                and SENSITIVE_WORDS.search(low):
            self.stack.append(node.name)
            self.args_stack.append([a.arg for a in node.args.args if a.arg != "self"])
            self.add(node, Category.SENSITIVE_DATA, "sensitive_data", Risk.MEDIUM,
                     f"Sensitive data accessor '{node.name}'",
                     "Function name indicates it reads personal, financial or credential data.",
                     "Data it returns should be tracked so it cannot flow to unapproved outputs.")
            self.args_stack.pop()
            self.stack.pop()
        self._scope(node, True)

    # ---- dict literal that looks like an LLM tool schema -----------------------------------
    def visit_Dict(self, node: ast.Dict) -> None:
        keys = {k.value: v for k, v in zip(node.keys, node.values, strict=False)
                if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        t = keys.get("type")
        if isinstance(t, ast.Constant) and t.value == "function" and "function" in keys:
            self.add(node, Category.TOOL_CALL, "tool_schema", Risk.MEDIUM,
                     "LLM tool schema declared",
                     "A function-calling schema handed to a model.",
                     "Defines what actions the model may request.")
        self.generic_visit(node)

    # ---- calls -----------------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        full = self.resolve(node.func) or ""
        last = full.split(".")[-1]
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        first = node.args[0] if node.args else None

        # code execution
        if full in EXEC_CALLS or (last in {"eval", "exec"} and full in {"eval", "exec"}):
            shell = isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True
            dyn = first is not None and _is_dynamic_str(first)
            risk = Risk.CRITICAL if (shell or full in {"eval", "exec", "os.system"} and dyn) \
                else Risk.HIGH
            self.add(node, Category.CODE_EXECUTION, full, risk,
                     f"Executes code/commands via {full}()",
                     "Runs a shell command or evaluates code" + (" built from variables" if dyn
                                                                 else "") + ".",
                     "Arbitrary execution is the highest-impact outcome of prompt injection.")
        # HTTP
        elif (full.startswith(HTTP_MODULES) and last in HTTP_VERBS) or \
                (full.split(".")[0] == "fetch") or full.endswith(".fetch"):
            url = _const_text(first) if first is not None else ""
            dynamic = first is not None and not url
            risk = Risk.HIGH if (dynamic and last in {"post", "put", "patch", "delete"}) \
                else Risk.MEDIUM
            self.add(node, Category.EXTERNAL_API, f"http.{last}", risk,
                     f"Outbound HTTP {last.upper()} call",
                     "Sends a request to an external service"
                     + ("; the URL is computed at runtime" if dynamic else f" ({url[:60]})") + ".",
                     "External calls can leak data and are a path for SSRF/exfiltration.")
        # LLM calls
        elif LLM_CALL.search(full) or (
                full.rsplit(".", 1)[0] in LLM_CTORS and last in LLM_OBJ_METHODS):
            has_tools = "tools" in kw or "functions" in kw
            self.add(node, Category.LLM_CALL, "llm_call", Risk.HIGH if has_tools else Risk.MEDIUM,
                     "LLM request" + (" with tools enabled" if has_tools else ""),
                     "Sends prompt/context to a model provider"
                     + (" and lets the model request tool calls" if has_tools else "") + ".",
                     "Prompt content leaves the process; model output is untrusted input.")
        # messaging
        elif last in MESSAGING_METHODS or full in MESSAGING_CTORS or \
                any(full.endswith(c) for c in MESSAGING_CTORS):
            self.add(node, Category.MESSAGING, "messaging", Risk.HIGH,
                     f"Sends a message ({last})",
                     "Delivers content to people or channels outside the application.",
                     "Outbound messages are a direct data-exfiltration and spam channel.")
        # database
        elif full in DB_CTORS:
            self.add(node, Category.DATABASE, f"db.{last}", Risk.MEDIUM,
                     f"Opens database connection ({last})",
                     "Connects to a datastore.", "Database access should be attributable and limited.")
        elif last in {"execute", "executemany", "executescript"} and first is not None and (
                _is_dynamic_str(first) or SQL_ANY.search(_const_text(first))):
            text = _const_text(first)
            write = bool(SQL_WRITE.search(text))
            dyn = _is_dynamic_str(first)
            drop = bool(re.search(r"\b(drop\s+table|truncate)\b", text, re.I))
            risk = Risk.CRITICAL if drop else Risk.HIGH if (write or dyn) else Risk.MEDIUM
            self.add(node, Category.DATABASE, "sql_write" if write else "sql_query", risk,
                     "SQL " + ("write" if write else "query") + (" built dynamically" if dyn else ""),
                     "Executes SQL" + (" assembled from variables (injection risk)" if dyn else "") + ".",
                     "Data changes and dynamic queries need an audit trail.")
            m = re.search(r"\b(from|into|update|join)\s+([A-Za-z_][\w.]*)", text, re.I)
            if m and SENSITIVE_WORDS.search(m.group(2)):
                self.add(node, Category.SENSITIVE_DATA, "sensitive_data", Risk.HIGH,
                         f"Reads/writes sensitive table '{m.group(2)}'",
                         "SQL touches a table whose name indicates personal or credential data.",
                         "Sensitive records must not reach unapproved destinations.")
        # filesystem
        elif full in FS_DELETE or last in {"unlink", "rmdir"} and full.count(".") >= 1:
            self.add(node, Category.FILE_SYSTEM, "fs.delete", Risk.HIGH,
                     f"Deletes files ({last})", "Removes files or directories.",
                     "Destructive file operations should be gated.")
        elif full in FS_MOVE or last in {"write_text", "write_bytes"}:
            self.add(node, Category.FILE_SYSTEM, "fs.write", Risk.MEDIUM,
                     f"Writes/moves files ({last})", "Creates or overwrites files.",
                     "File writes can persist injected content or overwrite data.")
        elif full == "open" and len(node.args) >= 1:
            mode_node = node.args[1] if len(node.args) > 1 else kw.get("mode")
            mode = _const_text(mode_node) if mode_node is not None else ""
            path = _const_text(node.args[0])
            if any(c in mode for c in "wax+"):
                self.add(node, Category.FILE_SYSTEM, "fs.write", Risk.MEDIUM,
                         "Opens a file for writing", "Creates or overwrites a file.",
                         "File writes can persist injected content or overwrite data.")
            if path.endswith(".env") or "/.env" in path:
                self.add(node, Category.SECRET_ACCESS, "reads_dotenv", Risk.HIGH,
                         "Reads a .env file", "Loads secrets from a .env file.",
                         "Secrets must not be reachable from model-driven code.")
            elif path and SENSITIVE_WORDS.search(path):
                self.add(node, Category.SENSITIVE_DATA, "sensitive_data", Risk.HIGH,
                         "Opens a file with a sensitive-looking name",
                         "Path suggests personal, financial or credential data.",
                         "Sensitive data must not reach unapproved outputs.")
        # secrets
        elif full in {"os.getenv", "os.environ.get"} and first is not None and \
                SECRET_NAME.search(_const_text(first)):
            self.add(node, Category.SECRET_ACCESS, "env_secret", Risk.MEDIUM,
                     f"Reads secret environment variable {_const_text(first)}",
                     "Accesses a credential held in the environment.",
                     "Credentials in code paths reachable by tools can be exfiltrated.")
        elif full in {"boto3.client", "boto3.resource", "boto3.Session", "keyring.get_password"}:
            self.add(node, Category.SECRET_ACCESS, "cloud_creds", Risk.MEDIUM,
                     f"Uses cloud/credential API ({full})", "Obtains cloud credentials or clients.",
                     "Cloud access amplifies the impact of any compromise.")
        # inter-agent / tools
        elif last in INTER_AGENT_CTORS or last in INTER_AGENT_CALLS:
            self.add(node, Category.INTER_AGENT, f"agent.{last}", Risk.MEDIUM,
                     f"Agent orchestration ({last})",
                     "Creates or invokes another agent / agent workflow.",
                     "Messages between agents are an injection and privilege-escalation path.")
        elif last in {c.split(".")[-1] for c in TOOL_CTORS} or full in TOOL_CTORS:
            self.add(node, Category.TOOL_CALL, "tool_registration", Risk.MEDIUM,
                     f"Registers a tool ({last})", "Wraps a function as an LLM-callable tool.",
                     "Defines what a model may trigger.")
            fn = kw.get("func")
            if isinstance(fn, ast.Name):
                self.tool_funcs.add(fn.id)

        # `tools=[fn, ...]` marks those functions as LLM-reachable
        tools_kw = kw.get("tools")
        if isinstance(tools_kw, ast.List | ast.Tuple):
            for el in tools_kw.elts:
                if isinstance(el, ast.Name):
                    self.tool_funcs.add(el.id)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:  # os.environ["API_KEY"]
        if self.resolve(node.value) == "os.environ" and SECRET_NAME.search(_const_text(node.slice)):
            self.add(node, Category.SECRET_ACCESS, "env_secret", Risk.MEDIUM,
                     f"Reads secret environment variable {_const_text(node.slice)}",
                     "Accesses a credential held in the environment.",
                     "Credentials in code paths reachable by tools can be exfiltrated.")
        self.generic_visit(node)


# ---- JavaScript / TypeScript (line patterns) ------------------------------------------------
_JS_RULES = [
    (re.compile(r"\b(child_process|execSync|spawnSync|\.exec\(|\.spawn\()"), Category.CODE_EXECUTION,
     "js.exec", Risk.HIGH, "Runs shell commands", "Spawns a process."),
    (re.compile(r"\beval\(|new Function\("), Category.CODE_EXECUTION, "js.eval", Risk.CRITICAL,
     "Evaluates dynamic code", "Executes code from a string."),
    (re.compile(r"\b(fetch|axios(\.\w+)?|got|superagent)\(|\bhttps?\.request\("),
     Category.EXTERNAL_API, "js.http", Risk.MEDIUM, "Outbound HTTP request",
     "Calls an external service."),
    (re.compile(r"\b(nodemailer|createTransport|sendMail|sgMail\.send|chat\.postMessage)\b"),
     Category.MESSAGING, "js.messaging", Risk.HIGH, "Sends a message", "Delivers email/chat."),
    (re.compile(r"\bfs\.(writeFile|writeFileSync|appendFile|unlink|unlinkSync|rm|rmSync|rmdir)\b"),
     Category.FILE_SYSTEM, "js.fs", Risk.MEDIUM, "Writes or deletes files", "Filesystem change."),
    (re.compile(r"process\.env\.[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*"),
     Category.SECRET_ACCESS, "js.env_secret", Risk.MEDIUM, "Reads a secret env var",
     "Accesses a credential."),
    (re.compile(r"\b(new OpenAI|new Anthropic|new Groq|chat\.completions\.create|messages\.create)\b"),
     Category.LLM_CALL, "js.llm", Risk.MEDIUM, "LLM request", "Sends prompt/context to a provider."),
    (re.compile(r"\b(tools\s*:\s*\[|tool\(\{|server\.tool\(|registerTool\()"),
     Category.TOOL_CALL, "js.tool", Risk.MEDIUM, "LLM tool definition", "Defines a model-callable tool."),
    (re.compile(r"\.(query|execute)\(\s*[`'\"].*\b(select|insert|update|delete)\b", re.I),
     Category.DATABASE, "js.sql", Risk.MEDIUM, "SQL query", "Executes SQL."),
]


def _js_candidates(f: SourceFile) -> list[Candidate]:
    out = []
    for i, line in enumerate(f.lines, 1):
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        for pattern, cat, kind, risk, title, desc in _JS_RULES:
            if pattern.search(line):
                out.append(Candidate(cat, kind, risk, title, desc,
                                     "Security-relevant operation in application code.",
                                     f.rel, i, "<module>", _snippet(f.lines, i)))
    return out


# ---- merge ----------------------------------------------------------------------------------
def analyse_files(files: list[SourceFile]) -> tuple[list[MonitoringPoint], list[dict], list[str]]:
    """Returns (points, discovered tool definitions, warnings)."""
    trees: list[tuple[SourceFile, ast.AST]] = []
    warnings: list[str] = []
    for f in files:
        if f.language == "python":
            try:
                trees.append((f, ast.parse(f.text)))
            except SyntaxError as exc:
                warnings.append(f"{f.rel}: syntax error at line {exc.lineno}; file skipped")
    tool_funcs: set[str] = set()
    tools: list[dict] = []
    # pass 1 discovers tool-exposed functions anywhere in the project; pass 2 uses the full set
    for f, tree in trees:
        v = _PyVisitor(f, tool_funcs)
        v.visit(tree)
        tools += v.defined_tools
    candidates: list[Candidate] = []
    for f, tree in trees:
        v = _PyVisitor(f, tool_funcs)
        v.visit(tree)
        candidates += v.out
    for f in files:
        if f.language in {"javascript", "typescript"}:
            candidates += _js_candidates(f)

    merged: dict[tuple, MonitoringPoint] = {}
    for c in candidates:
        top = c.symbol.split(".")[-1]
        exposed = top if top in tool_funcs and c.kind != "tool_definition" else None
        risk = bump(c.risk) if exposed else c.risk
        pid = make_point_id(c.category.value, c.kind, c.file, c.symbol)
        loc = Location(file=c.file, line=c.line, symbol=c.symbol, snippet=c.snippet,
                       arg_names=c.arg_names)
        if pid in merged:
            p = merged[pid]
            if len(p.locations) < 10 and all(x.line != c.line for x in p.locations):
                p.locations.append(loc)
            if RISK_ORDER.index(risk) > RISK_ORDER.index(p.risk):   # keep the worst finding
                p.risk = risk
                p.static_risk = max(p.static_risk, c.risk, key=RISK_ORDER.index)
            continue
        notes = [f"raised one level: reachable by an LLM as tool '{exposed}'"] if exposed else []
        merged[pid] = MonitoringPoint(
            point_id=pid, title=c.title, category=c.category, risk=risk, static_risk=c.risk,
            description=c.description, reason=c.reason, locations=[loc], exposed_via_tool=exposed,
            risk_notes=notes)
    order = {r: i for i, r in enumerate(reversed([Risk.LOW, Risk.MEDIUM, Risk.HIGH, Risk.CRITICAL]))}
    points = sorted(merged.values(), key=lambda p: (order[p.risk], p.locations[0].file,
                                                    p.locations[0].line))
    return points, tools, warnings
