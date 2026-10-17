"""Project inventory: which files to read, which to refuse to read, dependencies, frameworks.

Safety rules (the target project is untrusted input, and may contain secrets):
  * files that look like secrets (.env, keys, credentials) are listed but never opened
  * symlinks are not followed; every path is checked to stay inside the project root
  * size and count limits bound the work
  * `redact()` masks secret-looking tokens before any text reaches a model or a log
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.sdk.models import ProjectProfile

SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__",
                       "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
                       "site-packages", ".idea", ".vscode", ".sentinel", "coverage", ".next"})
SENSITIVE_FILE = re.compile(
    r"(^\.env($|\.)|\.pem$|\.key$|\.p12$|\.pfx$|^id_(rsa|ed25519|ecdsa)|credentials|secrets?\.(ya?ml|json|toml)$"
    r"|\.keystore$|\.netrc$|\.htpasswd$)", re.I)
LANGS = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
         ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript"}
MAX_FILE_BYTES = 512 * 1024

FRAMEWORKS = {
    "langchain": "LangChain", "langchain-core": "LangChain", "langgraph": "LangGraph",
    "crewai": "CrewAI", "autogen": "AutoGen", "pyautogen": "AutoGen", "ag2": "AutoGen",
    "llama-index": "LlamaIndex", "llama_index": "LlamaIndex", "openai": "OpenAI SDK",
    "anthropic": "Anthropic SDK", "groq": "Groq SDK", "litellm": "LiteLLM", "ollama": "Ollama",
    "mcp": "MCP", "fastmcp": "MCP", "semantic-kernel": "Semantic Kernel", "fastapi": "FastAPI",
    "flask": "Flask", "django": "Django", "express": "Express", "requests": "requests",
    "httpx": "httpx", "sqlalchemy": "SQLAlchemy", "boto3": "AWS SDK", "pydantic-ai": "PydanticAI",
    "@langchain/core": "LangChain.js", "ai": "Vercel AI SDK", "@modelcontextprotocol/sdk": "MCP",
}

_REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
     "[REDACTED-PRIVATE-KEY]"),
    (re.compile(r"\b(sk-[A-Za-z0-9_\-]{16,}|gsk_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|"
                r"gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9\-]{10,}|"
                r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})"),
     "[REDACTED-TOKEN]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|auth)(['\"]?\s*[:=]\s*)"
                r"(['\"])[^'\"\n]{4,}\3"), r"\1\2\3[REDACTED]\3"),
    (re.compile(r"\b[A-Fa-f0-9]{40,}\b"), "[REDACTED-HEX]"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


@dataclass
class SourceFile:
    rel: str
    language: str
    text: str
    lines: list[str] = field(default_factory=list)


@dataclass
class Inventory:
    root: Path
    files: list[SourceFile]
    profile: ProjectProfile


def is_sentinel_itself(root: Path) -> bool:
    """True when `root` is Sentinel's own repository or installed package."""
    if (root / "src" / "sentinel" / "sdk").is_dir():
        return True
    return (root / "sdk" / "scanner.py").exists() and root.name == "sentinel"


def _inside(root: Path, p: Path) -> bool:
    try:
        p.resolve().relative_to(root)
        return True
    except ValueError:
        return False


def _parse_deps(root: Path) -> list[str]:
    deps: set[str] = set()
    for req in root.glob("requirements*.txt"):
        for line in req.read_text(errors="ignore").splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.\-]+)", line)
            if m and not line.lstrip().startswith(("#", "-")):
                deps.add(m.group(1).lower())
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(errors="ignore"))
            for spec in data.get("project", {}).get("dependencies", []):
                m = re.match(r"\s*([A-Za-z0-9_.\-]+)", spec)
                if m:
                    deps.add(m.group(1).lower())
            for name in data.get("tool", {}).get("poetry", {}).get("dependencies", {}):
                deps.add(name.lower())
        except tomllib.TOMLDecodeError:
            pass
    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(errors="ignore"))
            for key in ("dependencies", "devDependencies"):
                deps.update(str(k).lower() for k in data.get(key, {}))
        except (json.JSONDecodeError, AttributeError):
            pass
    return sorted(deps)


def scan(root: Path, max_files: int = 2000) -> Inventory:
    root = root.resolve()
    files: list[SourceFile] = []
    skipped_sensitive: list[str] = []
    skipped_other = 0
    languages: dict[str, int] = {}

    def walk(d: Path) -> None:
        nonlocal skipped_other
        try:
            entries = sorted(d.iterdir(), key=lambda p: p.name)
        except OSError:
            return
        for p in entries:
            if p.is_symlink():
                skipped_other += 1
                continue
            if p.is_dir():
                if p.name in SKIP_DIRS or p.name.endswith(".egg-info"):
                    continue
                walk(p)
                continue
            if not p.is_file() or not _inside(root, p):
                continue
            rel = p.relative_to(root).as_posix()
            if SENSITIVE_FILE.search(p.name):
                skipped_sensitive.append(rel)  # name only; content is never opened
                continue
            lang = LANGS.get(p.suffix.lower())
            if lang is None:
                continue
            if len(files) >= max_files or p.stat().st_size > MAX_FILE_BYTES:
                skipped_other += 1
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                skipped_other += 1
                continue
            files.append(SourceFile(rel, lang, text, text.splitlines()))
            languages[lang] = languages.get(lang, 0) + 1

    walk(root)
    deps = _parse_deps(root)
    frameworks = sorted({FRAMEWORKS[d] for d in deps if d in FRAMEWORKS})
    imports = " ".join(f.text for f in files if f.language == "python")
    for key, label in (("langchain", "LangChain"), ("langgraph", "LangGraph"), ("crewai", "CrewAI"),
                       ("autogen", "AutoGen"), ("openai", "OpenAI SDK"), ("groq", "Groq SDK"),
                       ("anthropic", "Anthropic SDK")):
        if re.search(rf"^\s*(from|import)\s+{key}\b", imports, re.M) and label not in frameworks:
            frameworks.append(label)
    entry = [f.rel for f in files if re.search(r"""if\s+__name__\s*==\s*['"]__main__['"]""", f.text)
             or f.rel.rsplit("/", 1)[-1] in {"main.py", "app.py", "index.js", "server.js", "cli.py"}]
    readme = ""
    for name in ("README.md", "README.rst", "README.txt", "README"):
        if (root / name).is_file():
            readme = redact((root / name).read_text(errors="ignore")[:2000])
            break
    profile = ProjectProfile(
        root_name=root.name, files_scanned=len(files), files_skipped_sensitive=skipped_sensitive,
        files_skipped_other=skipped_other, languages=languages, dependencies=deps,
        frameworks=sorted(frameworks), entry_points=entry[:20], readme_excerpt=readme)
    return Inventory(root, files, profile)
