"""Add (and remove) guards in a Python project's source — only when the developer asks, and reversibly.

`sentinel sdk instrument` shows a unified diff of the decorators it would add for the SELECTED points
(dry run). `--apply` writes the changes after saving the originals under `.sentinel/backups/`, and
refuses to leave a file that no longer parses. Every line it adds ends with `# sentinel:auto`, so
`--revert` removes exactly those lines and nothing else.

Scope: Python functions and methods. Module-level statements, JavaScript/TypeScript and points
inside code Sentinel cannot map to a function are reported as "manual".
"""

from __future__ import annotations

import ast
import difflib
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sentinel.sdk.models import AnalysisResult, Category, MonitoringPoint
from sentinel.sdk.workspace import Workspace

MARK = "# sentinel:auto"
IMPORT_LINE = f"from sentinel.sdk import guard  {MARK}"
DEST_ARG_NAMES = ("to", "recipient", "recipients", "email", "address", "url", "endpoint", "host",
                  "destination", "channel", "webhook")


def guard_kwargs(p: MonitoringPoint) -> str:
    loc = p.locations[0]
    opts = []
    if p.category in {Category.MESSAGING, Category.EXTERNAL_API}:
        dest = next((a for a in loc.arg_names if a in DEST_ARG_NAMES), None)
        if dest:
            opts.append(f'destination_arg="{dest}"')
    if p.category is Category.SENSITIVE_DATA:
        opts.append('produces=["pii"]')
    return "".join(f", {o}" for o in opts)


@dataclass
class FilePlan:
    rel: str
    original: str
    modified: str
    points: list[str] = field(default_factory=list)


@dataclass
class Plan:
    files: list[FilePlan] = field(default_factory=list)
    manual: list[tuple[str, str]] = field(default_factory=list)    # (point id, reason)
    already: list[str] = field(default_factory=list)

    def diff(self) -> str:
        out = []
        for f in self.files:
            out += difflib.unified_diff(f.original.splitlines(True), f.modified.splitlines(True),
                                        f"a/{f.rel}", f"b/{f.rel}")
        return "".join(out)


def _functions(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}

    def walk(node: ast.AST, stack: list[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                name = ".".join([*stack, child.name])
                if not isinstance(child, ast.ClassDef):
                    found[name] = child
                walk(child, [*stack, child.name])
            else:
                walk(child, stack)

    walk(tree, [])
    return found


def _import_insert_line(tree: ast.Module) -> int:
    """1-based line before which the import goes: after the docstring and `from __future__` lines."""
    for i, node in enumerate(tree.body):
        is_doc = (i == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                  and isinstance(node.value.value, str))
        is_future = isinstance(node, ast.ImportFrom) and node.module == "__future__"
        if not (is_doc or is_future):
            decos = getattr(node, "decorator_list", [])
            return min([node.lineno, *[d.lineno for d in decos]])
    return (tree.body[-1].end_lineno or len(tree.body)) + 1 if tree.body else 1


def plan_instrumentation(ws: Workspace, analysis: AnalysisResult, point_ids: list[str] | None = None) -> Plan:
    selected = set(point_ids) if point_ids else set(ws.load_selected())
    plan = Plan()
    by_file: dict[str, list[MonitoringPoint]] = {}
    for p in analysis.points:
        if p.point_id not in selected:
            continue
        loc = p.locations[0]
        if not loc.file.endswith(".py"):
            plan.manual.append((p.point_id, f"{loc.file} is not Python — add the guard by hand"))
        elif loc.symbol == "<module>":
            plan.manual.append((p.point_id, f"{loc.file}:{loc.line} is module-level code — wrap it "
                                            "with `monitor(...)` by hand"))
        else:
            by_file.setdefault(loc.file, []).append(p)

    for rel, pts in sorted(by_file.items()):
        path = ws.project_root / rel
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text)
        except (OSError, SyntaxError, UnicodeDecodeError):
            plan.manual.extend((p.point_id, f"{rel} cannot be read/parsed") for p in pts)
            continue
        funcs = _functions(tree)
        lines = text.splitlines(keepends=True)
        edits: list[tuple[int, str]] = []
        done: list[str] = []
        for p in pts:
            if f'"{p.point_id}"' in text or f"'{p.point_id}'" in text:
                plan.already.append(p.point_id)
                continue
            fn = funcs.get(p.locations[0].symbol)
            if fn is None:
                plan.manual.append((p.point_id, f"cannot find function {p.locations[0].symbol} in {rel}"))
                continue
            first = min([fn.lineno, *[d.lineno for d in fn.decorator_list]])
            indent = " " * fn.col_offset
            edits.append((first, f'{indent}@guard("{p.point_id}"{guard_kwargs(p)})  {MARK}\n'))
            done.append(p.point_id)
        if not done:
            continue
        for line_no, deco in sorted(edits, key=lambda e: -e[0]):     # bottom-up keeps numbers valid
            lines.insert(line_no - 1, deco)
        if IMPORT_LINE not in text and "from sentinel.sdk import guard" not in text:
            at = _import_insert_line(tree)
            lines.insert(at - 1, IMPORT_LINE + "\n")
        plan.files.append(FilePlan(rel, text, "".join(lines), done))
    return plan


def apply_plan(ws: Workspace, plan: Plan) -> Path | None:
    """Back up originals, write the changes, verify they still parse (restoring on failure)."""
    if not plan.files:
        return None
    backup = ws.dir / "backups" / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    for f in plan.files:
        dest = backup / f.rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ws.project_root / f.rel, dest)
    written: list[FilePlan] = []
    try:
        for f in plan.files:
            ast.parse(f.modified)
            (ws.project_root / f.rel).write_text(f.modified, encoding="utf-8")
            written.append(f)
    except (SyntaxError, OSError) as exc:
        for f in written:
            shutil.copy2(backup / f.rel, ws.project_root / f.rel)
        raise RuntimeError(f"instrumentation aborted, originals restored: {exc}") from exc
    return backup


def revert(ws: Workspace) -> list[str]:
    """Remove every line Sentinel added (marked `# sentinel:auto`). Returns files changed."""
    changed = []
    for path in sorted(ws.project_root.rglob("*.py")):
        if ".sentinel" in path.parts or any(p in {"node_modules", ".venv", "venv", ".git"}
                                            for p in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if MARK not in text:
            continue
        kept = [ln for ln in text.splitlines(keepends=True) if not ln.rstrip().endswith(MARK)]
        new = "".join(kept)
        ast.parse(new)  # never leave a broken file
        path.write_text(new, encoding="utf-8")
        changed.append(path.relative_to(ws.project_root).as_posix())
    return changed
