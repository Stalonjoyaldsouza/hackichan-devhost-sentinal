"""`sentinel sdk …` commands. Run them from inside a business project (or pass --path)."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from sentinel.ai import make_provider
from sentinel.ai.providers import OfflineHeuristicProvider
from sentinel.audit import AuditStore
from sentinel.sdk.activity import ActivityTracker, latest_run_id, read_tasks
from sentinel.sdk.agents import AnalysisError, run_analysis
from sentinel.sdk.lifecycle import compute_status
from sentinel.sdk.models import (
    RISK_ORDER,
    AnalysisResult,
    Category,
    MonitoringPoint,
    PointState,
    Risk,
)
from sentinel.sdk.policygen import write_policy
from sentinel.sdk.scanner import is_sentinel_itself
from sentinel.sdk.workspace import Workspace, WorkspaceError, find_workspace
from sentinel.termlog import BOLD, CYAN, DIM, GREEN, RED, YELLOW, Style, TerminalLog
from sentinel.watch import watch

STATE_COLOR = {PointState.IDENTIFIED: DIM, PointState.SELECTED: YELLOW,
               PointState.IMPLEMENTED: CYAN, PointState.ACTIVE: GREEN}
RISK_COLOR = {Risk.LOW: DIM, Risk.MEDIUM: YELLOW, Risk.HIGH: RED, Risk.CRITICAL: RED}
LEGEND = ("IDENTIFIED = found · SELECTED = you chose it · IMPLEMENTED = guard present in code · "
          "ACTIVE = guard observed evaluating calls at runtime (only ACTIVE points are monitored)")
DEST_ARG_NAMES = ("to", "recipient", "recipients", "email", "address", "url", "endpoint", "host",
                  "destination", "channel", "webhook")


class CliError(Exception):
    pass


def _style(args: argparse.Namespace) -> Style:
    return Style(sys.stdout.isatty() and not args.no_color)


def _workspace(args: argparse.Namespace) -> Workspace:
    try:
        return find_workspace(args.path)
    except WorkspaceError as exc:
        raise CliError(str(exc)) from exc


def _analysis(ws: Workspace) -> AnalysisResult:
    try:
        return ws.load_analysis()
    except WorkspaceError as exc:
        raise CliError(str(exc)) from exc


def resolve_ids(analysis: AnalysisResult, tokens: list[str]) -> list[str]:
    known = {p.point_id for p in analysis.points}
    out = []
    for t in tokens:
        pid = t.upper() if t.upper().startswith("MP-") else f"MP-{t.upper()}"
        if pid not in known:
            raise CliError(f"unknown monitoring point '{t}' (see `sentinel sdk points`)")
        out.append(pid)
    return out


def parse_selection(text: str, points: list[MonitoringPoint], current: set[str]) -> set[str] | None:
    """Interactive selection grammar. Returns the new selection, or None to cancel."""
    t = text.strip().lower()
    if t in {"q", "quit", "cancel"}:
        return None
    if t in {"", "c", "keep"}:
        return set(current)
    if t in {"a", "all"}:
        return {p.point_id for p in points}
    if t in {"n", "none"}:
        return set()
    if t in {"h", "high"}:
        return {p.point_id for p in points if p.risk in {Risk.HIGH, Risk.CRITICAL}}
    chosen: set[str] = set()
    for part in t.replace(" ", "").split(","):
        if not part:
            continue
        lo, sep, hi = part.partition("-")
        try:
            a, b = int(lo), int(hi) if sep else int(lo)
        except ValueError as exc:
            raise CliError(f"cannot understand '{part}'") from exc
        if not (1 <= a <= b <= len(points)):
            raise CliError(f"'{part}' is outside 1-{len(points)}")
        chosen.update(points[i - 1].point_id for i in range(a, b + 1))
    return chosen


# ---- rendering ------------------------------------------------------------------------------
def _loc(p: MonitoringPoint) -> str:
    loc = p.locations[0]
    extra = f" +{len(p.locations) - 1}" if len(p.locations) > 1 else ""
    return f"{loc.file}:{loc.line}{extra}"


def print_points(st: Style, points: list[MonitoringPoint], statuses, selected: set[str],
                 numbered: bool = False) -> None:
    for i, p in enumerate(points, 1):
        state = statuses[p.point_id].state if statuses else PointState.IDENTIFIED
        mark = "[x]" if p.point_id in selected else "[ ]"
        num = f"{i:>3}. " if numbered else ""
        title = p.title if len(p.title) <= 52 else p.title[:51] + "…"
        print(f"{num}{mark if numbered else ''} {p.point_id}  "
              f"{st(f'{p.risk.value:<8}', BOLD, RISK_COLOR[p.risk])} "
              f"{st(f'{state.value:<11}', STATE_COLOR[state])} "
              f"{p.category.value:<22} {title:<52} {_loc(p)}"
              + (st("  [AI]", CYAN) if p.source == "ai" else ""))


def _counts(points: list[MonitoringPoint]) -> str:
    n = {r: sum(p.risk is r for p in points) for r in reversed(RISK_ORDER)}
    return ", ".join(f"{v} {k.value.lower()}" for k, v in n.items() if v)


def print_agent_table(st: Style, rows, header: bool = True) -> None:
    if header:
        print(st("  Agent activity", BOLD))
    for r in rows:
        color = {"RUNNING": CYAN, "COMPLETED": GREEN, "FAILED": RED}.get(r.status, DIM)
        dur = f"{r.duration_s:.2f}s" if r.duration_s is not None else "…"
        print(f"   {st(f'{r.status:<10}', color)} {r.agent:<14} {r.description[:46]:<46} {dur:>7}"
              + (f"  → {r.detail[:90]}" if r.detail else ""))


# ---- commands -------------------------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.path or ".").resolve()
    if is_sentinel_itself(root) and not args.allow_self:
        raise CliError("this looks like Sentinel's own source tree; run from your business project "
                       "(or pass --path / --allow-self)")
    ws = Workspace(root)
    created = ws.init()
    write_policy(ws)
    print(f"{'Initialised' if created else 'Already initialised'}: {ws.dir}")
    print("Next: sentinel sdk analyze [--guidelines FILE_OR_DIR ...]")
    return 0


def _confirm_egress(provider, args: argparse.Namespace, st: Style) -> None:
    if isinstance(provider, OfflineHeuristicProvider):
        return
    print(st(f"! AI mode '{provider.name}': redacted code excerpts (file names, detected operations,"
             " short snippets, dependency names, README start) and your guideline text will be "
             "SENT to the model provider. Secret-looking files are never read.", YELLOW))
    if args.yes:
        return
    if sys.stdin.isatty() and input("Continue? [y/N] ").strip().lower() in {"y", "yes"}:
        return
    raise CliError("not confirmed (use --yes to allow sending, or --ai offline)")


def cmd_analyze(args: argparse.Namespace) -> int:
    st = _style(args)
    root = Path(args.path or ".").resolve()
    if is_sentinel_itself(root) and not args.allow_self:
        raise CliError("refusing to analyse Sentinel's own source: run this from your business "
                       "project (or pass --path <project>); use --allow-self to override")
    try:
        provider = make_provider(args.ai)
    except ValueError as exc:
        raise CliError(str(exc)) from exc
    assert provider is not None  # choices exclude "off"
    _confirm_egress(provider, args, st)

    ws = Workspace(root)
    if ws.init():
        print(f"Initialised {ws.dir}")
    guideline_paths = [Path(g) for g in args.guidelines or []]
    auto = ws.dir / "guidelines"
    if auto.is_dir():
        guideline_paths.append(auto)

    log = TerminalLog(color=False if args.no_color else None)
    run_id = f"analysis-{datetime.now(UTC):%Y%m%d-%H%M%S}"
    store = AuditStore(ws.audit_path)
    tracker = ActivityTracker(store, run_id, sink=lambda ev: log(ev))
    log.banner(f"sentinel sdk analyze  project={root.name}  ai={provider.name}")
    try:
        result, run = run_analysis(root, guideline_paths, provider, tracker)
    except AnalysisError as exc:
        raise CliError(str(exc)) from exc
    finally:
        rows = read_tasks(store, run_id)
        store.close()
    ws.save_analysis(result)
    write_policy(ws)

    print()
    print_agent_table(st, rows)
    if result.understanding.get("summary"):
        print(f"\n  {st('Understanding', BOLD)}: {result.understanding['summary']}")
        for key in ("agents", "tools", "external_systems", "data_sources"):
            if result.understanding.get(key):
                print(f"    {key.replace('_', ' '):<17} {'; '.join(result.understanding[key][:6])}")
    print(f"\n  {st('Monitoring points', BOLD)}: {len(result.points)} identified ({_counts(result.points)})")
    print_points(st, result.points[:12], None, set())
    if len(result.points) > 12:
        print(f"   … {len(result.points) - 12} more: sentinel sdk points")
    for w in result.warnings[:5]:
        print(st(f"  ! {w}", YELLOW))
    if run.tracker.write_failures:
        print(st(f"  ! {run.tracker.write_failures} activity events could not be written", YELLOW))
    if result.project.files_skipped_sensitive:
        print(st(f"  ! not read (secret-looking): {', '.join(result.project.files_skipped_sensitive)}",
                 DIM))
    print("\nNext: sentinel sdk select -i   (nothing is monitored until you select, add a guard, "
          "and run the app)")
    return 0


def cmd_points(args: argparse.Namespace) -> int:
    ws, st = _workspace(args), _style(args)
    analysis = _analysis(ws)
    report = compute_status(ws, analysis)
    selected = set(ws.load_selected())
    pts = analysis.points
    if args.risk_min:
        floor = RISK_ORDER.index(Risk(args.risk_min))
        pts = [p for p in pts if RISK_ORDER.index(p.risk) >= floor]
    if args.category:
        pts = [p for p in pts if p.category.value == args.category]
    if args.state:
        pts = [p for p in pts if report.points[p.point_id].state.value == args.state]
    if args.json:
        print(json.dumps([{**p.model_dump(mode="json"), "state": report.points[p.point_id].state.value,
                           "selected": p.point_id in selected} for p in pts], indent=2))
        return 0
    print(f"{len(pts)} monitoring point(s)  ({_counts(pts) or 'none'})")
    print_points(st, pts, report.points, selected)
    print(st(f"\n{LEGEND}", DIM))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    ws, st = _workspace(args), _style(args)
    analysis = _analysis(ws)
    (pid,) = resolve_ids(analysis, [args.point])
    p = analysis.point(pid)
    assert p
    s = compute_status(ws, analysis).points[pid]
    print(st(f"{p.point_id}  {p.title}", BOLD))
    print(f"  category   {p.category.value}")
    print(f"  risk       {st(p.risk.value, BOLD, RISK_COLOR[p.risk])}  (static analysis: "
          f"{p.static_risk.value})")
    print(f"  state      {st(s.state.value, STATE_COLOR[s.state])}"
          + (f"   last runtime evaluation: {s.last_seen:%Y-%m-%d %H:%M:%S}Z "
             f"({s.evaluations} total)" if s.last_seen else ""))
    for note in s.notes:
        print(f"             ↳ {note}")
    print(f"  what       {p.description}")
    print(f"  why        {p.reason}")
    if p.exposed_via_tool:
        print(f"  exposure   reachable by an LLM as tool '{p.exposed_via_tool}'")
    for n in p.risk_notes:
        print(f"  risk note  {n}")
    for n in p.ai_notes:
        print(f"  AI note    {n}")
    if p.guideline_refs:
        print(f"  guidelines {', '.join(p.guideline_refs)}")
    if p.source == "ai":
        print(st("  source     AI-suggested; location exists but static analysis did not confirm it",
                 YELLOW))
    print("  locations")
    for loc in p.locations:
        print(f"    {loc.file}:{loc.line}  in {loc.symbol}\n      {loc.snippet}")
    if s.code_refs:
        print(f"  guards     {', '.join(s.code_refs)}")
    return 0


def _select_interactive(ws: Workspace, analysis: AnalysisResult, st: Style) -> int:
    pts = analysis.points
    current = set(ws.load_selected())
    report = compute_status(ws, analysis)
    print_points(st, pts, report.points, current, numbered=True)
    print("\nSelect points to monitor: numbers/ranges (1,3,5-7) · a=all · h=high+critical · "
          "n=none · Enter=keep current · q=cancel")
    while True:
        try:
            new = parse_selection(input("> "), pts, current)
        except CliError as exc:
            print(st(f"  {exc}", RED))
            continue
        except EOFError:
            new = None
        break
    if new is None:
        print("Cancelled; selection unchanged.")
        return 0
    return _apply_selection(ws, analysis, new, current)


def _apply_selection(ws: Workspace, analysis: AnalysisResult, new: set[str], current: set[str]) -> int:
    added, removed = sorted(new - current), sorted(current - new)
    if added:
        ws.select(added)
    if removed:
        ws.deselect(removed)
    n, rules = write_policy(ws)
    print(f"Selected {len(added)} added, {len(removed)} removed → {n} monitored point(s); "
          f"policy regenerated ({rules} rules).")
    if added:
        print("These are SELECTED only — not monitored until you add a guard and run the app:")
        for pid in added[:8]:
            print(f"  sentinel sdk snippet {pid}")
    return 0


def cmd_select(args: argparse.Namespace) -> int:
    ws, st = _workspace(args), _style(args)
    analysis = _analysis(ws)
    if args.interactive:
        return _select_interactive(ws, analysis, st)
    current = set(ws.load_selected())
    new = set(current)
    if args.all:
        new |= {p.point_id for p in analysis.points}
    if args.min_risk:
        floor = RISK_ORDER.index(Risk(args.min_risk))
        new |= {p.point_id for p in analysis.points if RISK_ORDER.index(p.risk) >= floor}
    if args.category:
        new |= {p.point_id for p in analysis.points if p.category.value == args.category}
    new |= set(resolve_ids(analysis, args.points))
    if new == current:
        raise CliError("nothing to select: give point ids, --all, --min-risk, --category or -i")
    return _apply_selection(ws, analysis, new, current)


def cmd_deselect(args: argparse.Namespace) -> int:
    ws = _workspace(args)
    analysis = _analysis(ws)
    current = set(ws.load_selected())
    new = set() if args.all else current - set(resolve_ids(analysis, args.points))
    return _apply_selection(ws, analysis, new, current)


def cmd_status(args: argparse.Namespace) -> int:
    ws, st = _workspace(args), _style(args)
    analysis = _analysis(ws)
    rep = compute_status(ws, analysis)
    by_state = {s: [p for p in analysis.points if rep.points[p.point_id].state is s]
                for s in PointState}
    print(st(f"Monitoring status — {ws.project_root.name}  (mode: {ws.load_config().mode})", BOLD))
    for s in PointState:
        print(f"  {st(f'{s.value:<12}', STATE_COLOR[s])} {len(by_state[s])}")
    audit = {None: "no runtime events yet", True: "hash chain verified",
             False: f"BROKEN — {rep.audit_detail}"}[rep.audit_ok]
    print(f"  audit trail: {audit}")
    shown = [p for p in analysis.points if rep.points[p.point_id].state is not PointState.IDENTIFIED]
    if shown:
        print()
        print_points(st, shown, rep.points, set(ws.load_selected()))
        for p in shown:
            for note in rep.points[p.point_id].notes:
                print(st(f"   {p.point_id}: {note}", DIM))
    active = len(by_state[PointState.ACTIVE])
    print(f"\n{active} of {len(analysis.points)} identified points are actively monitored right now.")
    for pid, where in rep.orphan_refs.items():
        print(st(f"! guard for unknown point {pid} at {', '.join(where)} (re-run analyze?)", YELLOW))
    print(st(LEGEND, DIM))
    return 0


def cmd_activity(args: argparse.Namespace) -> int:
    ws, st = _workspace(args), _style(args)
    if not ws.audit_path.exists():
        raise CliError("no activity yet — run `sentinel sdk analyze`")
    store = AuditStore(ws.audit_path, read_only=True)
    try:
        run_id = args.run or latest_run_id(store)
        rows = read_tasks(store, None if args.all else run_id)
    finally:
        store.close()
    if not rows:
        print("no agent activity recorded")
        return 0
    print(st("Agent activity" + ("" if args.all else f" — run {run_id}"), BOLD))
    for title, status in (("Running", "RUNNING"), ("Failed", "FAILED"), ("Completed", "COMPLETED")):
        sel = [r for r in rows if r.status == status]
        if sel:
            print(f"\n {title} ({len(sel)})")
            print_agent_table(st, sel, header=False)
    return 0


def snippet_for(p: MonitoringPoint) -> str:
    loc = p.locations[0]
    opts = []
    dest = next((a for a in loc.arg_names if a in DEST_ARG_NAMES), None)
    if p.category in {Category.MESSAGING, Category.EXTERNAL_API}:
        opts.append(f'destination_arg="{dest}"' if dest else
                    'destination_arg="<name of the argument holding the recipient/URL>"')
    if p.category is Category.SENSITIVE_DATA:
        opts.append('produces=["pii"]')
    arg_list = (", " + ", ".join(opts)) if opts else ""
    lines = [f"# {p.point_id} — {p.title}", f"# {loc.file}:{loc.line}  in {loc.symbol}"]
    if p.category is Category.SENSITIVE_DATA:
        lines.append('# produces=["pii"] labels what this returns, so later guarded sends are checked')
    lines.append("")
    if loc.symbol != "<module>":
        fn = loc.symbol.split(".")[-1]
        lines += ["from sentinel.sdk import guard", "",
                  f'@guard("{p.point_id}"{arg_list})', f"def {fn}(...):", "    ..."]
        lines += ["", "# or wrap just the call:"]
    sink = p.category in {Category.MESSAGING, Category.EXTERNAL_API}
    lines += ["from sentinel.sdk import monitor", "",
              f'with monitor("{p.point_id}"' + (", destination=<recipient>" if sink else "") + "):",
              f"    ...  # {loc.snippet[:70]}"]
    return "\n".join(lines)


def cmd_snippet(args: argparse.Namespace) -> int:
    analysis = _analysis(_workspace(args))
    (pid,) = resolve_ids(analysis, [args.point])
    p = analysis.point(pid)
    assert p
    print(snippet_for(p))
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    ws = _workspace(args)
    n, rules = write_policy(ws)
    print(f"policy regenerated: {n} selected point(s), {rules} rule(s) → {ws.policy_path}")
    cfg = ws.load_config()
    domains = cfg.allowed_destination_domains or "none (sensitive data may not leave)"
    print(f"mode={cfg.mode} default_action={cfg.default_action} allowed_destination_domains={domains}")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    ws = _workspace(args)
    return watch(ws.audit_path, TerminalLog(color=False if args.no_color else None, verbose=args.verbose),
                 interval=args.interval, heartbeat_timeout=1e9, from_start=args.from_start)


# ---- wiring ---------------------------------------------------------------------------------
def register(sub: argparse._SubParsersAction) -> None:
    sdk = sub.add_parser("sdk", help="analyse a business project and manage its monitoring points")
    ssub = sdk.add_subparsers(dest="sdk_command", required=True)

    def add(name: str, func, help_: str) -> argparse.ArgumentParser:
        p = ssub.add_parser(name, help=help_)
        p.add_argument("--path", help="business project directory (default: current directory)")
        p.set_defaults(func=_wrap(func))
        return p

    add("init", cmd_init, "create .sentinel/ in the project").add_argument(
        "--allow-self", action="store_true", help=argparse.SUPPRESS)

    a = add("analyze", cmd_analyze, "run the SDK agents against the project")
    a.add_argument("--guidelines", "-g", action="append", metavar="FILE_OR_DIR",
                   help="external guidelines/policies for the agents to consider (repeatable)")
    a.add_argument("--ai", choices=["offline", "groq", "auto"], default="offline",
                   help="offline = no model, nothing leaves your machine (default); groq/auto send "
                        "redacted excerpts to the model provider")
    a.add_argument("--yes", "-y", action="store_true", help="confirm sending excerpts to the provider")
    a.add_argument("--allow-self", action="store_true", help=argparse.SUPPRESS)

    p = add("points", cmd_points, "list monitoring points with their lifecycle state")
    p.add_argument("--risk-min", choices=[r.value for r in Risk])
    p.add_argument("--category", choices=[c.value for c in Category])
    p.add_argument("--state", choices=[s.value for s in PointState])
    p.add_argument("--json", action="store_true")

    add("show", cmd_show, "details, evidence and state of one point").add_argument("point")

    s = add("select", cmd_select, "choose which points to monitor")
    s.add_argument("points", nargs="*")
    s.add_argument("-i", "--interactive", action="store_true")
    s.add_argument("--all", action="store_true")
    s.add_argument("--min-risk", choices=[r.value for r in Risk])
    s.add_argument("--category", choices=[c.value for c in Category])

    d = add("deselect", cmd_deselect, "stop monitoring points")
    d.add_argument("points", nargs="*")
    d.add_argument("--all", action="store_true")

    add("status", cmd_status, "what is identified, selected, implemented and actually active")

    ac = add("activity", cmd_activity, "what each SDK agent has done / is doing")
    ac.add_argument("--run")
    ac.add_argument("--all", action="store_true", help="all runs")

    add("snippet", cmd_snippet, "code to add a guard for a point").add_argument("point")
    add("policy", cmd_policy, "regenerate .sentinel/policy.yaml from selection + config")

    w = add("watch", cmd_watch, "live-tail the project's audit trail (agent activity + runtime guards)")
    w.add_argument("--interval", type=float, default=1.0)
    w.add_argument("--from-start", action="store_true")


def _wrap(func):
    def run(args: argparse.Namespace) -> int:
        try:
            return func(args)
        except (CliError, WorkspaceError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    return run
