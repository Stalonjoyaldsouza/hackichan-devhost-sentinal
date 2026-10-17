"""Command-line entry point. All output goes to the terminal."""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from sentinel import demo
from sentinel.ai import make_provider
from sentinel.audit import AuditStore
from sentinel.investigator import reconstruct
from sentinel.policy import PolicyEngine, PolicyError, describe
from sentinel.runtime import DEFAULT_POLICY
from sentinel.termlog import TerminalLog
from sentinel.watch import watch

DEFAULT_DB_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", "var"))


def _log(args: argparse.Namespace) -> TerminalLog:
    return TerminalLog(verbose=args.verbose, color=False if args.no_color else None)


def cmd_demo(args: argparse.Namespace) -> int:
    db = Path(args.db) if args.db else (
        DEFAULT_DB_DIR / f"sentinel-demo-{datetime.now():%Y%m%d-%H%M%S}.db")
    db.parent.mkdir(parents=True, exist_ok=True)
    selected = list(demo.SCENARIOS) if args.scenario == "all" else [args.scenario]
    try:
        provider = make_provider(args.ai)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    checks = demo.run(selected, db, _log(args), provider)
    return 0 if checks and all(ok for *_, ok in checks) else 1


def cmd_watch(args: argparse.Namespace) -> int:
    return watch(Path(args.db), _log(args), interval=args.interval,
                 heartbeat_timeout=args.heartbeat_timeout, from_start=args.from_start)


def _open_existing(db: str) -> AuditStore:
    if not Path(db).exists():
        sys.exit(f"audit store not found: {db}")
    return AuditStore(db, read_only=True)


def cmd_audit_verify(args: argparse.Namespace) -> int:
    store = _open_existing(args.db)
    report = store.verify_chain()
    print(f"chain {'VERIFIED' if report.ok else 'BROKEN'}: {report.checked} events checked"
          + (f" — {report.detail}" if report.detail else ""))
    return 0 if report.ok else 2


def cmd_audit_report(args: argparse.Namespace) -> int:
    report = reconstruct(_open_existing(args.db), args.run)
    print(report.render())
    return 0 if report.chain_ok else 2


def cmd_policy_check(args: argparse.Namespace) -> int:
    try:
        engine = PolicyEngine(Path(args.policy))
    except PolicyError as exc:
        print(f"INVALID: {exc}")
        return 2
    info = describe(engine.bundle)
    print(f"OK  version={engine.version}")
    print(f"    tools={', '.join(info['tools'])}")
    print(f"    rules={', '.join(info['rules'])}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="AI agent security control plane (MVP)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="also show heartbeats, OK health checks and synthetic canary traffic")
    p.add_argument("--no-color", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("demo", help="run the scripted MVP scenarios with live terminal output")
    d.add_argument("--scenario", default="all", choices=["all", *demo.SCENARIOS])
    d.add_argument("--db", help="audit store path (default: var/sentinel-demo-<timestamp>.db)")
    d.add_argument("--ai", choices=["auto", "groq", "offline", "off"], default=None,
                   help="advisory AI agents: auto = Groq if GROQ_API_KEY is set, else the "
                        "offline heuristic stand-in (default: $SENTINEL_AI or auto)")
    d.set_defaults(func=cmd_demo)

    w = sub.add_parser("watch", help="independently tail an audit store and alert on gaps")
    w.add_argument("--db", required=True)
    w.add_argument("--interval", type=float, default=1.0)
    w.add_argument("--heartbeat-timeout", type=float, default=15.0)
    w.add_argument("--from-start", action="store_true", help="print existing events first")
    w.set_defaults(func=cmd_watch)

    a = sub.add_parser("audit", help="inspect an audit store")
    asub = a.add_subparsers(dest="audit_cmd", required=True)
    av = asub.add_parser("verify", help="verify the hash chain")
    av.add_argument("--db", required=True)
    av.set_defaults(func=cmd_audit_verify)
    ar = asub.add_parser("report", help="evidence-linked timeline for a run")
    ar.add_argument("--db", required=True)
    ar.add_argument("--run", required=True)
    ar.set_defaults(func=cmd_audit_report)

    pol = sub.add_parser("policy", help="policy bundle tools")
    psub = pol.add_subparsers(dest="policy_cmd", required=True)
    pc = psub.add_parser("check", help="validate a policy bundle")
    pc.add_argument("--policy", default=str(DEFAULT_POLICY))
    pc.set_defaults(func=cmd_policy_check)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    started = time.time()
    try:
        return int(args.func(args))
    finally:
        if args.command == "demo":
            print(f"   ({time.time() - started:.2f}s)")


if __name__ == "__main__":
    raise SystemExit(main())
