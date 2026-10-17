"""End-to-end: the real CLI and the independent watcher process logic."""

from __future__ import annotations

import io
import subprocess
import sys
from pathlib import Path

from sentinel.audit import AuditStore
from sentinel.cli import main
from sentinel.contracts import EventType, SecurityEvent
from sentinel.termlog import TerminalLog
from sentinel.watch import watch


def test_full_demo_passes_all_checks(tmp_path, capsys):
    db = tmp_path / "demo.db"
    assert main(["--no-color", "demo", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "checks passed" in out and "✘ CHECK" not in out
    assert main(["audit", "verify", "--db", str(db)]) == 0
    assert main(["audit", "report", "--db", str(db), "--run", "run-B"]) == 0
    assert "R-DF-SENSITIVE-EXTERNAL" in capsys.readouterr().out


def test_demo_does_not_modify_repo_policy(tmp_path):
    repo_policy = Path(__file__).resolve().parents[2] / "policies" / "default.yaml"
    before = repo_policy.read_bytes()
    main(["--no-color", "demo", "--scenario", "D", "--db", str(tmp_path / "d.db")])
    assert repo_policy.read_bytes() == before


def test_policy_check(tmp_path, capsys):
    assert main(["policy", "check"]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("version_label: x\n")
    assert main(["policy", "check", "--policy", str(bad)]) == 2


def test_cli_entrypoint_runs_as_module():
    out = subprocess.run([sys.executable, "-m", "sentinel.cli", "policy", "check"],
                         capture_output=True, text=True, check=True)
    assert out.stdout.startswith("OK")


def test_watch_alerts_on_missing_heartbeat_and_tamper(tmp_path):
    db = tmp_path / "w.db"
    store = AuditStore(db)
    store.append(SecurityEvent(trace_id="t", actor_id="agent.a", event_type=EventType.TOOL_CALL_REQUESTED,
                               tool_name="docs.read"))
    buf = io.StringIO()
    watch(db, TerminalLog(buf, color=False), interval=0, heartbeat_timeout=-1, from_start=True,
          max_iterations=1)
    out = buf.getvalue()
    assert "REQUEST" in out and "TELEMETRY_MISSING" in out

    store._conn.execute("DROP TRIGGER events_no_update")
    store._conn.execute("UPDATE events SET body=replace(body,'agent.a','agent.b')")
    buf = io.StringIO()
    watch(db, TerminalLog(buf, color=False), interval=0, heartbeat_timeout=60, max_iterations=1)
    assert "AUDIT_CHAIN_BROKEN" in buf.getvalue()
    store.close()


def test_terminal_output_strips_escape_sequences():
    buf = io.StringIO()
    TerminalLog(buf, color=False)(SecurityEvent(
        trace_id="t", actor_id="agent.\x1b[2Jevil", event_type=EventType.TOOL_CALL_REQUESTED,
        tool_name="docs.read"))
    assert "\x1b" not in buf.getvalue()
