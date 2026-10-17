"""Runtime guards, policy generation and the evidence-based lifecycle."""

from __future__ import annotations

import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.ai.providers import OfflineHeuristicProvider
from sentinel.audit import AuditStore
from sentinel.contracts import Decision, EventType
from sentinel.sdk import client as sdk_client
from sentinel.sdk.activity import ActivityTracker
from sentinel.sdk.agents import run_analysis
from sentinel.sdk.client import (
    Sentinel,
    SentinelApprovalRequired,
    SentinelDenied,
    SentinelUnavailable,
)
from sentinel.sdk.lifecycle import compute_status
from sentinel.sdk.models import Category, PointState
from sentinel.sdk.policygen import write_policy
from sentinel.sdk.workspace import Workspace, find_workspace

APP = '''
def get_customer_records():
    return [{"name": "Ada", "ssn": "123-45-6789"}]


def send_report(client, to, body):
    client.sendmail("reports@corp.example", to, body)
'''

DRIVER = '''
import sys
from pathlib import Path
from biz import get_customer_records, send_report

class Mail:
    def sendmail(self, *a):
        Path("sent.txt").write_text("sent")

rows = get_customer_records()
try:
    send_report(Mail(), sys.argv[1], "hello")
    print("RESULT sent")
except Exception as exc:
    print("RESULT", type(exc).__name__)
'''


@pytest.fixture
def biz(tmp_path: Path):
    """A tiny business project analysed by the SDK; returns (workspace, ids)."""
    root = tmp_path / "biz"
    root.mkdir()
    (root / "biz.py").write_text(APP)
    (root / "driver.py").write_text(DRIVER)
    ws = Workspace(root)
    ws.init()
    store = AuditStore(ws.audit_path)
    result, _ = run_analysis(root, [], OfflineHeuristicProvider(), ActivityTracker(store, "a"))
    store.close()
    ws.save_analysis(result)
    src = next(p for p in result.points if p.category is Category.SENSITIVE_DATA)
    sink = next(p for p in result.points if p.category is Category.MESSAGING)
    assert src.locations[0].symbol == "get_customer_records"
    assert sink.locations[0].symbol == "send_report"
    return ws, src.point_id, sink.point_id


def instrument(ws: Workspace, src_id: str, sink_id: str) -> None:
    f = ws.project_root / "biz.py"
    text = f.read_text()
    text = text.replace("def get_customer_records", f'@guard("{src_id}", produces=["pii"])\ndef get_customer_records')
    text = text.replace("def send_report", f'@guard("{sink_id}", destination_arg="to")\ndef send_report')
    f.write_text("from sentinel.sdk import guard\n" + text)


def run_driver(ws: Workspace, dest: str) -> str:
    out = subprocess.run([sys.executable, "driver.py", dest], cwd=ws.project_root,
                         capture_output=True, text=True, timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return next(ln for ln in out.stdout.splitlines() if ln.startswith("RESULT"))


def status(ws: Workspace, **kw):
    return compute_status(ws, ws.load_analysis(), **kw).points


def events(ws: Workspace, etype=None):
    store = AuditStore(ws.audit_path, read_only=True)
    try:
        return [s.event for s in store.all()
                if s.event.metadata.get("point_id") and (etype is None or s.event.event_type is etype)]
    finally:
        store.close()


# ---- lifecycle: each state requires its own evidence -----------------------------------------
def test_lifecycle_requires_evidence_at_every_step(biz):
    ws, src_id, sink_id = biz
    assert status(ws)[sink_id].state is PointState.IDENTIFIED

    ws.select([src_id, sink_id])
    write_policy(ws)
    s = status(ws)[sink_id]
    assert s.state is PointState.SELECTED and any("no guard in source" in n for n in s.notes)

    instrument(ws, src_id, sink_id)
    s = status(ws)[sink_id]
    assert s.state is PointState.IMPLEMENTED                      # code present ≠ working
    assert s.code_refs and any("no runtime evaluation" in n for n in s.notes)

    assert run_driver(ws, "x@corp.example") == "RESULT sent"
    st = status(ws)
    assert st[sink_id].state is PointState.ACTIVE and st[src_id].state is PointState.ACTIVE
    assert st[sink_id].evaluations == 1 and st[sink_id].last_seen is not None


def test_active_expires_outside_window(biz):
    ws, src_id, sink_id = biz
    ws.select([src_id, sink_id]); write_policy(ws); instrument(ws, src_id, sink_id)
    run_driver(ws, "x@corp.example")
    later = datetime.now(UTC) + timedelta(hours=48)
    s = status(ws, now=later)[sink_id]
    assert s.state is PointState.IMPLEMENTED and any("outside" in n for n in s.notes)


def test_tampered_audit_trail_cannot_yield_active(biz):
    ws, src_id, sink_id = biz
    ws.select([src_id, sink_id]); write_policy(ws); instrument(ws, src_id, sink_id)
    run_driver(ws, "x@corp.example")
    store = AuditStore(ws.audit_path)
    store._conn.execute("DROP TRIGGER events_no_update")
    store._conn.execute("UPDATE events SET body = replace(body, 'ALLOW', 'ALLOW ') "
                        "WHERE event_type = 'policy_decision'")
    store.close()
    rep = compute_status(ws, ws.load_analysis())
    assert rep.audit_ok is False
    assert rep.points[sink_id].state is PointState.IMPLEMENTED
    assert any("chain is broken" in n for n in rep.points[sink_id].notes)


def test_deselected_guard_is_not_monitored_and_says_so(biz):
    ws, src_id, sink_id = biz
    ws.select([src_id, sink_id]); write_policy(ws); instrument(ws, src_id, sink_id)
    ws.deselect([sink_id]); write_policy(ws)
    run_driver(ws, "x@corp.example")
    s = status(ws)[sink_id]
    assert s.state is PointState.IDENTIFIED and any("NOT monitored" in n for n in s.notes)
    decisions = [e for e in events(ws, EventType.POLICY_DECISION) if e.metadata["point_id"] == sink_id]
    assert decisions[0].policy_decision is Decision.NOT_EVALUATED
    assert decisions[0].reason_codes == ("POINT_NOT_SELECTED",)


def test_commented_out_guard_does_not_count(biz):
    ws, src_id, sink_id = biz
    ws.select([sink_id]); write_policy(ws)
    (ws.project_root / "biz.py").write_text(f'# @guard("{sink_id}")\n' + (ws.project_root / "biz.py").read_text())
    assert status(ws)[sink_id].state is PointState.SELECTED


def test_orphan_guard_reference_reported(biz):
    ws, src_id, sink_id = biz
    (ws.project_root / "x.py").write_text('from sentinel.sdk import guard\n@guard("MP-0BADC0DE")\ndef f(): ...\n')
    rep = compute_status(ws, ws.load_analysis())
    assert "MP-0BADC0DE" in rep.orphan_refs


# ---- enforcement through the real policy engine, in a separate process ------------------------
def test_observe_mode_logs_would_block_and_does_not_interfere(biz):
    ws, src_id, sink_id = biz
    ws.select([src_id, sink_id]); write_policy(ws); instrument(ws, src_id, sink_id)
    assert run_driver(ws, "attacker@evil.example") == "RESULT sent"      # not blocked in observe
    assert (ws.project_root / "sent.txt").exists()
    dec = [e for e in events(ws, EventType.POLICY_DECISION) if e.metadata["point_id"] == sink_id][0]
    assert dec.policy_decision is Decision.DENY and dec.metadata["would_block"] is True
    assert dec.reason_codes == ("SENSITIVE_DATA_TO_UNAPPROVED_DESTINATION",)
    assert dec.metadata["tainted_labels"] == ["pii"]
    assert dec.destination == "attacker@evil.example"


def test_enforce_mode_blocks_before_the_function_runs(biz):
    ws, src_id, sink_id = biz
    (ws.dir / "config.yaml").write_text((ws.dir / "config.yaml").read_text().replace("mode: observe", "mode: enforce"))
    ws.select([src_id, sink_id]); write_policy(ws); instrument(ws, src_id, sink_id)
    assert run_driver(ws, "attacker@evil.example") == "RESULT SentinelDenied"
    assert not (ws.project_root / "sent.txt").exists()                   # side effect never happened
    executed = [e for e in events(ws, EventType.TOOL_EXECUTED) if e.metadata["point_id"] == sink_id]
    assert executed == []
    src_exec = [e for e in events(ws, EventType.TOOL_EXECUTED) if e.metadata["point_id"] == src_id]
    assert len(src_exec) == 1                                             # the source ran, was recorded


def test_allowed_domains_permit_internal_destination(biz):
    ws, src_id, sink_id = biz
    cfg = ws.dir / "config.yaml"
    cfg.write_text(cfg.read_text().replace("mode: observe", "mode: enforce").replace(
        "allowed_destination_domains: []", "allowed_destination_domains: [corp.example]"))
    ws.select([src_id, sink_id]); write_policy(ws); instrument(ws, src_id, sink_id)
    assert run_driver(ws, "boss@corp.example") == "RESULT sent"
    assert run_driver(ws, "boss@evil.example") == "RESULT SentinelDenied"


def test_audit_never_records_argument_values(biz):
    ws, src_id, sink_id = biz
    ws.select([src_id, sink_id]); write_policy(ws); instrument(ws, src_id, sink_id)
    run_driver(ws, "x@corp.example")
    blob = " ".join(e.model_dump_json() for e in events(ws))
    assert "hello" not in blob and "123-45-6789" not in blob
    req = [e for e in events(ws, EventType.TOOL_CALL_REQUESTED) if e.metadata["point_id"] == sink_id][0]
    assert req.metadata["arg_names"] == ["client", "to", "body"]


# ---- in-process behaviour ---------------------------------------------------------------------
@pytest.fixture
def sentinel_for(biz):
    ws, src_id, sink_id = biz
    made = []

    def make(mode="observe", action=None, select=True):
        import re

        cfg = ws.dir / "config.yaml"
        text = re.sub(r"(?m)^mode: \w+$", f"mode: {mode}", cfg.read_text())
        text = re.sub(r"(?m)^point_actions: .*$", f"point_actions: {{{sink_id}: {action}}}" if action
                      else "point_actions: {}", text)
        cfg.write_text(text)
        if select:
            ws.select([src_id, sink_id])
        write_policy(ws)
        s = Sentinel(ws)
        made.append(s)
        return s

    yield ws, src_id, sink_id, make
    for s in made:
        s.close()


def test_require_approval_action(sentinel_for):
    ws, src_id, sink_id, make = sentinel_for
    s = make("enforce", "REQUIRE_APPROVAL")
    with pytest.raises(SentinelApprovalRequired) as exc:
        s.check(sink_id, destination="a@corp.example")
    assert exc.value.decision == "REQUIRE_APPROVAL"


def test_explicit_deny_action_in_enforce(sentinel_for):
    ws, src_id, sink_id, make = sentinel_for
    with pytest.raises(SentinelDenied, match="SDK_POINT_DENY"):
        make("enforce", "DENY").check(sink_id)


def test_runs_isolate_taint(sentinel_for):
    ws, src_id, sink_id, make = sentinel_for
    s = make("enforce")
    with s.run("req-1"):
        with s.monitor(src_id, produces=["pii"]):
            pass
        with pytest.raises(SentinelDenied):
            s.check(sink_id, destination="x@evil.example")
    with s.run("req-2"):                        # a different request is not tainted
        assert s.check(sink_id, destination="x@evil.example").decision == "ALLOW"


def test_enforce_fails_closed_when_policy_missing_or_audit_down(sentinel_for):
    ws, src_id, sink_id, make = sentinel_for
    s = make("enforce")
    s.store.fail_writes = True
    with pytest.raises(SentinelUnavailable, match="audit"):
        s.check(sink_id)
    s.store.fail_writes = False
    s._engine = None
    with pytest.raises(SentinelUnavailable, match="policy"):
        s.check(sink_id)


def test_observe_mode_degrades_visibly_not_fatally(sentinel_for, capsys):
    ws, src_id, sink_id, make = sentinel_for
    s = make("observe")
    s.store.fail_writes = True
    s._engine = None
    assert s.check(sink_id).reasons == ("POLICY_UNAVAILABLE",)
    assert "WARNING" in capsys.readouterr().err


def test_policy_reload_picks_up_selection_changes(sentinel_for):
    ws, src_id, sink_id, make = sentinel_for
    s = make("enforce", select=False)
    assert s.check(sink_id).reasons == ("POINT_NOT_SELECTED",)
    ws.select([sink_id]); write_policy(ws)
    s._last_policy_check = 0
    assert s.check(sink_id).decision == "ALLOW"


def test_guard_preserves_function_metadata_and_exceptions(sentinel_for):
    ws, src_id, sink_id, make = sentinel_for
    s = make("observe")

    @s.guard(sink_id)
    def boom(x: int):
        """doc"""
        raise ZeroDivisionError

    assert boom.__name__ == "boom" and boom.__doc__ == "doc"
    with pytest.raises(ZeroDivisionError):
        boom(1)
    done = [e for e in events(ws, EventType.TOOL_EXECUTED) if e.metadata["point_id"] == sink_id][-1]
    assert done.execution_status.value == "FAILED" and done.metadata["error"] == "ZeroDivisionError"


def test_async_functions_are_guarded(sentinel_for):
    import asyncio

    ws, src_id, sink_id, make = sentinel_for
    s = make("enforce", "DENY")

    @s.guard(sink_id)
    async def send():
        return "sent"

    with pytest.raises(SentinelDenied):
        asyncio.run(send())
    s2 = make("observe")

    @s2.guard(sink_id)
    async def send2():
        return "sent"

    assert asyncio.run(send2()) == "sent"


def test_bad_labels_fail_at_decoration_time(sentinel_for):
    ws, src_id, sink_id, make = sentinel_for
    s = make()
    with pytest.raises(ValueError, match="unknown data label"):
        s.guard(sink_id, labels=["top-secret"])


def test_unconfigured_project_runs_unmonitored_and_warns(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SENTINEL_PROJECT", raising=False)
    monkeypatch.setattr(sdk_client, "_default", None)

    @sdk_client.guard("MP-11111111")
    def f():
        return 5

    assert f() == 5 and "NOT monitoring" in capsys.readouterr().err
    monkeypatch.setattr(sdk_client, "_default", None)
    monkeypatch.setenv("SENTINEL_REQUIRE", "1")

    @sdk_client.guard("MP-22222222")
    def g():
        return 6

    with pytest.raises(Exception, match="no .sentinel"):
        g()
    monkeypatch.setattr(sdk_client, "_default", None)


def test_workspace_discovery_walks_up(biz):
    ws, *_ = biz
    sub = ws.project_root / "pkg" / "deep"
    sub.mkdir(parents=True)
    assert find_workspace(sub).project_root == ws.project_root


def test_generated_policy_is_valid_and_labelled_derived(biz):
    ws, src_id, sink_id = biz
    ws.select([src_id, sink_id])
    write_policy(ws)
    text = ws.policy_path.read_text()
    assert text.startswith("# GENERATED") and sink_id[3:] in text
    from sentinel.policy import PolicyEngine
    eng = PolicyEngine(ws.policy_path)
    assert "R-DF-SENSITIVE-EXTERNAL" in [r.id for r in eng.bundle.rules]
