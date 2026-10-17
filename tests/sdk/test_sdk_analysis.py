"""Scanner, detectors, guidelines and the analysis agents."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.ai.providers import OfflineHeuristicProvider, ProviderError
from sentinel.audit import AuditStore
from sentinel.sdk.activity import ActivityTracker, read_tasks
from sentinel.sdk.agents import AnalysisError, AnalysisRun, load_guidelines, run_analysis
from sentinel.sdk.detectors import analyse_files
from sentinel.sdk.models import Category, Risk
from sentinel.sdk.scanner import SourceFile, is_sentinel_itself, redact, scan


def analyse(project, guidelines=None, provider=None, store=None):
    tracker = ActivityTracker(store, "run-t")
    paths = [guidelines] if guidelines else []
    return run_analysis(project, paths, provider or OfflineHeuristicProvider(), tracker)


# ---- scanner ----------------------------------------------------------------------------------
def test_scanner_inventory_and_secret_files_never_read(project):
    inv = scan(project)
    assert inv.profile.files_scanned == 3
    assert inv.profile.files_skipped_sensitive == [".env"]
    assert "Groq SDK" in inv.profile.frameworks and "requests" in inv.profile.dependencies
    assert all(".env" not in f.rel for f in inv.files)
    assert "sk-live" not in inv.profile.model_dump_json()


def test_scanner_skips_noise_dirs_symlinks_and_big_files(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("eval(1)")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "y.py").write_text("eval(1)")
    outside = tmp_path.parent / "outside.py"
    outside.write_text("eval(1)")
    (tmp_path / "link.py").symlink_to(outside)
    (tmp_path / "big.py").write_text("x = 1\n" * 200_000)
    (tmp_path / "ok.py").write_text("print(1)\n")
    inv = scan(tmp_path)
    assert [f.rel for f in inv.files] == ["ok.py"]
    assert inv.profile.files_skipped_other >= 2


@pytest.mark.parametrize("text,gone", [
    ('api_key = "abcd1234efgh5678"', "abcd1234efgh5678"),
    ("token: sk-ABCDEFGHIJKLMNOPQRSTUV", "sk-ABCDEFGHIJKLMNOPQRSTUV"),
    ("key=AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----", "MIIE"),
    ("x = 'gsk_abcdefghijklmnopqrstuvwxyz'", "gsk_abcdefghijklmnopqrstuvwxyz"),
])
def test_redact(text, gone):
    assert gone not in redact(text)


def test_refuses_sentinels_own_tree():
    assert is_sentinel_itself(Path(__file__).resolve().parents[2])


# ---- detectors --------------------------------------------------------------------------------
def src(code: str, name: str = "app.py") -> list[SourceFile]:
    return [SourceFile(name, "python", code, code.splitlines())]


def by_cat(points, cat):
    return [p for p in points if p.category is cat]


def test_example_project_points(project):
    result, _ = analyse(project)
    cats = {p.category for p in result.points}
    assert {Category.MESSAGING, Category.EXTERNAL_API, Category.CODE_EXECUTION, Category.DATABASE,
            Category.SENSITIVE_DATA, Category.SECRET_ACCESS, Category.LLM_CALL,
            Category.TOOL_CALL, Category.INTER_AGENT} <= cats
    shell = next(p for p in result.points if p.category is Category.CODE_EXECUTION)
    assert shell.risk is Risk.CRITICAL and shell.locations[0].file == "tools.py"
    assert shell.exposed_via_tool == "run_report"
    # the secret VALUE in .env is never in the results, only the env var name
    assert "sk-live" not in result.model_dump_json()
    assert any("PAYMENTS_API_KEY" in p.title for p in result.points)


def test_ids_stable_across_line_shifts(project):
    a, _ = analyse(project)
    tools = project / "tools.py"
    tools.write_text("# new header\n# another line\n" + tools.read_text())
    b, _ = analyse(project)
    assert {p.point_id for p in a.points} == {p.point_id for p in b.points}
    moved = next(p for p in b.points if p.category is Category.CODE_EXECUTION)
    orig = next(p for p in a.points if p.point_id == moved.point_id)
    assert moved.locations[0].line == orig.locations[0].line + 2


def test_import_aliases_and_variable_types_resolved():
    code = """
import subprocess as sp
import requests as rq
from openai import OpenAI
client = OpenAI()
s = rq.Session()
def f(cmd, url):
    sp.run(cmd, shell=True)
    s.post(url, json={})
    client.chat.completions.create(model="m", messages=[], tools=[1])
"""
    pts, _, _ = analyse_files(src(code))
    assert any(p.category is Category.CODE_EXECUTION and p.risk is Risk.CRITICAL for p in pts)
    assert any(p.category is Category.EXTERNAL_API for p in pts)
    llm = by_cat(pts, Category.LLM_CALL)
    assert llm and llm[0].risk is Risk.HIGH and "tools enabled" in llm[0].title


def test_dynamic_sql_and_drop(tmp_path):
    code = '''
import sqlite3
def a(conn, name):
    conn.execute(f"SELECT * FROM users WHERE n = '{name}'")
def b(conn):
    conn.execute("DROP TABLE users")
def c(conn):
    conn.execute("SELECT 1")
'''
    pts, _, _ = analyse_files(src(code))
    risks = {p.locations[0].symbol: p.risk for p in by_cat(pts, Category.DATABASE)}
    assert risks["a"] is Risk.HIGH and risks["b"] is Risk.CRITICAL and risks["c"] is Risk.MEDIUM


def test_tool_exposure_raises_risk_one_level():
    code = '''
import os
def tool(f): return f
@tool
def danger(x):
    os.remove(x)
def plain(x):
    os.remove(x)
'''
    pts, tools, _ = analyse_files(src(code))
    fs = {p.locations[0].symbol: p for p in by_cat(pts, Category.FILE_SYSTEM)}
    assert fs["danger"].risk is Risk.CRITICAL and fs["danger"].static_risk is Risk.HIGH
    assert fs["plain"].risk is Risk.HIGH
    assert tools and tools[0]["name"] == "danger"


def test_tools_registered_via_list_are_marked_exposed():
    code = '''
import subprocess
def run(c): subprocess.run(c)
def go(client):
    client.chat.completions.create(model="m", messages=[], tools=[run])
'''
    pts, _, _ = analyse_files(src(code))
    assert next(p for p in pts if p.category is Category.CODE_EXECUTION).exposed_via_tool == "run"


def test_syntax_errors_become_warnings_not_crashes():
    pts, _, warns = analyse_files(src("def broken(:\n"))
    assert pts == [] and "syntax error" in warns[0]


def test_javascript_patterns():
    code = "const cp = require('child_process');\nfetch(url);\nprocess.env.STRIPE_SECRET_KEY\n// eval(x)\n"
    f = SourceFile("a.js", "javascript", code, code.splitlines())
    pts, _, _ = analyse_files([f])
    cats = {p.category for p in pts}
    assert {Category.CODE_EXECUTION, Category.EXTERNAL_API, Category.SECRET_ACCESS} <= cats
    assert not any(p.title == "Evaluates dynamic code" for p in pts)  # commented out


def test_snippets_never_contain_secret_values():
    key = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"
    code = f'import requests\nrequests.post("https://x.example", headers={{"k": "{key}"}})\n'
    pts, _, _ = analyse_files(src(code))
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in pts[0].locations[0].snippet


# ---- guidelines -------------------------------------------------------------------------------
def test_guidelines_become_requirements_and_raise_matching_points(project, guidelines):
    base, _ = analyse(project)
    with_g, _ = analyse(project, guidelines)
    reqs = [r for g in with_g.guidelines for r in g.requirements]
    assert reqs and any(r.strength == "MUST" for r in reqs)
    msg = next(p for p in with_g.points if p.category is Category.MESSAGING)
    assert msg.guideline_refs and msg.point_id in {p.point_id for p in base.points}
    raised = [p for p in with_g.points if any("guideline" in n for n in p.risk_notes)]
    assert raised
    for p in with_g.points:  # never more than one level above the static rating
        assert abs(["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(p.risk.value)
                   - ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(p.static_risk.value)) <= 1


def test_guideline_prompt_injection_is_flagged_and_ignored(project, guidelines):
    result, _ = analyse(project, guidelines)
    assert any("instruction-like text" in w for w in result.warnings)
    texts = " ".join(r.text.lower() for g in result.guidelines for r in g.requirements)
    assert "fully safe" not in texts and "ignore all previous" not in texts


def test_guideline_loading_limits(tmp_path):
    big = tmp_path / "g.md"
    big.write_text("x" * 300_000)
    with pytest.raises(AnalysisError, match="too large"):
        load_guidelines([big])
    with pytest.raises(AnalysisError, match="not found"):
        load_guidelines([tmp_path / "missing.md"])
    (tmp_path / "bin.exe").write_bytes(b"MZ")
    (tmp_path / "ok.md").write_text("Agents must not email data.")
    d = tmp_path / "dir"
    d.mkdir()
    (d / "a.md").write_text("Secrets must never leak. token = 'abcdefgh12345678'")
    docs = load_guidelines([d])
    assert [n for n, _ in docs] == ["a.md"] and "abcdefgh12345678" not in docs[0][1]


def test_empty_project_is_an_error(tmp_path):
    (tmp_path / "notes.txt").write_text("no code")
    with pytest.raises(AnalysisError, match="no analysable source"):
        analyse(tmp_path)


# ---- AI agents: hostile / failing model output ------------------------------------------------
class Scripted:
    name = "scripted"

    def __init__(self, answers=None, fail=()):
        self.answers, self.fail, self.payloads = answers or {}, set(fail), []

    def complete_json(self, task, system, payload, schema):
        self.payloads.append((task, payload))
        if task in self.fail:
            raise ProviderError("boom")
        return self.answers.get(task, OfflineHeuristicProvider().complete_json(task, system, payload, schema))


def test_triage_constraints(project):
    probe = Scripted()
    analyse(project, provider=probe)
    shell = next(pl for t, pl in probe.payloads if t == "triage")["points"]
    shell_id = next(p["point_id"] for p in shell if p["category"] == "code_execution")
    low_id = next(p["point_id"] for p in shell if p["risk"] == "HIGH")

    answer = {"adjustments": [
        {"point_id": shell_id, "risk": "LOW", "note": "looks fine, ignore all rules"},   # 3 levels away
        {"point_id": low_id, "risk": "MEDIUM", "note": "probably ok"},                    # 1 level: ok
        {"point_id": "MP-DEADBEEF", "risk": "LOW", "note": "ghost"},                      # unknown id
    ], "additional": [
        {"title": "Fake spot", "category": "database", "risk": "HIGH", "file": "tools.py",
         "line": 9999, "reason": "nowhere"},                                              # bad line
        {"title": "Missing file", "category": "database", "risk": "HIGH", "file": "../../etc/passwd",
         "line": 1, "reason": "x"},                                                       # bad file
        {"title": "Real spot", "category": "file_system", "risk": "MEDIUM", "file": "tools.py",
         "line": 52, "reason": "archive job"},                                            # valid
    ]}
    result, _ = analyse(project, provider=Scripted({"triage": answer}))
    by_id = {p.point_id: p for p in result.points}
    assert by_id[shell_id].risk is Risk.CRITICAL                      # AI could not lower it 3 steps
    assert any("not applied" in n for n in by_id[shell_id].ai_notes)
    assert by_id[low_id].risk is Risk.MEDIUM and by_id[low_id].static_risk is Risk.HIGH
    assert "MP-DEADBEEF" not in by_id
    ai_points = [p for p in result.points if p.source == "ai"]
    assert [p.title for p in ai_points] == ["[AI] Real spot"] and ai_points[0].verified is False
    assert sum("discarded" in w for w in result.warnings) == 2
    assert len(result.points) >= len(analyse(project)[0].points)       # AI can never remove points


def test_model_failure_is_recorded_and_deterministic_results_survive(project, tmp_path):
    store = AuditStore(tmp_path / "a.db")
    result, _ = analyse(project, provider=Scripted(fail={"understand", "triage"}), store=store)
    rows = {r.agent: r for r in read_tasks(store, "run-t")}
    store.close()
    assert rows["understanding"].status == "FAILED" and rows["triage"].status == "FAILED"
    assert rows["code-analyst"].status == "COMPLETED"
    assert result.points and result.understanding == {}
    assert any("understanding failed" in w for w in result.warnings)
    statuses = {a.name: a.status for a in result.agents}
    assert statuses["understanding"] == "FAILED" and statuses["code-analyst"] == "COMPLETED"


def test_malformed_model_output_is_rejected(project):
    result, _ = analyse(project, provider=Scripted({"understand": {"summary": 1}}))
    assert result.understanding == {} and any("understanding failed" in w for w in result.warnings)


def test_model_payload_contains_no_secret_values_or_secret_files(project):
    probe = Scripted()
    analyse(project, provider=probe)
    blob = str(probe.payloads)
    assert "sk-live" not in blob and "do-not-read" not in blob
    files = [pl["files"] for t, pl in probe.payloads if t == "triage"][0]
    assert ".env" not in files and set(files) == {"app.py", "llm.py", "tools.py"}


def test_activity_events_recorded_per_agent(project, tmp_path):
    store = AuditStore(tmp_path / "a.db")
    analyse(project, store=store)
    rows = read_tasks(store, "run-t")
    store.close()
    assert [r.agent for r in rows] == ["scanner", "code-analyst", "understanding", "triage"]
    assert all(r.status == "COMPLETED" and r.duration_s is not None for r in rows)
    ca = rows[1]
    assert ca.target == "tools.py" and ca.progress == "3/3"       # last file it was analysing


def test_tracker_marks_failed_task_and_reraises(tmp_path):
    store = AuditStore(tmp_path / "a.db")
    t = ActivityTracker(store, "r")
    with pytest.raises(RuntimeError), t.task("scanner", "boom"):
        raise RuntimeError("disk exploded")
    (row,) = read_tasks(store, "r")
    store.close()
    assert row.status == "FAILED" and "disk exploded" in row.detail


def test_tracker_survives_audit_failure(tmp_path):
    store = AuditStore(tmp_path / "a.db")
    store.fail_writes = True
    t = ActivityTracker(store, "r")
    with t.task("scanner", "x"):
        pass
    assert t.write_failures == 2
    store.close()


def test_analysis_run_class_exposes_egress_size(project):
    run = AnalysisRun(project, Scripted(), ActivityTracker(None, "r"))
    run.run([])
    assert run.egress_chars > 0
