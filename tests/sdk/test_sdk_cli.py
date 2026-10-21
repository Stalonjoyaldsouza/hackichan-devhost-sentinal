"""`sentinel sdk …` end to end through the real argument parser."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from sentinel.ai.providers import OfflineHeuristicProvider
from sentinel.audit import AuditStore
from sentinel.cli import main
from sentinel.sdk import cli as sdk_cli
from sentinel.sdk.cli import CliError, parse_selection, snippet_for
from sentinel.sdk.models import Category
from sentinel.sdk.workspace import Workspace
from sentinel.termlog import TerminalLog
from sentinel.watch import watch


def run(capsys, *argv) -> tuple[int, str, str]:
    code = main(["--no-color", *argv])
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.fixture
def analysed(project, guidelines, capsys):
    code, out, _ = run(capsys, "sdk", "analyze", "--path", str(project), "-g", str(guidelines))
    assert code == 0, out
    return project


def test_analyze_shows_agents_points_and_next_steps(project, guidelines, capsys):
    code, out, _ = run(capsys, "sdk", "analyze", "--path", str(project), "-g", str(guidelines))
    assert code == 0
    for agent in ("scanner", "guidelines", "code-analyst", "understanding", "triage"):
        assert f"sdk.{agent}" in out                       # live per-agent activity lines
    assert "Static analysis of 3 files" in out and "tools.py 3/3" in out   # current target + progress
    assert "Agent activity" in out and "COMPLETED" in out
    assert "Monitoring points:" in out and "Next: sentinel sdk select" in out
    assert "not read (secret-looking): .env" in out and "sk-live" not in out
    assert (project / ".sentinel" / "analysis.json").exists()
    assert "nothing is monitored until you select" in out
    assert (project / ".sentinel" / ".gitignore").read_text().startswith("audit.db")


def test_analyze_is_repeatable_and_keeps_selection(analysed, capsys):
    run(capsys, "sdk", "select", "--min-risk", "CRITICAL", "--path", str(analysed))
    before = json.loads((analysed / ".sentinel" / "state.json").read_text())["selected"]
    code, _, _ = run(capsys, "sdk", "analyze", "--path", str(analysed))
    assert code == 0
    assert json.loads((analysed / ".sentinel" / "state.json").read_text())["selected"] == before


def test_points_filters_and_json(analysed, capsys):
    p = str(analysed)
    _, out, _ = run(capsys, "sdk", "points", "--path", p)
    assert "IDENTIFIED" in out and "LEGEND".lower() not in out and "only ACTIVE points are monitored" in out
    _, out, _ = run(capsys, "sdk", "points", "--path", p, "--category", "messaging", "--json")
    pts = json.loads(out)
    assert pts and all(x["category"] == "messaging" and x["state"] == "IDENTIFIED" for x in pts)
    _, out, _ = run(capsys, "sdk", "points", "--path", p, "--risk-min", "CRITICAL")
    assert "MEDIUM " not in out


def test_show_details_and_unknown_id(analysed, capsys):
    pts = json.loads(run(capsys, "sdk", "points", "--path", str(analysed), "--json")[1])
    sh = next(x for x in pts if x["category"] == "code_execution")
    code, out, _ = run(capsys, "sdk", "show", sh["point_id"], "--path", str(analysed))
    assert code == 0 and "tools.py" in out and "run_report" in out and "reachable by an LLM" in out
    assert "guidelines" in out and "security-policy.md#" in out
    code, _, err = run(capsys, "sdk", "show", "MP-00000000", "--path", str(analysed))
    assert code == 2 and "unknown monitoring point" in err


def test_select_then_status_never_claims_more_than_selected(analysed, capsys):
    p = str(analysed)
    code, out, _ = run(capsys, "sdk", "select", "--min-risk", "HIGH", "--path", p)
    assert code == 0 and "not monitored until you add a guard" in out
    _, out, _ = run(capsys, "sdk", "status", "--path", p)
    assert "ACTIVE       0" in out and "IMPLEMENTED  0" in out
    n = len(json.loads(run(capsys, "sdk", "points", "--path", p, "--json")[1]))
    assert f"0 of {n} identified points are actively monitored right now" in out
    assert "Coverage: 0 of" in out and "Health:" in out
    assert (analysed / ".sentinel" / "policy.yaml").read_text().startswith("# GENERATED")


def test_select_requires_a_choice_and_valid_ids(analysed, capsys):
    p = str(analysed)
    code, _, err = run(capsys, "sdk", "select", "--path", p)
    assert code == 2 and "nothing to select" in err
    code, _, err = run(capsys, "sdk", "select", "MP-ZZZZZZZZ", "--path", p)
    assert code == 2 and "unknown" in err


def test_select_by_short_id_deselect_and_all(analysed, capsys):
    p = str(analysed)
    pts = json.loads(run(capsys, "sdk", "points", "--path", p, "--json")[1])
    pid = pts[0]["point_id"]
    run(capsys, "sdk", "select", pid[3:].lower(), "--path", p)       # short, lower-case id
    sel = json.loads((analysed / ".sentinel" / "state.json").read_text())["selected"]
    assert list(sel) == [pid]
    run(capsys, "sdk", "deselect", pid, "--path", p)
    assert json.loads((analysed / ".sentinel" / "state.json").read_text())["selected"] == {}
    run(capsys, "sdk", "select", "--all", "--path", p)
    assert len(json.loads((analysed / ".sentinel" / "state.json").read_text())["selected"]) == len(pts)
    run(capsys, "sdk", "deselect", "--all", "--path", p)
    assert json.loads((analysed / ".sentinel" / "state.json").read_text())["selected"] == {}


def test_interactive_selection(analysed, capsys, monkeypatch):
    n = len(json.loads(run(capsys, "sdk", "points", "--path", str(analysed), "--json")[1]))
    answers = iter([str(n + 80), "1-2,4"])
    monkeypatch.setattr("builtins.input", lambda _="": next(answers))
    code, out, _ = run(capsys, "sdk", "select", "-i", "--path", str(analysed))
    assert code == 0 and f"outside 1-{n}" in out and "3 added" in out
    answers2 = iter(["q"])
    monkeypatch.setattr("builtins.input", lambda _="": next(answers2))
    _, out, _ = run(capsys, "sdk", "select", "-i", "--path", str(analysed))
    assert "Cancelled" in out
    assert len(json.loads((analysed / ".sentinel" / "state.json").read_text())["selected"]) == 3


def test_parse_selection_grammar():
    from sentinel.sdk.models import Location, MonitoringPoint, Risk

    pts = [MonitoringPoint(point_id=f"MP-0000000{i}", title="t", category=Category.TOOL_CALL,
                           risk=r, static_risk=r, description="d", reason="r",
                           locations=[Location(file="a.py", line=1)])
           for i, r in enumerate([Risk.LOW, Risk.HIGH, Risk.CRITICAL, Risk.MEDIUM], 1)]
    ids = [p.point_id for p in pts]
    assert parse_selection("1,3-4", pts, set()) == {ids[0], ids[2], ids[3]}
    assert parse_selection("h", pts, set()) == {ids[1], ids[2]}
    assert parse_selection("a", pts, set()) == set(ids)
    assert parse_selection("n", pts, {ids[0]}) == set()
    assert parse_selection("", pts, {ids[0]}) == {ids[0]}
    assert parse_selection("q", pts, set()) is None
    for bad in ("0", "5", "x", "3-1"):
        with pytest.raises(CliError):
            parse_selection(bad, pts, set())


def test_snippet_contents(analysed, capsys):
    pts = json.loads(run(capsys, "sdk", "points", "--path", str(analysed), "--json")[1])
    msg = next(x for x in pts if x["title"].startswith("Sends a message (SMTP)"))
    _, out, _ = run(capsys, "sdk", "snippet", msg["point_id"], "--path", str(analysed))
    assert f'@guard("{msg["point_id"]}", destination_arg="to")' in out and "def send_email" in out
    sens = next(x for x in pts if x["category"] == "sensitive_data_access"
                and x["title"].startswith("Sensitive data accessor"))
    _, out, _ = run(capsys, "sdk", "snippet", sens["point_id"], "--path", str(analysed))
    assert '@guard("' + sens["point_id"] + '", produces=["pii"])' in out
    compile(out.split("\n\n", 1)[1].split("# or wrap")[0].replace("(...)", "(x)").replace("    ...", "    pass"),
            "snippet", "exec")  # the generated decorator code is valid Python


def test_activity_view_and_live_watch_show_agent_tasks(analysed, capsys):
    code, out, _ = run(capsys, "sdk", "activity", "--path", str(analysed))
    assert code == 0 and "Completed (5)" in out and "code-analyst" in out
    assert "Running" not in out and "Failed" not in out
    buf = io.StringIO()
    watch(analysed / ".sentinel" / "audit.db", TerminalLog(buf, color=False), interval=0,
          heartbeat_timeout=1e9, from_start=True, max_iterations=1)
    live = buf.getvalue()
    assert "sdk.code-analyst" in live and "tools.py 3/3" in live and "COMPLETED" in live


def test_failed_agents_visible_in_activity(project, capsys, monkeypatch):
    class Failing(OfflineHeuristicProvider):
        name = "failing"

        def complete_json(self, task, system, payload, schema):
            if task in {"understand", "triage"}:
                from sentinel.ai.providers import ProviderError
                raise ProviderError("provider exploded")
            return super().complete_json(task, system, payload, schema)

    monkeypatch.setattr(sdk_cli, "make_provider", lambda mode: Failing())
    code, out, _ = run(capsys, "sdk", "analyze", "--path", str(project), "--ai", "groq", "--yes")
    assert code == 0
    assert "FAILED" in out and "provider exploded" in out and "understanding failed" in out
    _, act, _ = run(capsys, "sdk", "activity", "--path", str(project))
    assert "Failed (2)" in act and "Completed (2)" in act and act.count("Agent activity") == 1


def test_refuses_to_analyse_sentinel_itself(capsys):
    repo = Path(__file__).resolve().parents[2]
    code, _, err = run(capsys, "sdk", "analyze", "--path", str(repo))
    assert code == 2 and "Sentinel's own source" in err
    code, _, err = run(capsys, "sdk", "init", "--path", str(repo))
    assert code == 2


def test_remote_ai_requires_explicit_consent(project, capsys, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "placeholder")
    monkeypatch.setattr("sys.stdin", io.StringIO(""))          # non-interactive
    code, out, err = run(capsys, "sdk", "analyze", "--path", str(project), "--ai", "groq")
    assert code == 2 and "SENT to the model provider" in out and "not confirmed" in err
    assert not (project / ".sentinel" / "analysis.json").exists()


def test_groq_without_key_is_a_clean_error(project, capsys, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    code, _, err = run(capsys, "sdk", "analyze", "--path", str(project), "--ai", "groq", "--yes")
    assert code == 2 and "GROQ_API_KEY" in err


def test_default_ai_is_offline_and_sends_nothing(project, capsys):
    _, out, _ = run(capsys, "sdk", "analyze", "--path", str(project))
    assert "ai=offline-heuristic" in out and "SENT" not in out


def test_commands_before_analysis_give_actionable_errors(tmp_path, capsys):
    p = tmp_path / "empty"
    p.mkdir()
    for argv in (["points"], ["status"], ["select", "--all"], ["activity"]):
        code, _, err = run(capsys, "sdk", *argv, "--path", str(p))
        assert code == 2 and "sentinel sdk" in err
    Workspace(p).init()
    code, _, err = run(capsys, "sdk", "points", "--path", str(p))
    assert code == 2 and "run `sentinel sdk analyze`" in err


def test_init_is_idempotent_and_keeps_config(tmp_path, capsys):
    p = tmp_path / "proj"
    p.mkdir()
    assert run(capsys, "sdk", "init", "--path", str(p))[1].startswith("Initialised")
    cfg = p / ".sentinel" / "config.yaml"
    cfg.write_text(cfg.read_text().replace("business-app", "mine").replace("proj", "mine"))
    out = run(capsys, "sdk", "init", "--path", str(p))[1]
    assert out.startswith("Already initialised") and "mine" in cfg.read_text()


def test_invalid_config_is_reported_not_crashed(analysed, capsys):
    cfg = analysed / ".sentinel" / "config.yaml"
    cfg.write_text("mode: panic\n")
    code, _, err = run(capsys, "sdk", "policy", "--path", str(analysed))
    assert code == 2 and "invalid" in err
    cfg.write_text("mode: observe\npoint_actions: {MP-AAAAAAAA: MAYBE}\n")
    code, _, err = run(capsys, "sdk", "policy", "--path", str(analysed))
    assert code == 2 and "invalid point_actions" in err


def test_snippet_helper_for_module_level_point():
    from sentinel.sdk.models import Location, MonitoringPoint, Risk
    p = MonitoringPoint(point_id="MP-ABCDEF12", title="t", category=Category.EXTERNAL_API,
                        risk=Risk.MEDIUM, static_risk=Risk.MEDIUM, description="d", reason="r",
                        locations=[Location(file="a.py", line=3, snippet="requests.get(u)")])
    s = snippet_for(p)
    assert "@guard" not in s and 'monitor("MP-ABCDEF12", destination=<recipient>)' in s


def test_audit_store_has_no_secret_values_after_full_flow(analysed):
    store = AuditStore(analysed / ".sentinel" / "audit.db", read_only=True)
    blob = " ".join(s.event.model_dump_json() for s in store.all())
    store.close()
    assert "sk-live" not in blob and store is not None
