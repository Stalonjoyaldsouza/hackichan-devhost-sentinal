from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sentinel.contracts import DataLabel, Decision, DecisionRequest, Mode
from sentinel.policy import PolicyEngine, PolicyError, PolicyUnavailable, destination_domain


def req(tool: str, *, roles=("support_agent",), dest=None, labels=(), prior=(), args=None,
        mode=Mode.NORMAL) -> DecisionRequest:
    return DecisionRequest(
        request_id="r1", actor_id="agent.x", actor_roles=tuple(roles), tool_name=tool,
        arguments=args or {}, resource=None, destination=dest, data_labels=tuple(labels),
        prior_tools_in_run=tuple(prior), mode=mode,
    )


@pytest.fixture
def engine(policy_path: Path) -> PolicyEngine:
    return PolicyEngine(policy_path)


def test_allow_with_matching_role(engine):
    d = engine.evaluate(req("docs.read"))
    assert d.decision is Decision.ALLOW
    assert d.matched_rules == ("R-ALLOW-READS",)
    assert d.policy_version.startswith("default-2026-10-17@")


def test_default_deny_without_matching_allow(engine):
    d = engine.evaluate(req("docs.read", roles=("intern",)))
    assert d.decision is Decision.DENY
    assert d.reason_codes == ("DEFAULT_DENY_NO_MATCHING_ALLOW",)


def test_unknown_tool_denied(engine):
    assert engine.evaluate(req("shell.exec")).reason_codes == ("UNKNOWN_TOOL",)


def test_deny_beats_allow(engine):
    d = engine.evaluate(req("email.send", dest="x@evil.example", labels=[DataLabel.CONFIDENTIAL]))
    assert d.decision is Decision.DENY
    assert "R-DF-SENSITIVE-EXTERNAL" in d.matched_rules


def test_sensitive_to_internal_domain_allowed(engine):
    d = engine.evaluate(req("email.send", dest="cfo@corp.example", labels=[DataLabel.PII]))
    assert d.decision is Decision.ALLOW


def test_internal_subdomain_allowed_lookalike_denied(engine):
    ok = engine.evaluate(req("email.send", dest="a@eu.corp.example", labels=[DataLabel.PII]))
    bad = engine.evaluate(req("email.send", dest="a@corp.example.evil.io", labels=[DataLabel.PII]))
    bad2 = engine.evaluate(req("email.send", dest="a@evilcorp.example", labels=[DataLabel.PII]))
    assert ok.decision is Decision.ALLOW
    assert bad.decision is Decision.DENY and bad2.decision is Decision.DENY


def test_missing_destination_is_treated_as_external(engine):
    d = engine.evaluate(req("email.send", dest=None, labels=[DataLabel.CONFIDENTIAL]))
    assert d.decision is Decision.DENY


def test_sequence_rule(engine):
    d = engine.evaluate(req("email.send", roles=("analyst",), dest="a@b.example", prior=["crm.export"]))
    assert "EXPORT_FOLLOWED_BY_EXTERNAL_SEND" in d.reason_codes
    d2 = engine.evaluate(req("email.send", roles=("analyst",), dest="a@b.example", prior=["docs.read"]))
    assert d2.decision is Decision.ALLOW


def test_approval_threshold(engine):
    assert engine.evaluate(req("payments.refund", args={"amount": 501})).decision \
        is Decision.REQUIRE_APPROVAL
    assert engine.evaluate(req("payments.refund", args={"amount": 500})).decision is Decision.ALLOW


def test_arg_gt_ignores_non_numeric(engine):
    # A bool or string must not satisfy a numeric threshold (True > 500 is False anyway, "9999" is str)
    assert engine.evaluate(req("payments.refund", args={"amount": "9999"})).decision is Decision.ALLOW


def test_restricted_mode_only_safe_tools(engine):
    assert engine.evaluate(req("docs.read", mode=Mode.RESTRICTED)).decision is Decision.ALLOW
    d = engine.evaluate(req("crm.update_record", mode=Mode.RESTRICTED))
    assert d.decision is Decision.DENY and d.reason_codes == ("SAFE_MODE_RESTRICTED",)


def test_canary_always_denied_even_for_privileged_roles(engine):
    d = engine.evaluate(req("canary.protected_noop", roles=("support_agent", "analyst", "admin")))
    assert d.decision is Decision.DENY


def test_unavailable_engine_raises(engine):
    engine.available = False
    with pytest.raises(PolicyUnavailable):
        engine.evaluate(req("docs.read"))


@pytest.mark.parametrize("mutate,msg", [
    (lambda b: b["rules"].append(dict(b["rules"][0])), "duplicate"),
    (lambda b: b["rules"][0]["match"].update(tools=["nope.tool"]), "unknown tools"),
    (lambda b: b["rules"][0].update(effect="MAYBE"), "invalid"),
    (lambda b: b["rules"][0]["match"].update(typo_field=1), "invalid"),
    (lambda b: b.update(approvers=[]), "invalid"),
])
def test_invalid_bundles_rejected(policy_path, mutate, msg):
    bundle = yaml.safe_load(policy_path.read_text())
    mutate(bundle)
    policy_path.write_text(yaml.safe_dump(bundle))
    with pytest.raises(PolicyError, match=msg):
        PolicyEngine(policy_path)


def test_version_changes_with_content(policy_path):
    v1 = PolicyEngine(policy_path).version
    policy_path.write_text(policy_path.read_text() + "\n# change\n")
    assert PolicyEngine(policy_path).version != v1


@pytest.mark.parametrize("dest,expected", [
    ("a@Corp.Example", "corp.example"), ("https://x.example/path", "x.example"), ("", None),
    (None, None), ("not a url", None),
])
def test_destination_domain(dest, expected):
    assert destination_domain(dest) == expected
