# Demo scenarios

Run one scenario at a time with `uv run sentinel demo --scenario <name>`. The scenarios are
deterministic, and each ends with `CHECK` lines that assert the security property against
**independent** state: target-system logs, ledgers, the outbox and the audit store. They do not
use the agent's view.

## baseline
`agent.support` reads a public FAQ and updates a CRM note. Both are allowed. The update is
`VERIFIED` by reading the record back.

## A — prohibited action blocked
`agent.cleanup` calls `crm.bulk_delete`. Rule `R-NO-BULK-DELETE` denies it. The checks confirm
the record count is unchanged and the CRM's own access log has no entry. A request with an
injected field name is rejected as `INVALID_ARGUMENTS` before policy is consulted.

## B — prohibited data flow from allowed steps
1. `agent.research` (analyst) reads `q4-acquisition-plan`, which is labelled `confidential`. Allowed.
2. It emails the content to `cfo@corp.example`. Allowed: the destination is internal.
3. It emails `contact@northwind-robotics.example`. Denied by `R-DF-SENSITIVE-EXTERNAL`. The
   decision's `evidence_refs` point at the step-1 execution event.
4. `agent.writer` is a different agent in a different run that never read the document. It pastes
   the same text to a press address and is denied through the **content fingerprint**.
5. `agent.export` runs `crm.export` and then emails an external address. Denied by the sequence
   rule `R-SEQ-EXPORT-THEN-EXTERNAL-EMAIL`, even though the body is harmless.

Not covered: paraphrased leaks and uninstrumented channels.

## approval
A refund of 900 triggers `R-REFUND-HIGH-VALUE` → `PENDING_APPROVAL`. Nothing is refunded while it
waits. `human.secops` approves, the agent resumes, and the refund executes once and is verified
against the ledger. A replay is refused (`APPROVAL_ALREADY_USED`). The tests also cover
self-approval, a non-listed approver, an agent acting as approver, a different agent reusing the
approval, expiry, and safe mode entered between approval and resume.

## C — claimed success vs. actual state
The CRM is put into a fault mode where it returns `{"status": "ok"}` without writing. The verifier
reads the record back → `FAILED`, and the monitor raises a HIGH finding. A refund that applies half
the amount → `PARTIAL`. With the verifier disabled, outcomes are `INCONCLUSIVE`, never `VERIFIED`.

## D — critical control failure
- **D1, audit outage.** The watchdog's audit probe fails → `RESTRICTED`. The containment probe
  confirms a protected call is refused and the target is untouched. All calls fail closed with
  `AUDIT_UNAVAILABLE`. An early recovery attempt is refused. Two healthy rounds plus the
  `human.secops` override restore `NORMAL`. Events buffered during the outage are persisted late
  and flagged as such.
- **D2, stale policy.** The policy file changes on disk without a reload → `STALE_POLICY` →
  `RESTRICTED`. Only `safe_in_restricted` tools (reads) still work. The demo edits a temporary copy
  of the policy, never `policies/default.yaml`.
- **D3, bypass.** Something writes to the mail system directly. The coverage probe reconciles the
  mail system's own log with the audit trail → `BYPASS_DETECTED` → `RESTRICTED`. The system stays
  restricted pending investigation.

Covered only in the tests: canary allowed by a broken policy engine (containment correctly
reported as **unverified**), lost telemetry, a tampered audit row, and a missing policy file.

## E — audit reconstruction
`sentinel audit report --run run-B` prints each trace in the run: request, decision with rule IDs
and policy version, label provenance, execution, outcome evidence, and findings. Every line cites
an event id. Missing steps are printed as `UNKNOWN`.
