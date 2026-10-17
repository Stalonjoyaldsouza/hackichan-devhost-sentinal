# Architecture — Sentinel MVP

> Status: **MVP implementation, provisional.** The stack and design choices below were made on
> 2026-10-17 at the user's request ("a tool which watches, output logged in the terminal, implement
> the MVP"). They are recorded in `docs/decisions.md` as PROVISIONAL and still need team sign-off
> (CLAUDE.md §14).

## 1. Architecture review (CLAUDE.md §9)

### Existing repository facts (before this change)
- Only `CLAUDE.md` and three `.claude/agents/*.md` files existed. No code, docs, tests or decisions.
- No team roster, stack, model provider or target integration had been recorded.

### Overall assessment
The proposal in CLAUDE.md is sound in its core principle — *LLMs advise, deterministic code
enforces* — and in insisting on independent evidence for outcomes and control health. Its main
weaknesses are that it is under-specified exactly where a security product most needs precision
(how the boundary is made non-bypassable, who holds tool credentials, what happens when the
safety machinery itself fails), and over-specified where it adds risk without demo value (five
LLM agents, LangGraph, OPA, Postgres, OpenTelemetry and React for a hackathon MVP).

**Strongest aspects**
1. Deterministic enforcement separated from LLM analysis; analysis can only *request* actions.
2. Outcome verification against target-system evidence rather than agent self-report.
3. Explicit distinction between incident monitoring (cap. 4) and control validation (cap. 5).
4. Honest-coverage principle: unobserved paths must not be claimed as protected.

### Critical flaws and risks (ranked)

| # | Severity | Finding | Impact | Change made in MVP |
|---|---|---|---|---|
| 1 | CRITICAL | **Bypass path not addressed.** The gateway only protects calls routed through it. If the agent holds tool credentials it can call tools directly. | Every guarantee collapses to "if the agent cooperates". | Tools are constructed and owned by the runtime; the agent only receives a `GatewayClient`. Target systems keep their **own** access logs, and the watchdog reconciles them against the audit trail to *detect* executions that bypassed the gateway (`BYPASS_DETECTED`). In-process isolation is documented as a limitation, not claimed as a guarantee. |
| 2 | CRITICAL | **Audit-before-execute ordering unspecified.** If the audit write happens after execution and fails, a side effect occurs with no record. | Unaudited side effects; violates principle 8. | Gateway writes the decision event *before* execution and fails closed (`AUDIT_UNAVAILABLE`) if the write fails. |
| 3 | HIGH | **Caller identity is caller-supplied.** The event contract has `actor_id` as a free field. | Agent can impersonate a more privileged actor. | Identity is derived from an opaque credential issued at registration; `actor_id` is never read from the request. |
| 4 | HIGH | **Audit log mutable by the monitored system.** | Tampering hides incidents. | Append-only SQLite table (UPDATE/DELETE blocked by triggers) plus a SHA-256 hash chain verified by the watchdog and the external `sentinel watch` process. |
| 5 | HIGH | **Approval replay / self-approval not addressed.** | An approval for one request is reused for another, or the agent approves itself. | Approvals are bound to the request hash, single-use, expiring, and the approver must be in the policy's approver list and differ from the requester. Policy is re-evaluated at resume time. |
| 6 | HIGH | **Watchdog trusts self-reported health.** | A broken control reports "healthy". | Probes test *behaviour*: a canary request must be denied and the canary tool must not run; audit probe writes then reads back and verifies the chain; policy probe re-hashes the file on disk. |
| 7 | MEDIUM | **Safe-mode effectiveness unverified.** | "Contained" claimed while tools still run. | After entering RESTRICTED the controller issues a probe for a protected tool and records `containment_verified=true/false`. |
| 8 | MEDIUM | **Data-flow lineage across transformations is not tractable in general.** | Over-claiming lineage. | Two deterministic mechanisms: run/actor taint (conservative) + content fingerprints (8-word shingles). Paraphrase/summarisation that removes shingles is **not** detected — documented. |
| 9 | MEDIUM | **Five LLM agents are unjustified for MVP.** No model provider is chosen; LLM agents add nondeterminism to demos. | Demo fragility; agent-count-for-its-own-sake (principle 9). | MVP ships **zero** LLM agents. A deterministic monitor raises findings (e.g. repeated denies). Risk/threat/audit LLM agents are deferred until a provider is approved; the investigator is deterministic and cites event IDs. |
| 10 | LOW | Heavy proposed stack (Postgres, OPA, LangGraph, OTel, React) vs. "keep the MVP small". | Setup time dominates build time. | Python 3.12 + Pydantic + PyYAML + SQLite; terminal output instead of a dashboard, per user request. |

### Single points of failure
- **Gateway + policy engine** — by design (fail-closed). Mitigation: canary probe, default deny.
- **Watchdog** — if it dies, nobody notices control failure. Mitigation: the runtime writes
  heartbeat events; the separate `sentinel watch` process alerts when heartbeats stop.
- **Audit store** — failure blocks protected actions (intentional). Safe-mode transitions during an
  audit outage are logged to the terminal and kept in memory, then flagged as `unpersisted`.

### Circular dependencies avoided
Safe-mode controller → gateway (to probe containment) and gateway → safe-mode controller (to read
the mode) would be circular. The controller exposes a read-only `mode` that the gateway reads; the
containment probe is injected as a callable, so neither module imports the other's internals.

## 2. Implemented control/data flow

```text
 scripted agent ──(GatewayClient: opaque credential)──┐
                                                       v
                                ┌──────────── Gateway (deterministic) ────────────┐
                                │ 1 resolve identity from credential               │
                                │ 2 validate tool + args (Pydantic schema)         │
                                │ 3 safe-mode check (RESTRICTED → only safe tools) │
                                │ 4 data-flow labels: run/actor taint + fingerprint│
                                │ 5 policy engine → ALLOW / DENY / REQUIRE_APPROVAL│
                                │ 6 audit write (fail closed if it fails)          │
                                │ 7 execute tool (runtime-owned credentials)       │
                                │ 8 record result, update taint/fingerprints       │
                                │ 9 outcome verifier: independent read-back        │
                                └──────────────────────┬───────────────────────────┘
                                                       v
                         Append-only hash-chained audit store (SQLite)
                                ^                 ^                 ^
              watchdog probes ──┘  investigator ──┘  sentinel watch ┘ (separate process:
              (policy, audit,      (timeline with     tails events, verifies chain,
               canary, bypass       event citations)   alerts on missing heartbeat)
               reconciliation,
               verifier)
                  │ CRITICAL
                  v
          Safe-mode controller ── RESTRICTED: only `safe_in_restricted` tools;
                                  containment probe; recovery = N healthy rounds
                                  + authorised human override
```

## 3. Component map

| Component | Module | Kind |
|---|---|---|
| Contracts | `sentinel/contracts.py` | Pydantic models, strict enums |
| Gateway | `sentinel/gateway.py` | deterministic |
| Policy engine | `sentinel/policy.py` | deterministic, YAML bundle, versioned by hash |
| Data-flow tracker | `sentinel/dataflow.py` | deterministic |
| Approvals | `sentinel/approvals.py` | deterministic |
| Audit store | `sentinel/audit.py` | SQLite, append-only, hash chain |
| Outcome verifier | `sentinel/verification.py` | deterministic read-back |
| Watchdog | `sentinel/watchdog.py` | deterministic probes |
| Safe-mode controller | `sentinel/safemode.py` | deterministic |
| Monitor | `sentinel/monitor.py` | deterministic heuristics (no LLM) |
| Investigator | `sentinel/investigator.py` | deterministic timeline |
| Mock target systems | `sentinel/tools/` | in-memory, with independent access logs |
| Terminal output | `sentinel/termlog.py`, `sentinel/cli.py`, `sentinel/watch.py` | — |

## 4. Coverage statement

**Covered:** tool calls made through `GatewayClient` to the mock tools registered in the runtime.

**Not covered / limitations:**
- Gateway and agent run in the same Python process. A malicious agent with access to the
  interpreter can reach tool objects directly. This is *detected* (bypass reconciliation against
  target-system logs), not *prevented*. Production would need process/network isolation and
  credentials held only by the gateway.
- No real LLM agent, MCP server or external API integration — the agent is scripted and the tools
  are mocks. Nothing here should be presented as a real integration.
- Data-flow detection does not follow paraphrased or transformed content and only knows labels
  assigned to registered resources.
- Single-node SQLite; no HA, no remote attestation of the watchdog.
