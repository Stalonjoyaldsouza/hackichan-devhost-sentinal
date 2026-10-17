# Sentinel — AI agent security control plane (MVP)

Sentinel sits between tool-using AI agents and the systems they act on. Every tool call passes a
**deterministic** enforcement boundary before anything executes, every decision lands in a
**tamper-evident audit trail**, outcomes are **verified against the target system** rather than the
agent's claim, and an **independent watchdog** keeps testing that those controls still work. If one
fails, the system drops into a **restricted safe mode**. All output goes to the terminal.

> Status: hackathon MVP. Agents are scripted and tools are in-memory mocks. Nothing here is a real
> integration with an LLM, MCP server or external API. See [Limitations](#limitations).

## The AI agents watching the stream

Three advisory agents read the event stream (sanitised, minimal fields only) and report findings
to the terminal and the audit trail:

| Agent | Looks for | Finding component |
|---|---|---|
| `agent.ai.threat` | prompt injection, exfiltration patterns, probing | `monitoring` |
| `agent.ai.risk` | an action that doesn't fit the agent's stated purpose | `risk` |
| `agent.ai.audit` | summarises a run that had a block or an outcome mismatch, citing event ids | `audit` |

**They advise; deterministic code enforces.** The agents hold no gateway credential and no tool, so
nothing they say can allow, deny or execute anything. Every model answer is schema-validated,
severity is capped at HIGH, cited event ids must exist in the audit store (otherwise the finding is
`INCONCLUSIVE`), and a failing or misbehaving model only produces a visible `DEGRADED` health line.

| `SENTINEL_AI` / `--ai` | Behaviour |
|---|---|
| `auto` (default) | Groq (`openai/gpt-oss-120b`, override with `SENTINEL_AI_MODEL`) if `GROQ_API_KEY` is set, otherwise `offline` |
| `groq` | Always Groq; errors at startup if `GROQ_API_KEY` is missing |
| `offline` | Keyword/pattern stand-in. **Not an AI model**; findings are tagged `[AI:offline-heuristic]` |
| `off` | No AI agents |

Groq models `openai/gpt-oss-120b` / `-20b` use strict schema-constrained JSON; any other model
(e.g. `llama-3.3-70b-versatile`) runs in plain JSON mode with the schema in the prompt. Either way
every answer is validated again locally. The Groq path is unit-tested against a fake SDK client; it
has not been exercised against the live API in this repository's test run.

```bash
export GROQ_API_KEY=your-key
```
```bash
uv run sentinel demo --ai groq
```

## Quick start

```bash
uv sync
uv run sentinel demo
```

The demo runs every scenario with live, colour-coded terminal output and ends with a pass/fail
summary of the security checks. Exit code is non-zero if any check fails.

To watch from a second terminal (a separate, read-only process with independent alerting):

```bash
uv run sentinel watch --db var/live.db
```

```bash
uv run sentinel demo --db var/live.db
```

## Commands

| Command | What it does |
|---|---|
| `sentinel demo [--scenario all\|baseline\|A\|B\|approval\|AI\|C\|D\|E] [--ai MODE] [--db PATH]` | Run scripted scenarios with live output |
| `sentinel watch --db PATH [--from-start] [--heartbeat-timeout S]` | Tail an audit store from a separate process; alert on missing heartbeat or broken hash chain |
| `sentinel audit verify --db PATH` | Recompute the audit hash chain (exit 2 if broken) |
| `sentinel audit report --db PATH --run RUN_ID` | Evidence-linked incident timeline; gaps are shown as `UNKNOWN` |
| `sentinel policy check [--policy PATH]` | Validate a policy bundle and print its version |

Global flags: `-v/--verbose` shows heartbeats, OK health checks and synthetic canary traffic.
`--no-color` (or `NO_COLOR=1`) disables ANSI colour.

## What the demo proves

| Scenario | Capability (CLAUDE.md §1) | What is checked |
|---|---|---|
| baseline | 2, 3 | Allowed work executes and is verified by read-back |
| A | 2 Pre-execution enforcement | `crm.bulk_delete` denied; the target system's own log proves it was never called; malformed args rejected |
| B | 1 Sequence & data flow | Read confidential doc (allowed) → internal email (allowed) → external email **denied**, with evidence linking to the read. A different agent pasting the text is caught by content fingerprint. Export → external send is caught by a sequence rule |
| approval | 2 | High-value refund held; human approves; executes once; replay refused |
| AI | 1, 4 (advisory) | An injected instruction is flagged by the threat agent while policy rules, not the AI, allow/deny. Risk and audit agents report with cited events |
| C | 3 Outcome verification | Tool says "ok" but CRM is unchanged → `FAILED`; half-applied refund → `PARTIAL` |
| D | 4 Containment, 5 Control validation | Audit outage, stale policy and an uninstrumented write are each detected → `RESTRICTED`; containment verified by live probe; recovery needs healthy rounds **and** an authorised human |
| E | Audit | Timeline for a run with every line citing an event id; hash chain verified |

Details: [docs/demo-scenarios.md](docs/demo-scenarios.md). Design and review:
[docs/architecture.md](docs/architecture.md). Decisions: [docs/decisions.md](docs/decisions.md).

## How enforcement works

```
agent ─GatewayClient─▶ authenticate ▶ validate ▶ data-flow labels ▶ policy ▶ audit ─┬▶ DENY
                                                                    (fail closed)  ├▶ HOLD for human
                                                                                   └▶ execute ▶ audit ▶ verify
```

- **Identity** comes from an opaque credential, never from a field in the request.
- **Policy** (`policies/default.yaml`) is deterministic YAML: DENY > REQUIRE_APPROVAL > ALLOW, and
  anything without an explicit ALLOW is denied. No LLM can permit an action.
- **Fail closed**: policy unavailable, policy crash, or audit write failure → DENY.
- **Audit**: SQLite, UPDATE/DELETE blocked by triggers, SHA-256 hash chain, secrets redacted.

## Development

```bash
uv run pytest
```

```bash
uv run ruff check src tests
```

Layout: `src/sentinel/` (one module per component, see docs/architecture.md §3), `policies/`,
`tests/{unit,integration,e2e}/`, `docs/`.

## Limitations

These are deliberate MVP boundaries. Do not present them as solved.

- **Same-process isolation.** Gateway and agents share a Python process. A hostile agent with
  interpreter access could reach tool objects. This is *detected* by reconciling target-system
  access logs with the audit trail, not *prevented*.
- **Mock integrations only.** The monitored agents are scripted; no MCP server or external API.
- **AI agents are advisory and see sanitised data.** Long text fields are truncated before analysis, so
  an injection hidden deep in a long argument may be missed. The offline stand-in is pattern matching only.
- **Data-flow coverage.** Paraphrased or summarised content that shares no 8-word run with the
  source is not caught by fingerprinting. Run/actor taint is conservative and can over-block, e.g.
  any external email after reading PII in the same run.
- **Tamper evidence, not tamper proofing.** Anyone who can rewrite the whole DB file can rebuild a
  consistent chain. External anchoring of the chain head is future work.
- **No bypass-acknowledgement workflow.** After a detected bypass the system stays RESTRICTED.
- **Approvals and identities are in memory** and are lost on restart. The audit trail is durable.
- **The watchdog runs in the runtime process.** `sentinel watch` provides an independent
  heartbeat and chain check from outside it.
