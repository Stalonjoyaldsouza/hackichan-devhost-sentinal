# Sentinel — AI agent security SDK and control plane

Sentinel helps you secure applications that use AI agents. It has two parts that share one engine:

1. **SDK — run it inside your own project.** AI agents read your code, work out where your agents
   and tools can do something risky (sensitive data, tool calls, external APIs, shell, email…),
   let you choose which points to monitor, and give you a runtime guard that enforces policy there.
2. **Control plane — the enforcement engine behind it.** Every tool call passes a **deterministic**
   boundary before it executes, every decision lands in a **tamper-evident audit trail**, outcomes
   are **verified against the target system** instead of the agent's claim, and an **independent
   watchdog** keeps testing that those controls still work (restricted safe mode if one fails).

Everything is shown in the terminal. AI models only **advise**; deterministic code decides.

> Status: hackathon MVP. The SDK analyses real projects and guards them at runtime; the bundled demos
> use a scripted agent with patched tools. The Groq integration has been run live against the
> example app. See [Limitations](#limitations).

## Install

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

To use it from another project, build and install the wheel there:

```bash
uv build --wheel
```
```bash
pip install dist/sentinel-0.1.0-py3-none-any.whl
```

## Use it on your own project (SDK)

Run these from inside the business project you want to analyse. Full guide: **[docs/sdk.md](docs/sdk.md)**.

```bash
sentinel sdk analyze --guidelines ./security-policy.md   # agents inspect the project (creates .sentinel/)
sentinel sdk points                                      # monitoring points: risk, location, reason
sentinel sdk select -i                                   # review and choose what to monitor
sentinel sdk snippet MP-1A2B3C4D                         # code to add a guard for one point
sentinel sdk status                                      # IDENTIFIED → SELECTED → IMPLEMENTED → ACTIVE
sentinel sdk activity                                    # what each SDK agent did / is doing
```

**See everything in one command** (guided demo with pass/fail checks — script in [docs/DEMO.md](docs/DEMO.md)):

```bash
uv run sentinel sdk demo
```

Or try it on the bundled example (a deliberately unsafe support bot) step by step:

```bash
cd examples/support_bot
```
```bash
uv run sentinel sdk analyze --guidelines ../guidelines
```

### What the SDK agents do

| Agent | Kind | Job |
|---|---|---|
| `scanner` | deterministic | inventory files, dependencies, frameworks; lists secret-looking files (`.env`, keys) **without opening them** |
| `guidelines` | AI / offline | turns your external guideline documents into checkable requirements |
| `code-analyst` | deterministic | finds monitoring points (Python via the AST, JS/TS via patterns) |
| `understanding` | AI / offline | explains how the application works: agents, tools, data, external systems |
| `triage` | AI / offline | reviews the candidates against that understanding and the guidelines |

`sdk activity` and `sdk watch` show which agent is running, what it is analysing, what completed and
what failed. Your code and guideline files are treated as untrusted input; model output is validated
and can only annotate points or move risk by one level — it cannot remove or select a point or touch
policy.

### Monitoring points are never claimed before they work

| State | Evidence required |
|---|---|
| IDENTIFIED | found by analysis |
| SELECTED | you chose it (`sdk select`) |
| IMPLEMENTED | a `guard("MP-…")` for it exists in your source code |
| ACTIVE | the guard was **observed evaluating a call at runtime** (audit trail, hash chain verified) |

Selecting a point does not monitor it, and pasting a decorator does not make it ACTIVE. The SDK
edits your source only when you ask: `sdk instrument` shows a diff and `--apply` writes it (reversible
with `--revert`), or add guards yourself — `sdk snippet` shows the code:

```python
from sentinel.sdk import guard

@guard("MP-1A2B3C4D", destination_arg="to")     # sink: where does the data go?
def send_email(to, subject, body): ...

@guard("MP-5E6F7A8B", produces=["pii"])         # source: labels what it returns
def get_customer_records(): ...
```

In `observe` mode (default) the guard only logs and reports what it *would* block, and a problem in
Sentinel itself never stops your app. In `enforce` mode a denied call raises `SentinelDenied` before
your function runs, and an unavailable policy or audit store fails closed. Configuration lives in
`.sentinel/config.yaml`.

### Once deployed

The guards keep working in production, and Sentinel watches them from **outside** the app:
each app sends a heartbeat; `sentinel sdk health` / `watch` alert when the app goes silent, a guard
is removed, the policy drifts or the audit trail breaks; `watch --ai groq` runs the threat, risk and
audit agents on live traffic (destinations masked); replicas can forward to a central collector so a
redeploy loses nothing. Details: [docs/sdk.md → Running in production](docs/sdk.md#running-in-production).

### SDK commands

| Command | Purpose |
|---|---|
| `sentinel sdk init` | create `.sentinel/` in the project |
| `sentinel sdk analyze [-g FILE_OR_DIR]… [--ai offline\|groq\|auto] [--yes]` | run the agents against the project |
| `sentinel sdk points [--risk-min R] [--category C] [--state S] [--json]` / `show ID` | list / inspect points |
| `sentinel sdk select [-i] [IDS…] [--all] [--min-risk R]` / `deselect` | choose points (regenerates the policy) |
| `sentinel sdk snippet ID` | integration code for a point |
| `sentinel sdk status` | counts per state, audit-trail health, how many points are really active |
| `sentinel sdk activity [--run ID] [--all]` | running / failed / completed agent tasks |
| `sentinel sdk watch` | live view of agent activity and runtime guard events |
| `sentinel sdk policy` | regenerate `.sentinel/policy.yaml` from selection + config |
| `sentinel sdk instrument [--apply] [--revert]` | add the guards for you (dry-run diff first; reversible) |
| `sentinel sdk health` | independent health check of the deployed app (exit 0 ok / 1 degraded / 2 critical) |
| `sentinel sdk watch [--ai groq]` | live events, health alerts, and AI agents watching production traffic |
| `sentinel sdk findings` | what the monitors and AI agents reported |
| `sentinel sdk approvals` / `approve` / `reject` | human approvals for risky actions |
| `sentinel sdk collector --db central.db` | central audit store for many replicas |
| `sentinel sdk demo [--ai groq --yes]` | the guided end-to-end demo |

Every command accepts `--path DIR` (default: the current directory, searching upward for
`.sentinel/`). Sentinel refuses to analyse its own source tree.

## AI models (Groq)

| Setting | Behaviour |
|---|---|
| `--ai offline` | No model. Nothing leaves your machine. Keyword/pattern stand-in, tagged `offline-heuristic` — **not AI**. **Default for `sdk analyze`.** |
| `--ai groq` | Uses Groq (`GROQ_API_KEY`; model `openai/gpt-oss-120b`, override with `SENTINEL_AI_MODEL`). Sends **redacted** excerpts and your guideline text to Groq and asks you to confirm (`--yes` skips). |
| `--ai auto` | Groq if `GROQ_API_KEY` is set, otherwise offline. Default for `sentinel demo`. |
| `SENTINEL_AI=off` | No AI agents (demo only). |

```bash
export GROQ_API_KEY=your-key
```
```bash
sentinel sdk analyze --ai groq
```

`openai/gpt-oss-120b` / `-20b` use strict schema-constrained JSON; other Groq models run in plain
JSON mode with the schema in the prompt. Every answer is validated again locally.

## Control plane demo

Scripted scenarios with live, colour-coded output and a pass/fail summary (non-zero exit if any
check fails):

```bash
uv run sentinel demo
```

Watch the same audit database from a second terminal (a separate, read-only process that alerts on a
missing heartbeat or a broken hash chain):

```bash
uv run sentinel watch --db var/live.db
```
```bash
uv run sentinel demo --db var/live.db
```

| Command | What it does |
|---|---|
| `sentinel demo [--scenario all\|baseline\|A\|B\|approval\|AI\|C\|D\|E] [--ai MODE] [--db PATH]` | Run scripted scenarios |
| `sentinel watch --db PATH [--from-start] [--heartbeat-timeout S]` | Tail an audit store from a separate process |
| `sentinel audit verify --db PATH` | Recompute the audit hash chain (exit 2 if broken) |
| `sentinel audit report --db PATH --run RUN_ID` | Evidence-linked incident timeline; gaps shown as `UNKNOWN` |
| `sentinel policy check [--policy PATH]` | Validate a policy bundle and print its version |

Global flags: `-v/--verbose` (heartbeats, OK health checks, canary traffic), `--no-color` / `NO_COLOR=1`.

| Scenario | Capability (CLAUDE.md §1) | What is checked |
|---|---|---|
| baseline | 2, 3 | Allowed work executes and is verified by read-back |
| A | 2 Pre-execution enforcement | `crm.bulk_delete` denied; the target's own log proves it was never called; malformed args rejected |
| B | 1 Sequence & data flow | Confidential read → internal email allowed → external email **denied**, evidence linked to the read; copied text caught by content fingerprint; export → external send caught by a sequence rule |
| approval | 2 | High-value refund held; human approves; executes once; replay refused |
| AI | 1, 4 (advisory) | Injected instruction flagged by the threat agent while policy rules, not the AI, allow/deny |
| C | 3 Outcome verification | Tool says "ok" but state is unchanged → `FAILED`; half-applied refund → `PARTIAL` |
| D | 4 Containment, 5 Control validation | Audit outage, stale policy and an uninstrumented write each → `RESTRICTED`; containment verified by live probe; recovery needs healthy rounds **and** an authorised human |
| E | Audit | Timeline where every line cites an event id; hash chain verified |

Details: [docs/demo-scenarios.md](docs/demo-scenarios.md).

### How enforcement works

```
agent ─GatewayClient─▶ authenticate ▶ validate ▶ data-flow labels ▶ policy ▶ audit ─┬▶ DENY
                                                                    (fail closed)  ├▶ HOLD for human
                                                                                   └▶ execute ▶ audit ▶ verify
```

- **Identity** comes from an opaque credential, never from a field in the request.
- **Policy** is deterministic YAML: DENY > REQUIRE_APPROVAL > ALLOW; anything without an explicit
  ALLOW is denied. The SDK generates its project policy for the same engine.
- **Fail closed**: policy unavailable, policy crash or audit write failure → DENY.
- **Audit**: SQLite, UPDATE/DELETE blocked by triggers, SHA-256 hash chain, secrets redacted.

## Development

```bash
uv run pytest
```
```bash
uv run ruff check src tests
```

Layout: `src/sentinel/` (control plane), `src/sentinel/sdk/` (analysis agents, runtime guard, CLI),
`src/sentinel/ai/` (model providers and stream-watching agents), `policies/`, `examples/`,
`tests/{unit,integration,e2e,sdk}/`, `docs/`. Design and decisions:
[docs/architecture.md](docs/architecture.md), [docs/decisions.md](docs/decisions.md).

Environment variables (see `.env.example`): `GROQ_API_KEY`, `SENTINEL_AI`, `SENTINEL_AI_MODEL`,
`SENTINEL_AI_FALLBACK_MODELS`, `SENTINEL_PROJECT` (workspace lookup), `SENTINEL_AUDIT_PATH`,
`SENTINEL_COLLECTOR_TOKEN`, `SENTINEL_HEARTBEAT=0`, `SENTINEL_APPROVER`, `SENTINEL_REQUIRE=1`
(guards error instead of running unmonitored when Sentinel cannot start), `NO_COLOR`.

## Limitations

These are deliberate MVP boundaries. Do not present them as solved.

**SDK**
- **Coverage is what is instrumented.** `instrument` adds guards for selected Python functions; other
  places need manual guards. Calls that bypass a guard are invisible to it (health reports missing
  and removed guards, not unknown code paths).
- **Static analysis is shallow.** Python uses the AST with import aliases and simple variable types;
  cross-module data flow, dynamic dispatch and reflection are not followed. JS/TS is line-pattern
  based and approximate. Other languages are not analysed. Risk levels are heuristic and err towards
  over-reporting.
- **Offline mode is keyword matching, not AI.** With Groq the agents were verified live on the
  example app; the free tier rate-limits, which the provider handles by retrying and falling back to
  smaller models. AI findings are advisory and can be wrong.
- **Data-flow scope.** Taint is per run (`sentinel.run(...)`; default one run per process, which is
  conservative). Paraphrased content is not tracked.
- **Approvals are a local file** (anyone who can write `.sentinel/` can approve) and policy cannot
  condition on argument values. The collector is plain HTTP (use TLS in front) and single-node.

**Control plane**
- **Same-process isolation.** Gateway and agents share a Python process; a hostile agent with
  interpreter access could reach tool objects. This is *detected* by reconciling target-system logs
  with the audit trail, not *prevented*.
- **Mock integrations only** in the demo: scripted agents, in-memory tools.
- **Advisory AI sees sanitised data.** Long fields are truncated, so an injection hidden deep in a
  long argument may be missed.
- **Tamper evidence, not tamper proofing.** Anyone who can rewrite the whole DB file can rebuild a
  consistent chain; external anchoring of the chain head is future work.
- **No bypass-acknowledgement workflow:** after a detected bypass the system stays RESTRICTED.
- **Approvals and identities are in memory** and lost on restart; the audit trail is durable.
- **The watchdog runs in the runtime process;** `sentinel watch` gives an independent heartbeat and
  chain check from outside it.
