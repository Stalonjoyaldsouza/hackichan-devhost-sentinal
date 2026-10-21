# Sentinel SDK — analyse a business project and monitor what matters

The SDK turns the Sentinel control plane into something you run **inside your own project**. It
reads your code, works out where your AI agents can do something risky, lets you choose what to
monitor, and gives you a runtime guard that enforces policy at those points. Everything is shown
in the terminal (the same live view as `sentinel watch`).

## Install

From a checkout of this repository (or from the built wheel):

```bash
uv build --wheel          # → dist/sentinel-0.1.0-py3-none-any.whl
```
```bash
pip install dist/sentinel-0.1.0-py3-none-any.whl     # or: uv pip install …
```

Requires Python 3.12+. The wheel ships the default policy; nothing else needs configuring.

## Quick start (inside your business project)

```bash
cd my-business-app
```
```bash
sentinel sdk analyze --guidelines ../security-policy.md
```
```bash
sentinel sdk select -i                 # review the list, choose points to monitor
```
```bash
sentinel sdk snippet MP-1A2B3C4D       # code to add for one point; paste it in
```
```bash
sentinel sdk status                    # honest view: what is really monitored
```

`analyze` creates `.sentinel/` on first use. It analyses the project in the current directory, never
Sentinel's own source (it refuses if you run it there; pass `--path <project>` to target another
directory). A runnable example lives in [examples/support_bot](../examples/support_bot) with
[guidelines](../examples/guidelines/security-policy.md).

## What the SDK agents do

| Agent | Kind | Job |
|---|---|---|
| `scanner` | deterministic | inventory files, dependencies, frameworks; lists secret-looking files (`.env`, keys) **without opening them** |
| `guidelines` | AI / offline | turns each guideline document into checkable requirements (`MUST`/`SHOULD`, mapped to categories) |
| `code-analyst` | deterministic | AST analysis (Python) and pattern matching (JS/TS) for monitoring points |
| `understanding` | AI / offline | explains how the application works: agents, tools, data sources, external systems |
| `triage` | AI / offline | reviews the candidates against the understanding and guidelines |

`sentinel sdk activity` shows, per agent, what it is analysing right now, what completed, what
failed and the result of each. The same events stream live through `sentinel sdk watch` and
appear during `analyze`.

### What the AI is and isn't allowed to do
Your code and guideline documents are treated as **untrusted input** (a guideline file can say
"ignore previous instructions" — it is flagged and ignored). Model output is schema-validated and
constrained: it can add notes, move a risk level by **one step**, and propose extra points only at a
file:line that exists. It **cannot** remove a point, select one, or touch policy. Guideline-driven
risk increases are applied by deterministic code, and total raise is capped at one level over the
static rating. If a model call fails, the task shows `FAILED`, a warning is recorded, and the
deterministic results are still produced.

### AI mode and data egress
`--ai offline` (default) uses no model: nothing leaves your machine, and the `understanding` and
`guidelines` agents use keyword heuristics (their output is labelled `offline-heuristic`; `triage`
makes no adjustments). `--ai groq` (needs `GROQ_API_KEY`) sends **redacted** excerpts — file names,
detected operations, ≤140-char snippets, dependency names, the start of the README and your guideline
text — to Groq, and asks for confirmation (`--yes` to skip). Secret-looking files are never read and
token/password patterns are masked before anything is sent or logged.

## Monitoring points

Each point has: id (`MP-XXXXXXXX`, stable across line shifts), risk, category, description, **reason
for monitoring**, source locations, and links to the guideline requirements that concern it.
Categories: `sensitive_data_access`, `tool_call`, `external_api`, `messaging`, `inter_agent`,
`code_execution`, `file_system`, `database`, `secret_access`, `llm_call`. A point inside a function an
LLM can call as a tool is raised one risk level.

```bash
sentinel sdk points [--risk-min HIGH] [--category messaging] [--state ACTIVE] [--json]
sentinel sdk show MP-1A2B3C4D
```

### Lifecycle — derived from evidence, never claimed

| State | Meaning | Evidence required |
|---|---|---|
| IDENTIFIED | found by analysis | in `analysis.json` |
| SELECTED | you chose to monitor it | in `state.json` |
| IMPLEMENTED | a guard for it exists in your code | `guard("MP-…")` / `monitor("MP-…")` / `check("MP-…")` found in source (comments ignored) |
| ACTIVE | the guard is **working** | a policy evaluation for the point in the audit trail within `activity_window_hours`, and the audit hash chain verifies |

Selecting a point does not monitor it. Having a decorator in the code does not make it ACTIVE. If
the audit chain is broken, no point can be ACTIVE. A guard on a deselected point is reported as
`NOT monitored`. `sentinel sdk status` ends with the count of actively monitored points.

## Adding a guard

```python
from sentinel.sdk import guard, monitor

@guard("MP-1A2B3C4D", destination_arg="to")            # sink: where does the data go?
def send_email(to, subject, body): ...

@guard("MP-5E6F7A8B", produces=["pii"])                # source: labels what it returns
def get_customer_records(): ...

with monitor("MP-9C0D1E2F", destination=url):          # or wrap a single call
    requests.post(url, json=payload)

with sentinel.run("request-123"):                      # optional: scope data-flow to a request
    handle(request)
```

Per call the guard records request → decision → execution in `.sentinel/audit.db` (argument
**names** only, never values), evaluates `.sentinel/policy.yaml` with the same deterministic engine
as the rest of Sentinel, and, because of `produces`, tracks that PII was read so a later send in the
same run to a non-allowed destination is caught even though each call alone is allowed.

* `mode: observe` (default) — never interferes; decisions that would block are logged with
  `would_block: true`.
* `mode: enforce` — `DENY` raises `SentinelDenied`, `REQUIRE_APPROVAL` raises
  `SentinelApprovalRequired`, both **before** your function runs. If the policy or audit store is
  unavailable the call fails closed (`SentinelUnavailable`).
* No `.sentinel/` workspace → the guard warns on stderr and runs the function unmonitored
  (`SENTINEL_REQUIRE=1` makes that an error instead).

### Let Sentinel add the guards

```bash
sentinel sdk instrument            # dry run: shows the diff for every SELECTED point
sentinel sdk instrument --apply    # writes it; originals saved under .sentinel/backups/
sentinel sdk instrument --revert   # removes exactly the lines Sentinel added
```

Every added line ends with `# sentinel:auto`. Files are re-parsed before being written and restored
if anything would break. Python functions and methods only; module-level code and JS/TS are listed
as "manual".

### Purpose and outcome verification

```python
from sentinel.sdk import purpose

with purpose(user_message):            # why the agent is acting — the AI agents compare it with
    agent.run(user_message)            # what the agent actually does (spots injected instructions)

@guard("MP-…", verify=lambda result, order_id, amount: ledger.refunded(order_id) == amount)
def issue_refund(order_id, amount): ...   # True → VERIFIED, False/str → FAILED, error → INCONCLUSIVE
```

No `verify` means no outcome claim at all — Sentinel never marks success from the function's own
return value.

## Running in production

A deployed app keeps its guards; everything below runs **outside** the app so a broken or
compromised app cannot vouch for itself.

| What | How |
|---|---|
| **App heartbeat** | Every guarded app sends a heartbeat every `heartbeat_seconds` (default 10) with policy version, audit and collector health, and the points it has guarded. A clean shutdown writes a stop marker, so a crash is distinguishable from a stop. |
| **Independent health** | `sentinel sdk health` (exit 0 OK, 1 degraded, 2 critical — use it in cron/CI/alerting) detects: app not reporting, policy missing/invalid/out of date or stale inside the app, guards missing or **removed**, audit trail broken or failing, collector unreachable. |
| **Live watch** | `sentinel sdk watch` streams events and prints health alerts as they appear and resolve. Add `--ai groq` (or `offline`) to run the threat / risk / audit agents on live traffic; their findings land in the audit trail (`sentinel sdk findings`). |
| **Safe failure** | `observe`: if Sentinel itself breaks (read-only disk, bad config, internal bug) the app keeps running with one warning. `enforce`: the guarded call fails closed (`SentinelUnavailable`). |
| **Central audit** | Run `sentinel sdk collector --db central.db` and set `collector_url` in each replica's config (token in `SENTINEL_COLLECTOR_TOKEN`). Replicas write locally first and forward from a persisted cursor, so an outage loses nothing; the collector de-duplicates and keeps its own hash chain. Point `watch`/`health` at the central store with `SENTINEL_AUDIT_PATH`. |
| **Approvals** | In `enforce` mode, `REQUIRE_APPROVAL` refuses the call and records a pending approval. `sentinel sdk approvals` / `approve ID --as human.owner` / `reject`. The next identical call (same point, function and destination) proceeds once. |
| **Read-only images** | Run `sentinel sdk policy` at build time so `policy.yaml` ships with the image (it is tracked in git). Without it the guard generates a temporary copy and warns. |

What the AI sees when watching: point titles and categories, function names, decisions, labels,
purposes and destinations with **e-mail local parts masked** (`a***@evil.example`, also inside free
text) and URLs reduced to their host — never argument values. Sending requires `--ai groq` plus
confirmation (`--yes`).

## Configuration (`.sentinel/config.yaml`)

```yaml
app_name: my-app
mode: observe                  # observe | enforce
default_action: ALLOW          # ALLOW | DENY | REQUIRE_APPROVAL for selected points
allowed_destination_domains: [corp.example]   # sensitive data may only reach these
approvers: [human.owner]
point_actions: {MP-1A2B3C4D: REQUIRE_APPROVAL}
activity_window_hours: 24
heartbeat_seconds: 10          # 0 disables the app heartbeat
collector_url: null            # e.g. http://collector.internal:8765 (behind TLS for remote)
collector_token_env: SENTINEL_COLLECTOR_TOKEN
audit_path: null               # or $SENTINEL_AUDIT_PATH
```

`policy.yaml` is **derived** from this file and the selection (`sentinel sdk policy`); selecting or
deselecting regenerates it, and running apps reload it within ~5 s. With no allowed domains,
sensitive-labelled data may not reach any selected external/messaging point.

## Commands

| Command | Purpose |
|---|---|
| `sentinel sdk init [--path DIR]` | create `.sentinel/` |
| `sentinel sdk analyze [-g FILE_OR_DIR]… [--ai offline\|groq\|auto] [--yes] [--path DIR]` | run the agents; also reads `.sentinel/guidelines/` |
| `sentinel sdk points / show` | list / inspect points |
| `sentinel sdk select [-i] [IDS…] [--all] [--min-risk R] [--category C]` | choose points (regenerates policy) |
| `sentinel sdk deselect [IDS…] [--all]` | stop monitoring |
| `sentinel sdk snippet ID` | integration code for a point |
| `sentinel sdk status` | counts per state + audit-trail health |
| `sentinel sdk activity [--run ID] [--all]` | running / failed / completed agent tasks |
| `sentinel sdk watch [--from-start]` | live view of agent activity and runtime guard events |
| `sentinel sdk policy` | regenerate `policy.yaml` |
| `sentinel sdk instrument [IDS…] [--apply] [--revert]` | add/remove guards for selected points (dry run by default) |
| `sentinel sdk health [--heartbeat-timeout S]` | independent health check; exit 0/1/2 |
| `sentinel sdk watch [--ai off\|offline\|groq\|auto] [--yes] [--from-start]` | live events + health alerts + optional AI agents |
| `sentinel sdk findings [--limit N]` | findings from the monitors and AI agents |
| `sentinel sdk approvals` / `approve ID --as WHO` / `reject ID --as WHO` | human approvals |
| `sentinel sdk collector --db PATH [--host] [--port] [--allow-remote]` | central audit collector |
| `sentinel sdk demo [--ai offline\|groq] [--yes] [--keep]` | guided end-to-end demo with pass/fail checks |

Every command takes `--path` (default: current directory, searching upward for `.sentinel/`).

## Files in `.sentinel/`

`config.yaml` (edit) · `analysis.json` · `state.json` (selection) · `policy.yaml` (derived) ·
`audit.db` (append-only, hash-chained; git-ignored with `policy.yaml`). Commit `config.yaml`,
`analysis.json` and `state.json` if you want the team to share the selection.

## Limitations

* **Coverage is what is instrumented.** Calls that bypass a guard are invisible to it. Health
  reports selected points without a guard (and guards that disappeared), but it cannot see calls in
  code nobody analysed or selected.
* **Static analysis is shallow.** Python is analysed through the AST with import aliases and simple
  `x = Client()` types; cross-module data flow, dynamic dispatch and reflection are not followed.
  JavaScript/TypeScript uses line patterns and is approximate. Other languages are not analysed.
  Auto-instrumentation covers Python functions/methods only.
* **Risk levels are heuristic.** Expect false positives; raises deliberately over-report.
* **Offline mode is not AI.** It is keyword matching; the triage agent only adjusts risk with a real
  model. AI findings are advisory and can be wrong (the AI never blocks anything).
* **Groq free tier rate-limits.** The provider retries once and falls back to smaller models
  (`openai/gpt-oss-20b`, `llama-3.3-70b-versatile`; set `SENTINEL_AI_FALLBACK_MODELS`); if every
  model is limited, the AI step shows `FAILED`/`DEGRADED` and deterministic results continue.
* **Policy cannot condition on argument values** (e.g. refund amount); `REQUIRE_APPROVAL` applies to
  every call of a point. Approvals are a local file: anyone who can write `.sentinel/` can approve.
* **Collector is plain HTTP** with a bearer token; put it behind TLS for anything beyond localhost.
  It is a single process with a SQLite store (no HA). In-memory spooling (read-only disk) is lost if
  the process dies before forwarding.
* **Heartbeats prove the process and Sentinel are alive, not that every code path is exercised.**
  A point is ACTIVE only after its guard evaluated a call.
* **Data-flow scope.** Taint is per run (`sentinel.run(...)`, default one run per process).
  Paraphrased/transformed data is not tracked.
