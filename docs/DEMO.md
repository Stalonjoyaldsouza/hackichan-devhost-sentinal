# Demo script (≈ 5 minutes)

Everything below is real output from commands you run live. Nothing external is contacted unless
you choose `--ai groq`.

## One command: the full story with pass/fail checks

```bash
uv run sentinel sdk demo
```

With real AI (Groq) analysing the code and watching the live traffic:

```bash
export GROQ_API_KEY=your-key
```
```bash
uv run sentinel sdk demo --ai groq --yes
```

It ends with `Result: 23/23 checks passed`. What the audience sees, step by step:

| # | Step | The point to make |
|---|---|---|
| 1 | Agents analyse the example support bot with the company's guidelines | It understands the app (tools, data, external systems), finds risky spots, and ignores a prompt injection hidden *in the guideline file*. The `.env` file is listed but never opened. |
| 2 | Select HIGH+ points; `instrument` shows a diff, then `--apply` | Guards are added for you, reviewable and reversible. |
| 3 | `status` before running | Guards exist but **nothing is ACTIVE** — Sentinel never claims monitoring it hasn't seen work. |
| 4 | App deployed in **observe** mode; an injected request makes the agent email customer data to an attacker | It is not blocked (observe), but `watch` shows the policy would block it, the data-flow monitor flags it as "NOT blocked", and the AI threat agent flags the injected instruction. Destinations are masked before the AI sees them. |
| 5 | `status` again | Exercised points are ACTIVE; never-exercised ones honestly stay IMPLEMENTED. |
| 6 | Switch to **enforce** | The same attack is refused *before* the email is sent; the legitimate internal email still works. |
| 7 | High-value refund | Held for human approval → `approve` → proceeds once → asking again needs a new approval. |
| 8 | Failure drills | `kill -9` the app → `health` says APP_NOT_REPORTING (critical). Change config without regenerating policy → POLICY_OUT_OF_DATE. Remove the guards → GUARD_REMOVED (critical). The audit chain verifies throughout. |
| 9 | Recovery | Guards restored, app restarted → the crash is recorded as replaced by a new process, no critical findings remain, points are ACTIVE again. |

## Doing it by hand (two terminals)

Terminal 1 — the watcher, independent of the app:

```bash
cd examples/support_bot
```
```bash
uv run sentinel sdk watch --ai offline
```

Terminal 2 — analyse, select, instrument, then run your app as usual:

```bash
uv run sentinel sdk analyze --guidelines ../guidelines
```
```bash
uv run sentinel sdk select --min-risk HIGH
```
```bash
uv run sentinel sdk instrument --apply
```
```bash
uv run sentinel sdk status
```
```bash
uv run sentinel sdk health
```

Undo the changes to the example afterwards:

```bash
uv run sentinel sdk instrument --revert
```

## If something goes wrong on stage

* Groq rate limit (HTTP 429): the provider retries and falls back to smaller models; if all are
  limited, run the offline demo — every check still passes without AI.
* No network: use `uv run sentinel sdk demo` (offline). It never calls out.
