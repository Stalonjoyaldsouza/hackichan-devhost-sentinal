# Decision log

Status values: `PROVISIONAL` (chosen to unblock the MVP, needs team sign-off), `CONFIRMED`, `SUPERSEDED`.

| Date | Decision | Rationale | Owner | Impact | Status |
|---|---|---|---|---|---|
| 2026-10-17 | MVP is a **terminal tool**: all output goes to the terminal; no web dashboard. | Explicit user request ("a tool which watches, not the website; output logged in the terminal"). | User (Stalonjoyaldsouza) | Replaces the React dashboard for the MVP; satisfies CLAUDE.md §2 item 8 via CLI. | CONFIRMED by user |
| 2026-10-17 | Proceed to implementation after a written architecture review (`docs/architecture.md`) rather than waiting for a separate team approval round. | User asked to implement the MVP now. | User | §9 review delivered in docs; team may still revise. | CONFIRMED by user |
| 2026-10-17 | Python 3.12, Pydantic v2, PyYAML, pytest; managed with `uv`. | Smallest stack that supports strict validation and tests; matches the Python proposal in CLAUDE.md. | Claude | Whole codebase. | PROVISIONAL |
| 2026-10-17 | SQLite append-only, hash-chained audit store instead of PostgreSQL. | Zero-setup, deterministic demos; triggers + hash chain give tamper evidence. | Claude | `sentinel/audit.py`. Swap-able behind `AuditStore`. | PROVISIONAL |
| 2026-10-17 | In-house deterministic YAML policy engine instead of OPA. | No OPA binary installed; rule set is small; deterministic and fully unit-tested. | Claude | `sentinel/policy.py`, `policies/default.yaml`. | PROVISIONAL |
| 2026-10-17 | No LLM agents in the MVP; LangGraph/OpenTelemetry deferred. | No model provider approved (§14); deterministic controls are the MVP's value. | Claude | Monitor and investigator are deterministic. | PROVISIONAL |
| 2026-10-17 | Data labels: `public`, `internal`, `confidential`, `pii`. Confidential/PII may not leave approved internal domains. | Needed for scenario B; simplest useful set. | Claude | `policies/default.yaml`. | PROVISIONAL |
| 2026-10-17 | Safe mode: any CRITICAL probe → RESTRICTED (only `safe_in_restricted` tools). Recovery needs 2 consecutive healthy rounds **and** an authorised human override. | Fail visibly and safely; avoid flapping; keep a human in the loop. | Claude | `sentinel/safemode.py`, `sentinel/watchdog.py`. | PROVISIONAL |
