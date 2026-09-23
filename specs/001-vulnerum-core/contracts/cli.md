# CLI Contract

`custos` — Typer app, module `custos_vulnerum.cli`. Exit code `0` on success, `1` on
operational failure (safety refusal, failed check, missing evidence), `2` on usage
errors (Typer/Click default).

| Command | Behavior | Writes |
|---|---|---|
| `custos list` | Rich table of labs: id, CVE, severity, component, status (down/running) | — |
| `custos lab up <id> [--mitigated]` | `docker compose up -d` for the lab project (vulnerable or mitigated variant), waits for HTTP readiness | — |
| `custos lab down <id>` | `docker compose down -v --remove-orphans` for all variants of the lab | — |
| `custos verify <id> [--mitigated]` | Runs `verification` checks + safety re-verification (loopback bindings, managed labels); prints observed values; exit 1 if any check fails | — |
| `custos run <id> [--retest]` | Safety gate → executes `poc.steps` → writes evidence run (`phase=poc` or `retest`) | `artifacts/<id>/<run>/evidence.json` |
| `custos detect <id> [--retest]` | Loads latest evidence run of the phase, derives events, matches Sigma rules, resolves ATT&CK | `detections.json` + updates `evidence.json` |
| `custos report <id> [--retest]` | Renders lifecycle report from evidence runs (poc + retest when both exist) | `report.md`, `report.html` |

Global environment overrides (all optional): `CUSTOS_ROOT` (repository root),
`CUSTOS_ARTIFACTS_DIR` (default `<root>/artifacts`).

Verdict semantics: `run` computes `result = vulnerable` iff at least one `role: proof`
step's indicators are met; `--retest` executes the same plan and expects
`result = not_vulnerable` (exit 1 if the lab is still exploitable).
