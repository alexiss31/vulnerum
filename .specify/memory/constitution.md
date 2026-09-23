# Vulnerum Constitution

Spec-Driven Development backbone for this repository, following
[github/spec-kit](https://github.com/github/spec-kit) (`.specify/memory/constitution.md`).

## Core Principles

### I. Safety Is Architectural

Vulnerable services bind to `127.0.0.1` only. Lab containers run on isolated Docker
networks. PoC steps run only against containers that Vulnerum itself launched and
labelled (`io.custos.*`). Payloads are fixed per lab: no arbitrary commands, no arbitrary
targets, no Internet scanning, no generic exploitation. `custos_vulnerum.safety` enforces
this before any request is sent; `custos verify` re-verifies bindings at runtime. Any
change that widens reachability is a constitutional violation.

### II. Deterministic First

Same lab, same result. No LLM calls, no wall-clock logic in verdicts, no network access
beyond the local lab. Randomness is limited to per-run canary tokens, recorded in
evidence. Outcomes derive only from observable artifacts: responses, container logs and
canary connections.

### III. Evidence Honesty

Artifacts record only what actually ran: timestamp, request, selected logs, result,
matched rule, ATT&CK IDs. Never claim a check passed that did not run. A report without
evidence is a bug. Screenshots and demo media are not fabricated; the README embeds real
captured output or nothing.

### IV. Test-First (NON-NEGOTIABLE)

Behavior is pinned by tests before or with implementation: unit tests for every
deterministic subsystem, Docker smoke tests for the lab lifecycle (skipped, never faked,
when Docker is unavailable). CI runs lint, types, tests, security audit and Sigma rule
validation on every push.

### V. Library-First with a Text CLI

Every capability lives in `src/custos_vulnerum/` as a typed, importable module (Pydantic
models at the boundaries) and is reachable from the `custos` CLI. Machine-readable
evidence and reports are JSON; human output is Rich-rendered but the underlying data is
always available as files.

### VI. Simplicity

One project, one package, one orchestration core. Labs are data (`labs/<cve>/`), not
code: adding a CVE must not require changing core orchestration. No speculative
generality, no abstraction without two concrete users.

### VII. Documentation Honesty

Docs describe shipped behavior only. No placeholders, no dead links to missing files, no
claims about checks or demos that do not exist. Third-party material keeps attribution
and a license note.

## Additional Constraints

- Python 3.12 with `uv`; Typer, Rich, Pydantic, httpx, Jinja2 are the allowed core deps.
- Sigma rules conform to the Sigma specification v2.x and are validated with current
  SigmaHQ tooling (pySigma / sigma-cli) in CI.
- MITRE ATT&CK identifiers and names come from live ATT&CK content, kept in
  `src/custos_vulnerum/data/attack_techniques.json` with source URLs.
- The Wazuh adapter is optional: the default demo must run without Wazuh.
- Runtime output goes to `artifacts/` (git-ignored); only tiny curated fixtures are
  tracked.

## Governance

This constitution supersedes ad-hoc practice for this repository. Amendments require a
commit to this file with rationale and an updated date. Reviews check: safety boundaries
unchanged, tests before code, evidence produced by real runs only.

**Version**: 1.0.0 | **Ratified**: 2026-09-23 | **Last Amended**: 2026-09-23
