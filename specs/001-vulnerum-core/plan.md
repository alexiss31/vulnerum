# Implementation Plan: Vulnerum — Local Vulnerability Lifecycle

**Branch**: `001-vulnerum-core` | **Date**: 2026-09-23 | **Spec**: [spec.md](spec.md)

## Summary

Single Python 3.12 package `custos_vulnerum` behind a Typer CLI `custos`, orchestrating
data-defined Docker labs (`labs/<cve>/`) through the vulnerability lifecycle: launch →
verify → controlled PoC → evidence → Sigma detection → ATT&CK mapping → mitigation →
retest → report. Safety is enforced in code: localhost-only reachability, isolated lab
networks, managed-container gate, fixed payloads.

## Technical Context

**Language/Version**: Python 3.12 (uv-managed, `.python-version` pinned)

**Primary Dependencies**: Typer (CLI), Rich (output), Pydantic v2 (models), httpx (HTTP
PoC steps), Jinja2 (reports), PyYAML (lab metadata); Docker Compose v2 for lab lifecycle.

**Storage**: Filesystem only — `artifacts/<lab>/<run>/` JSON + Markdown/HTML reports;
no database.

**Testing**: pytest (unit, `-m "not docker"`), Docker smoke tests (`-m docker`, skip
when the daemon is unavailable), Sigma rule tests with pySigma + the official Sigma
JSON schema.

**Target Platform**: macOS/Linux workstations and GitHub Actions `ubuntu-latest`; needs
Docker only for lab commands and smoke tests.

**Project Type**: Single package + CLI, labs-as-data.

**Performance Goals**: Lab startup < 60 s warm; `custos run` bounded by step timeouts
(≤ 30 s per step); full local CI gate < 2 min.

**Constraints**: Constitution I–VII. Notably: localhost binding, managed containers
only, fixed payloads, evidence honesty.

**Scale/Scope**: 2 labs, 3 Sigma rules, 6 CLI verbs, 1 optional SIEM adapter.

## Constitution Check

*GATE: passed before Phase 0; re-checked after design.*

- I Safety Is Architectural — PASS: design binds `127.0.0.1`, isolated networks, `safety.py` gate before every send, fixed payloads declared in `lab.yaml`.
- II Deterministic First — PASS: verdicts derive from responses/logs/canary only; token randomness recorded in evidence.
- III Evidence Honesty — PASS: `evidence.json` is the single source for reports; report renders "not run" explicitly when stages are missing.
- IV Test-First — PASS: test list derived in [tasks.md](tasks.md) before implementation; smoke tests mirror the demo path.
- V Library-First + Text CLI — PASS: every verb maps to an importable module; JSON artifacts are the data interface.
- VI Simplicity — PASS: one package; labs are declarative YAML/Compose/Markdown; no plugin loader beyond directory discovery.
- VII Documentation Honesty — PASS: README/SECURITY describe shipped commands only; attributions tracked (see [research.md](research.md)).

## Project Structure

### Documentation (this feature)

```text
specs/001-vulnerum-core/
├── spec.md              # Feature specification
├── plan.md              # This file
├── research.md          # Phase 0: source research + decisions
├── data-model.md        # Phase 1: typed models and schemas
├── quickstart.md        # Phase 1: validation scenarios
├── contracts/           # CLI contract, lab schema, evidence JSON schema
│   ├── cli.md
│   ├── lab-schema.md
│   └── evidence.schema.json
├── checklists/
│   └── spec-quality.md  # /speckit-checklist output
└── tasks.md             # Executable task list (TDD ordering)
```

### Source Code (repository root)

```text
src/custos_vulnerum/
├── cli.py               # Typer app: list, lab up/down, verify, run, detect, report
├── config.py            # Path resolution (labs/, detection/, artifacts/)
├── models.py            # Pydantic models: lab.yaml, PoC plan, evidence, detections
├── catalog.py           # labs/ discovery + lab.yaml loading
├── lifecycle.py         # Docker Compose project up/down/status/logs
├── safety.py            # Localhost + managed-container gate
├── canary.py            # LDAP canary log parsing (canary runs as lab service)
├── pocs.py              # Declarative PoC plan executor (http, canary_ldap steps)
├── evidence.py          # Normalized evidence artifacts I/O + event derivation
├── detection.py         # Sigma-subset matcher over normalized events
├── attack.py            # ATT&CK tag → technique resolution (curated data)
├── report.py            # Jinja2 report rendering (Markdown + HTML)
├── data/attack_techniques.json
└── templates/report.{md,html}.j2

labs/
├── README.md            # Lab authoring guide
├── _template/           # Documented copy-ready template (skipped by discovery)
├── cve-2021-41773/      # compose.yaml, compose.mitigated.yaml, Dockerfile, lab.yaml,
│                        # mitigation.md, fixtures/
└── cve-2021-44228/      # + canary/ (in-network LDAP canary image)

detection/
├── sigma/               # Sigma v2 rules (validated in CI)
└── wazuh/               # Optional Wazuh custom-rule adapter + notes

tests/                   # unit + docker smoke tests, fixtures
.github/workflows/ci.yml # ruff, mypy, pytest, bandit, pip-audit, sigma
```

**Structure Decision**: single package, labs-as-data. PoC behavior is declared in
`lab.yaml` and executed by one generic runner (Constitution VI): a new CVE needs zero
orchestration changes.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| none | — | — |
