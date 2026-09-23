# Tasks: Custos Vulnerum — Local Vulnerability Lifecycle

Feature: `001-vulnerum-core` · Input: [plan.md](plan.md), [research.md](research.md),
[data-model.md](data-model.md), [contracts/](contracts/)

Format: `T### · [P?] · phase · requirement-refs · description`. `[P]` = parallel-safe.
Checkboxes are checked as implementation lands (all checked at release).

## Phase 0 — Scaffolding (completed first)

- [x] T001 · P · Setup · FR-012 · uv project, pyproject (Typer/Rich/Pydantic/httpx/Jinja2/PyYAML + dev), ruff/mypy/pytest/bandit config, Makefile, .editorconfig, .gitignore, pre-commit, MIT LICENSE
- [x] T002 · P · Setup · FR-012 · rtk bootstrap + SDD artifacts (constitution, spec, plan, research, data-model, contracts, checklist, tasks, quickstart)

## Phase 1 — Core (test-first: tests listed per task)

- [x] T003 · P · Core · FR-002 · `models.py`: LabMeta/PoCStep/VerificationCheck/LogRule with `extra="forbid"` + placeholder validation (`tests/test_models.py`)
- [x] T004 · P · Core · FR-002 · `config.py` + `catalog.py`: root resolution, labs/ discovery skipping `_template` (`tests/test_catalog.py`)
- [x] T005 · P · Core · FR-005 · `safety.py`: loopback-only target gate + managed-container label/binding assertions (`tests/test_safety.py`)
- [x] T006 · Core · FR-001/FR-002 · `lifecycle.py`: compose up/down/status/logs per project+variant (`tests/test_lifecycle.py`)
- [x] T007 · Core · FR-003 · `pocs.py`: declarative executor for `http` + `canary_ldap` steps, act/proof verdict semantics (`tests/test_pocs.py`)
- [x] T008 · P · Core · FR-006 · `evidence.py`: evidence run model, artifact I/O, event derivation (`tests/test_evidence.py`) + `contracts/evidence.schema.json` validation
- [x] T009 · P · Core · FR-007 · `detection.py`: Sigma-subset matcher (keywords, maps, modifiers, condition grammar) (`tests/test_detection.py`)
- [x] T010 · P · Core · FR-007 · `attack.py` + `data/attack_techniques.json` (live ATT&CK transcription) (`tests/test_attack.py`)
- [x] T011 · Core · FR-001 · `report.py` + Jinja2 templates (Markdown + HTML) (`tests/test_report.py`)
- [x] T012 · Core · FR-001 · `cli.py`: list, lab up/down, verify, run, detect, report with Rich output and exit-code contract (`tests/test_cli.py`)
- [x] T013 · Core · FR-003 · `canary.py`: canary log parsing/token match (`tests/test_canary.py`)

## Phase 2 — Labs (data only)

- [x] T014 · P · US1 · FR-003 · `labs/cve-2021-41773/`: Dockerfile (httpd:2.4.49 + vulhub-adapted config), compose (+isolated net, loopback port, labels), compose.mitigated (httpd:2.4.51), lab.yaml, mitigation.md, fixtures
- [x] T015 · P · US1 · FR-003 · `labs/cve-2021-44228/`: minimal vulnerable log4j 2.14.1 webapp (stock jars) + in-network minimal LDAP canary, mitigated variant (JndiLookup removed), lab.yaml, mitigation.md, fixtures
- [x] T016 · P · Setup · FR-004 · `labs/_template/` + `labs/README.md` authoring guide (loadable, skipped by discovery)

## Phase 3 — Detection content

- [x] T017 · P · US3 · FR-007 · Sigma v2 rules (apache traversal; log4shell http indicators; log4shell jndi/canary signal) in `detection/sigma/`
- [x] T018 · P · US3 · FR-007 · Sigma rule tests: pySigma parse + official JSON schema + tag/ATT&CK checks (`tests/test_sigma_rules.py`) + vendored schema fixture with provenance
- [x] T019 · P · US3 · FR-008 · Wazuh optional adapter: `local_rules.xml` example + integration notes + XML test (`tests/test_wazuh_rules.py`)

## Phase 4 — Verification and delivery

- [x] T020 · P · Setup · FR-010 · Docker smoke tests: full lifecycle both labs incl. mitigated retest (`tests/test_smoke_docker.py`, skip-not-fake)
- [x] T021 · P · Setup · FR-011 · `.github/workflows/ci.yml`: ruff, mypy, pytest (unit), bandit, pip-audit, sigma validation
- [x] T022 · P · US1-4 · FR-009/FR-013 · README.md (60s scan) + SECURITY.md (safety model)
- [x] T023 · US1-4 · SC-001 · End-to-end run on Docker for both labs: capture real outputs for README, fix failures
- [x] T024 · US1-4 · SC-003 · Clean-checkout verification (`make ci`) + hygiene audit (secrets, unsafe ports, dead docs, generated junk)
- [x] T025 · US1-4 · FR-012 · Conventional commit history; publish `alexiss31/custos-vulnerum` public on `main`; verify README + Actions state

## Dependency notes

- T003–T005 are foundational for T006–T013; T007 needs T003/T005/T008.
- T014–T016 only need T003 (schema) and can proceed in parallel with Phase 1.
- T023 is the convergence gate: no claim of "ready" without real end-to-end evidence.
