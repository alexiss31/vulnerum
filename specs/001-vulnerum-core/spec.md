# Feature Specification: Custos Vulnerum — Local Vulnerability Lifecycle

**Feature Branch**: `001-vulnerum-core`

**Created**: 2026-09-23

**Status**: Implemented

**Input**: User description: "Public portfolio project demonstrating the local
vulnerability lifecycle: launch → verify → controlled PoC → collect evidence → detect →
map MITRE ATT&CK → mitigate → retest → report, with safety as architecture and Spec Kit
as the SDD backbone."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Launch and verify a vulnerable lab, safely (Priority: P1)

An operator lists the available labs, launches one in Docker, and verifies it is really
up, really vulnerable and really confined to localhost before touching it.

**Why this priority**: Nothing else is meaningful until a lab runs safely and is proven
to be the vulnerable target we claim.

**Independent Test**: `custos list`, `custos lab up <id>`, `custos verify <id>` on a
machine with Docker; verify prints PASS only when the service answers and the port is
bound to `127.0.0.1`.

**Acceptance Scenarios**:

1. **Given** Docker is running, **When** the operator runs `custos lab up cve-2021-41773`, **Then** the Apache 2.4.49 lab starts and is reachable only at `http://127.0.0.1:<port>`.
2. **Given** the lab is up, **When** the operator runs `custos verify <id>`, **Then** every check reports the observed value (banner/version marker, HTTP status, port binding) and the summary passes.
3. **Given** Docker is not running, **When** any lab command runs, **Then** it fails with a clear, actionable error and never reports success.

### User Story 2 - Run a controlled PoC and collect normalized evidence (Priority: P2)

The operator runs the lab's fixed PoC and gets a machine-readable evidence record:
timestamp, request, selected logs, result — written under `artifacts/`.

**Why this priority**: The PoC + evidence pair is the offensive-understanding proof and
the input to all later stages.

**Independent Test**: `custos run <id>` against a fresh lab produces
`artifacts/<id>/<run>/evidence.json` whose steps contain real requests and log excerpts.

**Acceptance Scenarios**:

1. **Given** the vulnerable lab is up and verified, **When** the operator runs `custos run <id>`, **Then** fixed PoC steps execute against the managed container only and the verdict is `vulnerable` with evidence for each step.
2. **Given** a run completed, **When** the operator inspects `evidence.json`, **Then** each step shows request, response summary, selected container logs and timestamps.
3. **Given** the target is not a Custos-managed container, **When** a PoC would run, **Then** the run aborts with `SafetyError` and sends nothing.

### User Story 3 - Detect the activity with Sigma and map MITRE ATT&CK (Priority: P3)

The operator matches the collected evidence against Sigma v2 rules and gets matched
rules plus ATT&CK technique IDs attached to the evidence.

**Why this priority**: Detection engineering is half the portfolio value; it builds on
evidence produced in US2.

**Independent Test**: `custos detect <id>` after a successful run reports ≥1 matched rule
with ATT&CK IDs; after a retest run the exploitation-signal rule reports no match.

**Acceptance Scenarios**:

1. **Given** a `vulnerable` evidence run, **When** the operator runs `custos detect <id>`, **Then** the matching Sigma rule and its ATT&CK IDs are stored in `detections.json` and merged into the evidence record.
2. **Given** a retest evidence run, **When** the operator runs `custos detect <id> --retest`, **Then** the exploitation-signal rule (canary/lookup) reports zero matches — attempt indicators may still match, because the attempt itself stays visible in logs.
3. **Given** rules in `detection/sigma/`, **When** CI validates them, **Then** current SigmaHQ tooling accepts them and they parse under the Sigma v2 specification.

### User Story 4 - Mitigate, retest, and export the lifecycle report (Priority: P4)

The operator launches the mitigated variant, re-runs the same PoC expecting it to fail,
and exports a report covering the whole lifecycle with ATT&CK mapping and mitigation
notes.

**Why this priority**: Closes the lifecycle: the report is the shareable artifact.

**Independent Test**: `custos lab up <id> --mitigated`, `custos run <id> --retest`,
`custos report <id>` produce a report that states exploitability before, the mitigation,
and the retest outcome with evidence.

**Acceptance Scenarios**:

1. **Given** a mitigated lab is up, **When** the operator runs `custos run <id> --retest`, **Then** the verdict is `not_vulnerable` and evidence shows the blocked indicator.
2. **Given** PoC and retest evidence exist, **When** the operator runs `custos report <id>`, **Then** `report.md` and `report.html` under `artifacts/` present lifecycle, evidence, detections, ATT&CK table and mitigation notes.

### Edge Cases

- Docker unavailable → clear error, no partial state, non-zero exit.
- Lab already up (same or other variant) → compose project is idempotent; verify detects the running variant.
- Retest run against a *vulnerable* lab → report must show `vulnerable` (mitigation NOT effective), not silently claim success.
- Detection run without evidence → clear error pointing to `custos run`.
- Log volume large → evidence keeps *selected* excerpts per lab config, with line caps.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The product is a Python 3.12 CLI `custos` with commands `list`, `lab up <id> [--mitigated]`, `lab down <id>`, `verify <id>`, `run <id> [--retest]`, `detect <id>`, `report <id>`.
- **FR-002**: Each lab lives in `labs/<cve>/` and owns its Compose files, `lab.yaml` metadata, `fixtures/` and `mitigation.md`; core orchestration is lab-agnostic.
- **FR-003**: Two deterministic labs ship: CVE-2021-41773 (Apache HTTP Server 2.4.49) and CVE-2021-44228 (Log4Shell on Solr 8.11.0 / Log4j 2.14.1).
- **FR-004**: A documented lab template (`labs/_template/`) allows adding a CVE without touching `src/custos_vulnerum/`.
- **FR-005**: Safety: all published ports bind `127.0.0.1`; lab networks are isolated; PoCs run only against Custos-managed labelled containers; payloads are fixed per lab.
- **FR-006**: PoC runs write normalized evidence (timestamp, request, selected logs, result, matched rule, ATT&CK IDs) to generated `artifacts/`; runtime artifacts are git-ignored except tiny tracked fixtures.
- **FR-007**: Sigma v2 rules cover both labs and are validated with current SigmaHQ tooling in CI.
- **FR-008**: An optional Wazuh adapter (example custom rule + integration notes) ships under `detection/wazuh/`; the default demo never requires Wazuh.
- **FR-009**: `SECURITY.md` documents the safety model, permitted use and reporting policy.
- **FR-010**: Tests: pytest unit tests for all deterministic subsystems plus Docker smoke tests that skip when Docker is unavailable.
- **FR-011**: CI runs Ruff, mypy, pytest, Bandit and pip-audit, plus Sigma validation.
- **FR-012**: Repo hygiene: `pyproject.toml`, `.editorconfig`, `.gitignore`, pre-commit hooks, a Makefile task runner, MIT license for original code, conventional commits.
- **FR-013**: README is scannable in ~60 seconds: value proposition, small badge row, quickstart, compact Mermaid architecture, supported-labs table, detection/report example, safety, testing/CI, acknowledgements.
- **FR-014**: No placeholders, no fake results, no fabricated screenshots.

### Key Entities

- **Lab**: a CVE-specific, self-contained directory: metadata, compose lifecycle (vulnerable + mitigated variants), fixtures, mitigation notes.
- **PoC plan**: ordered fixed steps (`http`, `canary_ldap`) with roles `act`/`proof`; proof indicators determine exploitability.
- **Evidence run**: normalized record of one execution (poc or retest) with steps, logs, verdict.
- **Detection match**: Sigma rule hit over normalized events, with ATT&CK IDs.
- **Report**: lifecycle narrative assembled from evidence runs + detections + ATT&CK + mitigation notes.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: From a clean checkout with Docker, the 8-command demo (`make demo`) completes for both labs with `vulnerable → detected → retest not_vulnerable` outcomes, in under 10 minutes on a warm image cache.
- **SC-002**: 100% of unit tests pass without Docker; smoke tests skip (never fail) when Docker is unavailable.
- **SC-003**: `make ci` (lint, mypy, unit, sigma, audit) passes from a clean checkout.
- **SC-004**: Every `proof` verdict in `artifacts/` is backed by at least one concrete indicator (response match or canary log line) present in the same file.
- **SC-005**: Adding a hypothetical third lab requires only `labs/<cve>/` content (zero changes in `src/custos_vulnerum/`).

## Assumptions

- Docker Engine with the Compose v2 plugin is available for lab commands; everything else works without it.
- Labs target `127.0.0.1` on fixed high ports (8917 for CVE-2021-41773, 8986 for CVE-2021-44228) chosen to avoid common local services.
- The Log4Shell PoC proves exploitation by the JNDI lookup reaching a lab-internal LDAP canary; it deliberately does not deliver a remote class (no code execution payload).
- Vulnerable images are pinned (`httpd:2.4.49`, `solr:8.11.0`); the mitigated Apache variant pins `httpd:2.4.51` (first fully patched release).
- Wazuh integration is documented, not orchestrated.

## Clarifications (resolved during /speckit-clarify)

- *PoC depth for CVE-2021-41773*: fixed two-step proof — `/etc/passwd` disclosure via
  traversal, then CGI traversal executing the constant `echo;id`. No user-supplied
  commands (Constitution I).
- *Log4Shell proof*: JNDI `ldap:` lookup captured by an in-network canary service;
  payload target is the canary container name, never an external host.
- *Sigma scope*: rules are authored against Custos normalized event fields and document
  the mapping to real log sources in `logsource.definition`; full SIEM portability is a
  v2 concern.
