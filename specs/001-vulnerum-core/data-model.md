# Data Model

Typed in `src/custos_vulnerum/models.py` (Pydantic v2). Machine contract for evidence:
[contracts/evidence.schema.json](contracts/evidence.schema.json).

## Lab metadata (`labs/<cve>/lab.yaml`)

| Field | Type | Meaning |
|---|---|---|
| `id` | str | Directory name; unique lab key (e.g. `cve-2021-41773`) |
| `title`, `summary` | str | Human description |
| `cve` | str | CVE identifier |
| `cvss` | float | Base score (NVD) |
| `severity` | enum | `low\|medium\|high\|critical` |
| `vendor`, `component`, `affected_versions`, `fixed_versions` | str | Advisory facts |
| `references` | list[str] | URLs |
| `attack` | list[AttackRef] | `{technique_id, role}` → resolved via curated data |
| `compose.file` / `compose.mitigated_file` | str | Compose files relative to the lab dir |
| `compose.project` | str | Compose project name (`custos-cve-2021-41773`) |
| `compose.target_service` | str | Service PoCs address |
| `compose.port` | int | Published host port (loopback only) |
| `compose.container_port` | int | Container port |
| `verification` | list[VerificationCheck] | Deterministic pre-PoC checks (`http_status`, `body_contains`, `server_marker`) |
| `poc.steps` | list[PoCStep] | Declarative fixed steps (below) |
| `evidence.log_rules` | list[LogRule] | `{service, contains[], max_lines}` log selectors |
| `detection_rules` | list[str] | Sigma rule paths (relative to `detection/`) |
| `mitigation_notes` | str | Path to `mitigation.md` |

## PoC plan (`poc.steps`)

Discriminated union on `type` + `role` (`act` must succeed; `proof` indicators mean
exploitable):

- **HttpStep** `{type: http, name, role, method, path, headers, body, expect_status,
  expect_body[], expect_body_regex[], description}` — placeholders: `{base_url}`,
  `{token}`, `{canary_host}`, `{canary_port}`.
- **CanaryLdapStep** `{type: canary_ldap, name, role, token_field, timeout_seconds,
  description}` — asserts the run token appears in the lab canary service log.

## Evidence run (`artifacts/<lab>/<run_id>/evidence.json`)

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | str | `1.0` |
| `run_id` | str | UTC `YYYYMMDDTHHMMSSZ` |
| `lab_id`, `cve` | str | Target lab |
| `phase` | enum | `poc` \| `retest` |
| `started_at`, `finished_at` | ISO-8601 | UTC timestamps |
| `token` | str | Per-run canary token |
| `steps[]` | StepEvidence | Per-step evidence |
| `result` | enum | `vulnerable` \| `not_vulnerable` \| `error` |
| `detections[]` | DetectionMatch | Filled by `custos detect` |
| `attack[]` | AttackTechnique | Resolved ATT&CK rows |

### StepEvidence

`name`, `type`, `role`, `description`, `request` (`{method, url, headers, body_excerpt,
sent_at}`), `response` (`{status, body_excerpt, received_at}`), `logs[]` (`{service,
lines[]}`), `canary` (`{checked, matched, matched_lines[], observed_at}`),
`indicators_met` (bool), `expected` (human sentence).

### Normalized detection events (derived, not stored twice)

One event per request and one per selected log line:
`{timestamp, run_id, lab_id, phase, source, product, service, http_method, http_path,
http_user_agent, http_body, status, message, container}` — the field names Sigma rules
match on (documented in each rule's `logsource.definition`).

### DetectionMatch

`rule_id`, `rule_title`, `rule_level`, `attack_tags[]`, `technique_ids[]`,
`matched_event` (the event dict), `matched_identifiers[]` (search-identifiers that fired).

## ATT&CK dataset (`data/attack_techniques.json`)

`{technique_id, name, tactic_id, tactic_name, url, source}` — values transcribed from
live ATT&CK pages (see research.md) and resolved from `attack.*` Sigma tags at detect
time.

## Artifact layout

```text
artifacts/<lab_id>/<run_id>/
├── evidence.json      # normalized run record (schema above)
├── detections.json    # list[DetectionMatch] + rule metadata
├── report.md          # rendered lifecycle report
└── report.html        # same, HTML
```
