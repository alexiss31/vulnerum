# `lab.yaml` Schema (contract)

Parsed by `custos_vulnerum.models.LabMeta` (Pydantic); unknown keys are rejected.
Complete annotated example lives in [`labs/_template/lab.yaml`](../../../labs/_template/lab.yaml).

```yaml
id: cve-0000-0000                 # == directory name
title: str
summary: str
cve: CVE-0000-0000
cvss: 0.0
severity: critical                # low | medium | high | critical
vendor: str
component: str
affected_versions: str
fixed_versions: str
references: [url, ...]
attack:
  - technique_id: T1190
    role: initial access          # free text role in the lab narrative
compose:
  file: compose.yaml
  mitigated_file: compose.mitigated.yaml
  project: custos-cve-0000-0000   # docker compose project name (lowercase)
  target_service: str             # service receiving PoC requests
  port: 12734                     # published host port (bound to 127.0.0.1 in compose)
  container_port: 80
verification:                     # deterministic pre-PoC checks
  - kind: http_status             # http_status | body_contains | server_marker
    value: "200"
    description: str
poc:
  steps:
    - type: http                  # http | canary_ldap
      name: str
      role: act                   # act | proof (proof indicators == exploitable)
      method: GET
      path: /str                  # placeholders: {base_url} {token} {canary_host} {canary_port}
      headers: {Name: value}
      body: str
      expect_status: [200]
      expect_body: [str]
      expect_body_regex: [regex]
      description: str
    - type: canary_ldap
      name: str
      role: proof
      timeout_seconds: 10
      description: str
evidence:
  log_rules:                      # select lines from compose service logs
    - service: str
      contains: [str]
      max_lines: 20
detection_rules: [sigma/file.yml, ...]   # relative to detection/
mitigation_notes: mitigation.md
```

Rules enforced at load time:

1. `id` matches the directory name.
2. Exactly the fields above (`extra="forbid"`).
3. At least one `proof` step (a lab without an exploitability indicator cannot produce a
   verdict).
4. Placeholders resolved at run time; unknown placeholders are an error.
