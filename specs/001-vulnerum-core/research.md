# Phase 0 Research: authoritative sources and decisions

All sources inspected 2026-09-23 (live fetches, not memory). License audit included.

## Spec-Driven Development — github/spec-kit (MIT)

- Flow confirmed from the repo README: **constitution → specify → plan → tasks →
  implement → converge**, with clarify/checklist/analyze as optional quality gates.
- Artifacts mirror spec-kit's templates (`templates/constitution-template.md`,
  `spec-template.md`, `plan-template.md`, `tasks-template.md`) in
  `.specify/memory/` and `specs/001-vulnerum-core/`.
- Decision: keep the artifacts in-repo and hand-authored (no CLI scaffolding tool
  vendored into the repo).

## Docker Compose (docs.docker.com/reference/compose-file/networks/)

- `ports: ["127.0.0.1:8917:80"]` binds published ports to loopback only.
- `internal: true` isolates a network from external connectivity.
- `driver_opts: com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"` hardens the
  bridge default binding.
- Decision: every lab uses an isolated network (internal where possible) + explicit
  loopback port bindings + `io.custos.*` labels for the managed-container gate.

## Sigma — SigmaHQ/sigma-specification (spec text), pySigma (LGPL-2.1), sigma-cli (LGPL-2.1)

- Current specification: **v2.1.0** (2025-08-02); JSON schema V2.0.0 in
  `json-schema/sigma-detection-rule-schema.json`.
- Rule authoring conventions captured: single quotes, 4-space indent for rules,
  lowercase keys, filename convention (`web_cve_2021_41773_apache_path_traversal.yml` style),
  condition grammar (`and/or/not`, `N of them`, `N of pattern`, brackets), value modifiers
  (`|contains`, `|startswith`, `|endswith`, `|re`, `|exists`, `|all`), tags as
  namespaced (`attack.t1190`).
- Validation tooling: pySigma parses rules (`SigmaCollection.from_yaml`); sigma-cli
  converts them through real backends. CI uses both: pySigma parse + JSON-schema check
  in tests, `sigma convert` with a pySigma backend as the SigmaHQ-tooling gate.
- Decision: `custos detect` ships a small, documented **Sigma-subset matcher** over
  normalized lab events (deterministic, dependency-light, fully unit-tested). Rules
  themselves remain portable Sigma v2 and pass official tooling.

## MITRE ATT&CK (attack.mitre.org)

- **T1190 — Exploit Public-Facing Application** (Tactic TA0001 *Initial Access*),
  Enterprise v19 (technique version 2.8, last modified 2026-05-12). Verified live on
  the technique page; names/tactics/URLs stored in
  `src/custos_vulnerum/data/attack_techniques.json`.
- T1190's procedure examples explicitly include Log4Shell campaigns (C0017/C0018),
  matching CVE-2021-44228; the detection strategy DET0080 describes request → error →
  post-exploit chains matching our evidence model.
- Decision: both labs map to T1190; the Apache CGI code-execution proof additionally
  references T1059.004 (Command and Scripting Interpreter: Unix Shell) via the same
  curated dataset.

## Wazuh (documentation.wazuh.com, wazuh/wazuh-docker — GPLv2)

- Custom rules live in `local_rules.xml` (ruleset XML syntax: `rule id`, `level`,
  `match`/`pcre2`, `mitre` block with technique IDs, `group`).
- `wazuh/wazuh-docker` deploys the stack with Docker Compose; custom rules mount into
  the manager (`/var/ossec/etc/rules/`).
- Decision: ship an **optional** adapter (`detection/wazuh/`) with one example rule per
  lab and integration notes. The default demo never requires Wazuh (spec FR-008).

## vulhub/vulhub (MIT, Copyright phith0n / https://vulhub.org)

- `httpd/CVE-2021-41773`: `httpd:2.4.49` with CGI modules enabled and
  `<Directory />` set to `Require all granted`; PoC:
  `curl --path-as-is '.../icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'` (disclosure) and
  `curl --data 'echo;id' '.../cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'` (code execution).
- `log4j/CVE-2021-44228`: Solr 8.11.0 (Log4j 2.14.1); trigger:
  `GET /solr/admin/cores?action=${jndi:ldap://...}` — the `action` value is logged and
  the JNDI lookup fires an LDAP query.
- License audit: vulhub is MIT; adaptations preserve attribution in file headers and
  README acknowledgements. Upstream images: Apache httpd (Apache-2.0), Apache Solr
  (Apache-2.0), Apache Log4j (Apache-2.0).
- Decision: lab Dockerfiles/Compose are **adapted from** vulhub's reference setups
  (MIT), but built from **official multi-arch images** (`httpd:2.4.49`, `solr:8.11.0`)
  so the labs run on arm64 and amd64 alike (probed via `docker manifest inspect`;
  `vulhub/*` images are not multi-arch).

## PoC depth and mitigation variants

- CVE-2021-41773 proof = fixed disclosure request + fixed `echo;id` CGI request (no
  arbitrary commands). Mitigated variant = `httpd:2.4.51` (first fully patched release
  for the 2.4.49 traversal family).
- CVE-2021-44228 proof = JNDI `ldap:` lookup captured by an **in-network canary
  service** (the payload references the canary service inside the isolated lab network —
  nothing points off-box). The PoC deliberately stops at "lookup happened": no remote
  class loading, no code execution. Mitigated variant = the vendor-neutral Apache
  advisory fix (JndiLookup class removed from log4j-core), verified empirically by
  retest (no canary hit).
- Log4Shell detection is written against both the request indicators (`${jndi:` in
  path/user-agent/body, raw and URL-encoded) and the canary/JNDI signals, matching
  ATT&CK DET0080's multi-signal idea.

## Lab design decisions (verified empirically during implementation)

- **Target app for CVE-2021-44228**: the official `solr:8.11.0` image bakes
  `-Dlog4j2.formatMsgNoLookups=true` into its CMD and its log4j build does not resolve
  message-time lookups even when the flag is removed (verified against the shipped
  classes and live requests). The lab therefore ships a minimal webapp built against
  **stock log4j 2.14.1 jars from Maven Central** — the vulhub Log4Shell README
  explicitly allows "an application that depends on Log4j2" as the demonstrator.
- **Payload shape**: the JDK's `HttpServer` rejects raw `{`/`}` in request URIs
  ("Bad request URI"), so the query payload travels URL-encoded (the classic evasion
  form) while the User-Agent keeps the raw form. The app logs the decoded input —
  both forms are covered by the Sigma rule.
- **LDAP canary**: JNDI clients open with a 14-byte anonymous LDAP bind and wait for a
  bind response before sending the search request that carries the looked-up name (and
  the run token). The canary is therefore a minimal LDAP responder (bind + search
  answers) rather than a raw TCP sink, so the token-bearing bytes actually arrive.
- **Network isolation**: `internal: true` compose networks disable published-port
  forwarding entirely (verified: bindings declared but never activated). Labs use a
  dedicated per-lab bridge with `host_binding_ipv4=127.0.0.1` and explicit loopback
  publishes instead — same practical boundary, working port forwarding.
- **Variant switching**: both variants publish the same loopback port, so `lab up` of
  one variant replaces the other (recorded in `contracts/cli.md`).
- **Pull wedge workaround (dev machine only)**: this project's Docker daemon had a
  wedged image-pull path (registry pulls hang regardless of registry, local import/load
  fine). Images were fetched with `skopeo copy` and `docker load`ed. This is not part
  of the product; a clean checkout only needs a working Docker.

## Prose and presentation

- `ayghri/i-have-adhd/skills/i-have-adhd/SKILL.md` (MIT): prose rules adopted for all
  human-facing docs — action-first, numbered bounded steps, visible outcomes, no filler.
- `latent-spaces/brag` (launch-video generator) inspected: a rendered video adds no
  verifiable value and risks "fabricated demo" perception. Decision: **no video, no
  screenshots** — the README embeds real captured CLI/report text only.
