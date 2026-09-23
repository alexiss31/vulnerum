# Lab authoring guide

Add a CVE as **data** — the orchestration core (`src/custos_vulnerum/`) never changes.

## Steps (~15 min)

1. Copy the template: `cp -r labs/_template labs/cve-YYYY-NNNNN`
2. Edit `lab.yaml`: set `id: cve-YYYY-NNNNN` (must equal the directory name) and fill
   every field (schema: [`specs/001-vulnerum-core/contracts/lab-schema.md`](../specs/001-vulnerum-core/contracts/lab-schema.md)).
3. Wire the lab in `compose.yaml`: pinned image/build, **loopback-only** port,
   isolated `labnet`, `io.custos.*` labels. Keep `compose.mitigated.yaml` as the fixed
   variant used for retesting.
4. Write `poc.steps` — fixed payloads only (see below) — and `evidence.log_rules`.
5. Add a Sigma rule under `detection/sigma/` and list it in `detection_rules`.
   Validate: `make sigma`.
6. Write `mitigation.md` (fix steps + retest commands) and tiny `fixtures/` samples.
7. Prove it: `make unit && uv run custos lab up cve-YYYY-NNNNN && uv run custos run cve-YYYY-NNNNN`.

## Hard rules (Constitution I)

- Published ports bind `127.0.0.1` only; networks isolated (`internal: true` where
  possible).
- Services carry `io.custos.project: vulnerum` and `io.custos.lab: <id>` labels — the
  safety gate refuses anything else.
- PoC payloads are **constants of the lab**. No user-supplied hosts, commands or
  scanning. Callbacks go to the lab-internal canary (`canary.ldap`), never outside.
- At least one `role: proof` step whose indicators equal "exploitable".

## Files

| File | Purpose |
|---|---|
| `lab.yaml` | metadata, compose wiring, verification checks, PoC plan, evidence/detection config |
| `compose.yaml` | vulnerable variant (project `custos-<id>`) |
| `compose.mitigated.yaml` | patched variant (project `custos-<id>-mit`) |
| `mitigation.md` | fix + compensating controls + retest procedure |
| `fixtures/` | tiny real-format log samples used by tests and the report examples |
| `canary/` | optional in-network callback service (see cve-2021-44228) |
