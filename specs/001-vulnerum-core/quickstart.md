# Quickstart — validation scenarios

Bounded path to prove the whole lifecycle. Times are warm-cache estimates.

## Prerequisites

- Docker Engine + Compose v2 plugin
- `uv` (https://docs.astral.sh/uv/)
- ~2 GB free disk for lab images

## Scenario 1 — full lifecycle, CVE-2021-41773 (~3 min)

1. `uv sync --extra dev`
2. `uv run custos lab up cve-2021-41773` → Apache 2.4.49 up at `http://127.0.0.1:8917`
3. `uv run custos verify cve-2021-41773` → PASS (banner 2.4.49, loopback binding)
4. `uv run custos run cve-2021-41773` → `result: vulnerable` (passwd disclosure + CGI `uid=`)
5. `uv run custos detect cve-2021-41773` → ≥1 Sigma rule matched, ATT&CK T1190 mapped
6. `uv run custos lab up cve-2021-41773 --mitigated` → httpd:2.4.51 variant up
7. `uv run custos run cve-2021-41773 --retest` → `result: not_vulnerable`
8. `uv run custos report cve-2021-41773` → `artifacts/cve-2021-41773/<run>/report.md`

Expected: step 4 evidence shows `root:x:0:0` and `uid=`; step 7 evidence shows the same
requests returning 404 with no disclosure; report shows mitigation effective.

## Scenario 2 — full lifecycle, CVE-2021-44228 (~4 min)

1. `uv run custos lab up cve-2021-44228` → Solr 8.11.0 at `http://127.0.0.1:8986`
2. `uv run custos verify cve-2021-44228` → PASS
3. `uv run custos run cve-2021-44228` → `result: vulnerable` (LDAP canary captured the run token)
4. `uv run custos detect cve-2021-44228` → log4shell rules matched
5. `uv run custos lab up cve-2021-44228 --mitigated` → lookups disabled variant up
6. `uv run custos run cve-2021-44228 --retest` → `result: not_vulnerable` (canary silent)
7. `uv run custos report cve-2021-44228`

Expected: step 3 canary evidence contains the run token from the JNDI LDAP query; step 6
canary evidence is empty; report maps T1190 and cites `mitigation.md`.

## Scenario 3 — quality gates (~2 min, no Docker)

1. `make ci` → ruff, mypy, unit tests, Sigma validation, bandit + pip-audit all pass
2. `make smoke` (optional, needs Docker) → lifecycle tests run or skip explicitly

## Cleanup

`uv run custos lab down cve-2021-41773 && uv run custos lab down cve-2021-44228`,
then `make clean` to drop `artifacts/`.
