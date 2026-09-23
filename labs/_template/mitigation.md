# Template mitigation notes — CVE-0000-0000

## Fix (do this)

1. Concrete upgrade/patch step with the exact fixed version.
2. Configuration hardening that removes the exploitation condition.

## Compensating controls (until patched)

- WAF / virtual-patch signature matching the Sigma rule in `detection/sigma/`.
- Egress or permission restrictions that limit impact (link ATT&CK mitigations).

## Retest

1. `custos lab up cve-0000-0000 --mitigated`
2. `custos run cve-0000-0000 --retest` — expect `not_vulnerable`.
3. `custos report cve-0000-0000` — PoC `vulnerable` → retest `not_vulnerable`.

## ATT&CK view

- [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access).
