# Security Policy

## Safety model

Custos Vulnerum is a **local lab tool**. It runs deliberately vulnerable software to
demonstrate the vulnerability lifecycle, with safety enforced architecturally:

- Vulnerable services publish ports on `127.0.0.1` only and run on isolated Docker
  networks. `custos verify` re-verifies the bindings at runtime.
- PoC traffic is only sent to containers carrying the `io.custos.*` labels that this
  tool created. Any other target aborts with `SafetyError` before traffic is sent.
- PoC payloads are constants of each lab. There is no way to point the tool at an
  arbitrary host, run an arbitrary command, scan the Internet or chain a generic
  exploit — by design, not by policy.
- The Log4Shell lab proves exploitation through a JNDI lookup captured by an
  in-network canary. No code is delivered, inside or outside the lab.

## Supported use

- Running the bundled labs on a machine you own or control.
- Studying the detection content (`detection/sigma/`, `detection/wazuh/`) and reports.
- Adding new labs under `labs/` for CVEs you are authorized to test locally.

## Out of scope

- Pointing the labs, PoCs or payloads at systems you do not own or lack permission to
  test.
- Repurposing the PoC steps for scanning, exploitation or weaponization outside the
  local labs. The vulnerable images are real and dangerous — do not expose the ports
  beyond loopback (the compose files make that hard on purpose).

## Reporting vulnerabilities in Custos Vulnerum

Report suspected vulnerabilities in this codebase via
[GitHub private reporting](https://github.com/alexiss31/custos-vulnerum/security/advisories/new)
(or open a public issue if the finding is low risk and has no exploit value).

Include: affected version/commit, reproduction steps, impact, and any proof-of-concept
that stays within the local-lab safety model. Expect an acknowledgement within 7 days.

## Supported versions

| Version | Supported |
|---|---|
| `main` | yes |
| older commits | best effort |

## Keeping the labs contained

1. Run `uv run custos lab down <id>` when you are done; `docker compose down -v` is
   invoked for both variants (vulnerable and mitigated).
2. Never re-publish the lab ports on `0.0.0.0` or a routable address.
3. Treat `artifacts/` as operational data: it contains real exploit evidence from your
   machine (it is git-ignored for that reason).
