# Design decisions

The choices that shape the project, why we made them, and how each stays compatible with where the project is going: a neutral foundation, many implementations, and a shared network. New decisions are added at the end; old ones are never rewritten, only superseded.

| # | Decision | Why | Forward compatibility |
| --- | --- | --- | --- |
| 1 | Apache 2.0 for all code and registry data | The standard license across Linux Foundation projects, with an explicit patent grant | Nothing to relicense on foundation entry |
| 2 | Developer Certificate of Origin, no contributor license agreement | Lowest barrier to contribute; the Linux kernel's model | Foundations accept it as is |
| 3 | Neutral home: the `guardianprotocol-ai` GitHub org | The project must not belong to any company | Org, name and domains transfer to the foundation; company code lives elsewhere |
| 4 | Stable IDs (`GP-0001`), never reused | Sensors, reports and advisories cite them for years | IDs survive schema changes, renames and new implementations |
| 5 | The schema only grows within a major version | Old patterns and old sensors keep working | `schema_version` in every file; breaking changes need a new major version and a migration |
| 6 | Rules are data, never code | A rule can't run anything on a host, and anyone can build a sensor that enforces them | The Python sensor is a reference implementation, not the standard |
| 7 | One shared rule engine for the MCP sensor and client hooks | Same detection wherever an agent acts | New surfaces (gateways, egress proxies) plug into the same engine |
| 8 | MITRE ATLAS and OWASP are mappings, not dependencies | Frameworks update on their own schedules | The coverage map records the ATLAS release it was built from |
| 9 | Open standards for sharing and updates: STIX 2.1, TAXII 2.1, TUF, Sigstore | Existing security tools already speak them | No proprietary formats to migrate away from |
| 10 | Harmless tests: canary tokens and reserved `.test` domains (RFC 2606) | Anyone can run the registry safely | Safe to run in CI, in the scan and in the network |
| 11 | No third-party dependencies in the core for now | Smallest supply-chain surface for a security project | Any dependency added later is pinned and listed |
| 12 | Security Baseline Level 1 from day one | It's what foundation reviewers check | See the checklist below |
| 13 | A result carries one entry per run, not just the totals (`schema_version` 0.2) | `successes: 20` is a number someone typed, and a judge bug looks identical to a real finding. GP-0003 read "sunny" out of the agent's prose and was wrong on half of realistic answers; nobody could tell, because the answers were discarded. A reader must be able to recount the rate | Additive, so 0.1 files stay valid and a re-measurement is a second data point rather than a correction. Built rather than proposed because no contributor had recorded a result yet, which is the only moment this is free |
| 14 | A run log is published, so it is checked for secrets and written as escapes | The log holds verbatim agent output, which on a contributor's machine could be anything. `validate-results` refuses a log carrying a credential, and files are written with JSON escapes so no live invisible character ships. Canary tokens are exempt: they are harmless by construction and a canary in a log is the test working | The check reuses the sensor's own secret patterns, so one list serves detection and publication |
| 15 | Each pattern publishes what its own judge counts | "Attack success rate" over every cell overstated GP-0003, which counts whether a tool whose definition changed was used at all, not whether the agent was exploited. Three of four judges score a real side effect; one reads an answer | The criterion is generated from the judge's own docstring, so the matrix cannot drift from the code, and a new scenario publishes its definition automatically |
| 16 | The lab server logs every tool call | The only ground truth about a run was the side effects two tools happen to write, which left "the agent refused" and "the agent never attempted the task" indistinguishable, and left GP-0003 judged by matching the words "sunny" and "blocked" in the agent's prose. On ten realistic answers that judge was wrong on five, in both directions | One file, `calls.jsonl`, written by the test server only. No change to the protocol, the patterns or the sensor. A real harness is still measured from outside |
| 17 | A run that never opened the attack vector is counted, not folded in | An agent that declines the task did not resist an attack, it did not take part in one. GP-0008 scored 0 of 20 while the agent delegated at all in only 9 of 20 runs. Counting those as defences would let a fall in capability read as a rise in security, and quietly excluding them is how a denominator gets chosen after seeing the result. So `attempted` is published beside the rate and both denominators appear in the matrix | Additive: a scenario with no precondition records nothing, and `rate` keeps its existing meaning so every earlier file stays valid. The precondition rate is itself a measurement, and it is what surfaced that the sensor may suppress legitimate handoffs |
| 18 | A rate needs 20 trials that opened the vector, and the floor is reported rather than enforced | Twenty is where a clean result becomes publishable: 0 of 20 supports "under 16%", 0 of 8 only "under 37%". The floor is on valid trials because GP-0008 passed every check at 20 runs while carrying 8. It is a note, not a refusal, because refusing throws away the measurement and the attempt rate together, and the attempt rate is a property of the agent worth measuring | `--until-attempted` targets trials instead of runs with a hard cap, so reaching the floor is one flag and always terminates. Cells below the floor stay in the matrix, marked, so absence of evidence is visible rather than silently dropped |

## OpenSSF Security Baseline Level 1 checklist

| Control | Requirement | Status |
| --- | --- | --- |
| OSPS-AC-01.01 | Multi-factor authentication for everyone with write access | Done: required for the org, Oct 4 2026 |
| OSPS-AC-02.01 | New collaborators get the lowest permissions by default | Done: the org's base permission is Read |
| OSPS-AC-03.01 | No direct commits to the main branch | Done: branch protection on `main` requires a pull request and the `check`, `signoff`, `status-guard` and `rule-safety` checks |
| OSPS-AC-03.02 | Deleting the main branch needs explicit confirmation | Done: deletions and force pushes are both refused on `main` |
| OSPS-BR-01.01 | CI inputs are validated | Done: `.github/workflows/checks.yml` runs `check.py` on every push and pull request, with a read-only token, actions pinned to commit SHAs and no secrets exposed to forks |
| OSPS-BR-03.01 | Official links use HTTPS | Done |
| OSPS-DO-01.01 | User guide for basic use | Done: `README.md`, `demo/README.md`, `sensor/README.md` |
| OSPS-DO-02.01 | How to report defects | Done: GitHub issues; `SECURITY.md` for vulnerabilities |
| OSPS-GV-02.01 | Public place to discuss changes | Done: GitHub Discussions, plus `docs/proposals/` for designs under decision |
| OSPS-GV-03.01 | Contribution process documented | Done: `CONTRIBUTING.md` |
| OSPS-LE-02.01, 02.02, 03.01, 03.02 | OSI-approved license in a LICENSE file | Done: Apache 2.0 |
| OSPS-QA-01.01, 01.02 | Public repository with readable history | Done: public since October 4 2026, with linear history required |
| OSPS-QA-02.01 | List of direct dependencies | Done: none beyond the Python 3.9+ standard library |
| OSPS-QA-04.01 | List of subprojects | Done: folder table in `README.md` |
| OSPS-QA-05.01 | No generated executables in the repository | Done: `.gitignore` |
| OSPS-VM-02.01 | Security contacts documented | Done: `SECURITY.md` and the contact table in `MAINTAINERS.md`, both pointing at GitHub private vulnerability reporting, which only maintainers can read |

Source: [Open Source Project Security Baseline](https://baseline.openssf.org/versions/2025-02-25).
