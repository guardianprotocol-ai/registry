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

## OpenSSF Security Baseline Level 1 checklist

| Control | Requirement | Status |
| --- | --- | --- |
| OSPS-AC-01.01 | Multi-factor authentication for everyone with write access | To do: require 2FA in the org settings |
| OSPS-AC-02.01 | New collaborators get the lowest permissions by default | To do: set base permission to Read in the org settings |
| OSPS-AC-03.01 | No direct commits to the main branch | To do: add a branch rule on `main` after the first push |
| OSPS-AC-03.02 | Deleting the main branch needs explicit confirmation | To do: same branch rule |
| OSPS-BR-01.01 | CI inputs are validated | When CI is added |
| OSPS-BR-03.01 | Official links use HTTPS | Done |
| OSPS-DO-01.01 | User guide for basic use | Done: `README.md`, `demo/README.md`, `sensor/README.md` |
| OSPS-DO-02.01 | How to report defects | Done: GitHub issues; `SECURITY.md` for vulnerabilities |
| OSPS-GV-02.01 | Public place to discuss changes | To do: turn on GitHub Discussions |
| OSPS-GV-03.01 | Contribution process documented | Done: `CONTRIBUTING.md` |
| OSPS-LE-02.01, 02.02, 03.01, 03.02 | OSI-approved license in a LICENSE file | Done: Apache 2.0 |
| OSPS-QA-01.01, 01.02 | Public repository with readable history | At public launch |
| OSPS-QA-02.01 | List of direct dependencies | Done: none beyond the Python 3.9+ standard library |
| OSPS-QA-04.01 | List of subprojects | Done: folder table in `README.md` |
| OSPS-QA-05.01 | No generated executables in the repository | Done: `.gitignore` |
| OSPS-VM-02.01 | Security contacts documented | Done: `SECURITY.md`; add a security email once the project domain is set |

Source: [Open Source Project Security Baseline](https://baseline.openssf.org/versions/2025-02-25).
