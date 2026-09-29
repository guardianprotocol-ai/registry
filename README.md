# Guardian Protocol Registry

An open registry of known attacks on AI agents. Every pattern has a stable ID, links to OWASP and MITRE ATLAS, a runnable test with a harmless payload, and a detection rule.

- The **test** powers scans: run every pattern against your agent and see which attacks get through.
- The **detection** powers sensors: block the attack in real time.
- **Sightings** from the network show which attacks are active right now.

New here? Start with [ARCHITECTURE.md](ARCHITECTURE.md): the three domains of defense (actions, words, thoughts), how the registry, scan, sensor and network fit together, and the roadmap.

## What's in this repository

| Folder | What it is |
| --- | --- |
| `patterns/` | One YAML file per attack pattern |
| `schema.yaml` | The pattern format |
| `coverage/` | Every MITRE ATLAS technique, triaged by where the protocol can act on it |
| `sensor/` | Prototype MCP proxy that enforces detections in real time |
| `demo/` | A 90-second end-to-end demo with a visual report |

No dependencies beyond the Python 3.9+ standard library.

Coming next: a scanner that runs each pattern's test many times and reports an attack success rate, and hooks that cover an agent client's built-in tools (Claude Code first).

## Pattern lifecycle

| Status | Meaning | Can block traffic? |
| --- | --- | --- |
| `draft` | Proposed; format valid | No |
| `verified` | Test and detection proven by automatic checks; two reviewers approved | No |
| `enforced` | Approved for sensors to act on | Yes |

## How contributions are checked

Every pull request runs these checks automatically:

1. **Format:** the entry validates against `schema.yaml`.
2. **Test proves itself:** the test succeeds against the vulnerable reference agent and fails against the hardened reference agent.
3. **Detection proves itself:** the rule fires on the test's attack traffic and stays quiet on the benign traffic corpus. The false-alarm rate is recorded in the entry.
4. **Payload safety:** payloads are harmless. Destinations use reserved test domains such as `.test` (RFC 2606). No real malware and no real data.
5. **Duplicates:** checked against existing patterns.

Then two maintainers review. At least one must be from an organization other than the contributor's, and at least one from outside White Hat Labs.

Every commit is signed off under the Developer Certificate of Origin (`git commit -s`).

## Contributing a pattern

1. Copy `patterns/GP-0001.yaml` and give it the next free ID.
2. Fill in every field, including the test and the detection.
3. Open a pull request. Credit goes in the `credits` field, with your name and organization.

## Reporting an incident

Don't open a public issue for an active attack or anything specific to one vendor's product. Use the private reporting process in `SECURITY.md`. We follow coordinated disclosure: affected parties hear first, and the public advisory comes after a fix or on a set timeline.

## The project

- [CONTRIBUTING.md](CONTRIBUTING.md): how to contribute
- [GOVERNANCE.md](GOVERNANCE.md): roles, decisions and neutrality
- [ROADMAP.md](ROADMAP.md): the next twelve months
- [docs/DECISIONS.md](docs/DECISIONS.md): design decisions and the security baseline checklist
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [MAINTAINERS.md](MAINTAINERS.md)

## License

Apache 2.0.
