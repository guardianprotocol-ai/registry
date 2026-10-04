# Guardian Protocol Registry

An open registry of known attacks on AI agents. Every pattern has a stable ID, links to OWASP and MITRE ATLAS, a runnable test with a harmless payload, and a detection rule.

- The **test** powers scans: run every pattern against your agent and see which attacks get through.
- The **detection** powers sensors: block the attack in real time.
- **Sightings** from the network show which attacks are active right now.

**Want to contribute?** [START_HERE.md](START_HERE.md) gets you set up in about 15 minutes and points you to a first task.

New to the design? Read [ARCHITECTURE.md](ARCHITECTURE.md): the three domains of defense (actions, words, thoughts), how the registry, scan, sensor and network fit together, and the roadmap.

## What's in this repository

| Folder | What it is |
| --- | --- |
| `patterns/` | One YAML file per attack pattern |
| `schema.yaml` | The pattern format |
| `coverage/` | Every MITRE ATLAS technique, triaged by where the protocol can act on it |
| `scanner/` | Validates the registry and measures an attack success rate against an agent |
| `sensor/` | Prototype MCP proxy that enforces detections in real time |
| `hooks/` | Client hooks that cover an agent's own tools, which never pass through MCP |
| `demo/` | A 90-second end-to-end demo with a visual report |

No dependencies beyond the Python 3.9+ standard library.

Coming next: reference agents beyond Claude Code, so an attack success rate can be compared across models, and scenarios for the patterns the scan cannot yet run.

## Pattern lifecycle

| Status | Meaning | Can block traffic? |
| --- | --- | --- |
| `draft` | Proposed; format valid | No |
| `verified` | Test and detection proven by automatic checks; two reviewers approved | No |
| `enforced` | Approved for sensors to act on | Yes |

## How contributions are checked

Run every check with one command:

```bash
python3 check.py
```

Every pull request runs the same script automatically. Today it checks:

1. **Format:** every pattern validates against `schema.yaml`, and its ID matches its filename.
2. **Payload safety:** canary tokens are well formed, and every destination is inside reserved, unroutable space: `.test`, `.example`, `.invalid` and `.localhost` (RFC 2606 and RFC 6761), the `example.com` family, the RFC 5737 documentation addresses, or loopback. Anything else is refused, including bare public IP addresses.
3. **Detections prove themselves:** the sensor's rule tests run an attack that must be caught and ordinary work that must not be, for every rule.
4. **Tools work:** the scanner, sensor and hook test suites pass.

Coming before patterns can move past `draft`: each test run against the vulnerable reference agent (must be exploited) and the hardened one (must resist), false-alarm rates measured on a benign traffic corpus, and a duplicate check.

Then maintainers review. Patterns need two approvals: at least one from an organization other than the contributor's, and never all from the same company. During the private preview, while there are fewer than three maintainers, a reviewer from another organization listed in `.github/CODEOWNERS` can give the second approval.

Every commit is signed off under the Developer Certificate of Origin (`git commit -s`).

## Contributing a pattern

1. Copy `docs/pattern-template.yaml` to `patterns/` and give it the next free ID. `patterns/GP-0001.yaml` is a complete example.
2. Fill in every field, including the test and the detection.
3. Run `python3 check.py`, then open a pull request. Credit goes in the `credits` field, with your name and organization.

## Reporting an incident

Don't open a public issue for an active attack or anything specific to one vendor's product. Use the private reporting process in `SECURITY.md`. We follow coordinated disclosure: affected parties hear first, and the public advisory comes after a fix or on a set timeline.

## The project

- [START_HERE.md](START_HERE.md): your first contribution
- [TRACKS.md](TRACKS.md): the areas of work and who leads each
- [CONTRIBUTING.md](CONTRIBUTING.md): how to contribute
- [CONTRIBUTORS.md](CONTRIBUTORS.md): everyone who has contributed
- [GOVERNANCE.md](GOVERNANCE.md): roles, decisions and neutrality
- [ROADMAP.md](ROADMAP.md): the next twelve months
- [docs/DECISIONS.md](docs/DECISIONS.md): design decisions and the security baseline checklist
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [MAINTAINERS.md](MAINTAINERS.md)

## License

Apache 2.0.
