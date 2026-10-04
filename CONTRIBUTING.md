# Contributing to Guardian Protocol

Thank you for helping defend AI agents. Every accepted pattern protects everyone who runs the protocol.

New here? [START_HERE.md](START_HERE.md) gets you set up in about 15 minutes, and [TRACKS.md](TRACKS.md) shows the areas of work.

## Ways to contribute

- **Review a coverage row.** Check how a MITRE ATLAS technique is triaged in `coverage/atlas-coverage.csv`.
- **Write a pattern.** A test plus a detection for an attack not yet in the registry. See `README.md` for the format and checks.
- **Improve the sensor or tooling.** Bug fixes, new transports, client hooks, tests.
- **Improve the docs.** Clearer is better.

Report live attacks and vulnerabilities privately, never in a public issue. See `SECURITY.md`.

## How a change gets in

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Fork the repository and create a branch from the latest `main`. Contributors work in their own forks; only maintainers merge into this repository.
3. Make your change. Keep each pull request to one idea. Run `python3 check.py` before you push. For a new attack pattern, start with `python3 check.py new-pattern "Title of the attack"`, which takes the next free ID and the boilerplate.
4. Sign off every commit under the Developer Certificate of Origin (below).
5. Open a pull request with the evidence that it works: `check.py` output, a scanner run, or the corpus cases you added. Automatic checks run, then reviewers from `.github/CODEOWNERS` review it.
6. A maintainer merges once checks pass and reviews are complete. Nobody merges their own change.

## What the checks enforce

Everything here is checked by a machine before a person reviews it, so a careless change
fails fast rather than in review.

| Rule | What it means for you |
| --- | --- |
| Every commit is signed off | `git commit -s`. A sign-off naming someone other than the author is refused |
| `check.py` passes | Format, tests, rule lint and the rule gate, on Python 3.9, 3.12 and 3.13 |
| Rule changes come with evidence | A change to `rules.py` or `signatures.json` needs a test in `sensor/tests/` or a case in `corpus/` |
| Patterns map to MITRE ATLAS | At least one real technique ID from `coverage/atlas-coverage.csv`, or an argued `maps_to.custom_reason` saying which technique came closest and what it misses |
| Patterns credit someone | `credits` needs at least one entry with a `name`. `organization` is optional and leaving it out means an individual |
| New patterns are `draft` | Only a maintainer changes a pattern's status, in a separate pull request |

Roles are in [GOVERNANCE.md](GOVERNANCE.md). Maintainers have a runbook in
[docs/MAINTAINING.md](docs/MAINTAINING.md).

Registry patterns need two approvals: at least one from an organization other than the contributor's, and never all from the same company. During the private preview there is one maintainer, so that rule cannot be met yet: changes are reviewed by the founding maintainer alone, and the two-approval rule starts the moment a second maintainer joins.

## Developer Certificate of Origin

We use the [Developer Certificate of Origin](https://developercertificate.org/) (DCO), the same sign-off the Linux kernel uses, instead of a contributor license agreement. Add it with:

```bash
git commit -s -m "Add pattern GP-0013"
```

This appends `Signed-off-by: Your Name <you@example.com>`, which certifies you have the right to submit the work under the project's license.

## Tools

Contributors may use any tools, including AI assistants. Every contribution is reviewed and signed off by a person who is accountable for it. Make sure your tools' terms allow you to contribute the output under Apache 2.0, in line with the [Linux Foundation's generative AI policy](https://www.linuxfoundation.org/legal/generative-ai).

## Safety rules for patterns

- Tests use canary tokens and reserved `.test` domains only. No real malware, credentials or personal data.
- Describe attacks at the level a defender needs to reproduce them safely. Evasion techniques that would help attackers more than defenders go through `SECURITY.md`, not a pull request.

## Credit

Add yourself to `CONTRIBUTORS.md` in your first pull request, and to the `credits` field of any pattern you write or substantially improve. Release notes name everyone who contributed to each release.

## Conduct

Everyone taking part follows our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree your contributions are licensed under Apache 2.0.
