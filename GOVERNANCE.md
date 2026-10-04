# Governance

Guardian Protocol is a vendor-neutral open source project. It is being built to be contributed to a neutral foundation, with the Linux Foundation's Agentic AI Foundation as the intended long-term home and OpenSSF as a candidate first stop. This document describes how the project is run until then, and is written to carry over to a foundation without changes to how contributors work.

## Principles

- **Neutral.** No company, including companies founded by the project's founders, gets privileged access to the project, the registry or network data. Every company building on the protocol is listed equally.
- **Open.** Decisions, roadmap and discussion happen in public: GitHub issues, pull requests and discussions. Security matters are the only exception (see `SECURITY.md`).
- **Accountable.** Every change is reviewed by someone other than its author, and every commit is signed off under the DCO.
- **Safe by default.** Anything that can change what sensors block everywhere needs approval from several maintainers at different organizations.

## Roles

Three roles, plus the people who hold the keys.

| Role | GitHub permission | Can | How you get there |
| --- | --- | --- | --- |
| **Contributor** | None needed, the repository is public | Fork, open pull requests, comment, review without binding effect | Nothing to ask for. Open a pull request |
| **Reviewer** | Write, and listed in `.github/CODEOWNERS` for an area | Binding approval in their area | About five good merged pull requests, nominated by a maintainer, no objection within 7 days |
| **Maintainer** | Maintain, and listed in `MAINTAINERS.md` | Merge, cut releases, promote patterns. Promoting a pattern to `enforced` needs two maintainers from different organizations | Sustained good reviewing, same nomination process |

Why these three and not more: GitHub only counts an approval as binding when it comes from someone with Write access, and a code owner must have Write. So Reviewer equals Write is the natural line between an opinion and an approval. Triage work, labelling and closing stale issues, is done by reviewers until the volume needs a role of its own.

**Key holders** are not a role. Two or three people are owners of the GitHub organization and hold the keys for settings and emergencies, eventually from different organizations. Holding keys is not the same as deciding direction.

**Technical Steering Committee.** Formed at foundation entry, not now. It will set technical direction, resolve disputes and approve new maintainers.

### How `main` is protected

The repository is public and `main` is protected. A pull request is required, with one
approving review and six passing checks: `check` on Python 3.9, 3.12 and 3.13, plus
`signoff`, `status-guard` and `rule-safety`. History stays linear. Force pushes and branch
deletion are refused.

Two things are deliberately not on yet, and both switch on when a second maintainer joins:
requiring a review from a code owner, and applying branch protection to administrators.
With a single maintainer the required approval cannot come from anyone else, so the
founding maintainer merges using the administrator override, which GitHub records on every
pull request for anyone to read. That is the honest description of the current state, not
a gap we are hiding.

## Decisions

- **Everyday changes:** lazy consensus through pull request review.
- **Significant changes** (the pattern schema, the sensor's rule format, governance, the network's data rules): a public proposal as a GitHub issue labeled `proposal`, open for at least 7 days, then approval by a majority of maintainers.
- **Rules that block traffic globally** (`enforced` patterns): approval by at least two maintainers from different organizations.

## Diversity of maintainers

The project aims for maintainers from several organizations. Until the TSC is formed, no single organization should hold more than half of maintainer seats once there are at least four maintainers. `MAINTAINERS.md` lists each maintainer's affiliation.

## Project assets

The Guardian Protocol name, domains and GitHub organization are held for the project, not for any company, and will be transferred to the foundation on acceptance.

## Changes to this document

Changes to governance follow the significant-change process above.
