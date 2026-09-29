# Governance

Guardian Protocol is a vendor-neutral open source project. It is being built to be contributed to a neutral foundation, with the Linux Foundation's Agentic AI Foundation as the intended long-term home and OpenSSF as a candidate first stop. This document describes how the project is run until then, and is written to carry over to a foundation without changes to how contributors work.

## Principles

- **Neutral.** No company, including companies founded by the project's founders, gets privileged access to the project, the registry or network data. Every company building on the protocol is listed equally.
- **Open.** Decisions, roadmap and discussion happen in public: GitHub issues, pull requests and discussions. Security matters are the only exception (see `SECURITY.md`).
- **Accountable.** Every change is reviewed by someone other than its author, and every commit is signed off under the DCO.
- **Safe by default.** Anything that can change what sensors block everywhere needs approval from several maintainers at different organizations.

## Roles

| Role | Who | Can |
| --- | --- | --- |
| Contributor | Anyone who opens an issue or pull request | Propose changes |
| Reviewer | Contributors with a track record in an area, listed in `.github/CODEOWNERS` | Approve changes in their area |
| Maintainer | Listed in `MAINTAINERS.md` | Merge changes, cut releases, promote patterns to `enforced` |
| Technical Steering Committee (TSC) | Formed at foundation entry | Set technical direction, resolve disputes, approve new maintainers |

Reviewers and maintainers are nominated by an existing maintainer, based on sustained, high-quality contributions, and confirmed by lazy consensus of the maintainers (no objection within 7 days).

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
