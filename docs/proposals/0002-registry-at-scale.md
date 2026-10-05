# 0002: Running the registry at scale

**Status:** draft, for the working group to decide
**Author:** Frank Albanese

## The goal

Thousands of contributors, many engines, millions of sensors, and rules that are always current, because protection that lags an attack protects nobody. The structure has to make the safe path the easy path, and it is cheapest to set now, while there are twelve patterns.

This draws on projects that already run open detection content at scale: Snort and Suricata rule sets, ClamAV signatures, YARA rule repositories, the Sigma rule repository, Semgrep and Nuclei community rules, and the OSV vulnerability database.

## 1. Separate content from code

**Content** (patterns, detections, test cases) changes daily. **Code** (engines, scanner, tooling) changes monthly. They get separate review owners, separate release cadences and separate version numbers, as rule sets and engines do everywhere above. Content declares which engine versions it needs (proposal 0001); engines skip content they can't evaluate.

## 2. One directory per pattern

Everything about a pattern lives together, so a contribution touches one place and two contributors rarely touch the same file:

```
patterns/GP-0007/
  pattern.yaml        # what the attack is, mappings, lifecycle (today's GP-0007.yaml)
  detection.yaml      # the rule (proposal 0001)
  tests/
    attack-ssh-key.json      # corpus cases, same format as corpus/ today
    benign-own-deploy.json
  signatures.json     # signatures only this pattern uses (shared ones stay central)
```

`CODEOWNERS` can then assign families of patterns to the people who know them. A shared benign corpus stays central, because ordinary work must be checked against every rule, not just one.

## 3. The repository is source; releases are built bundles

Sensors never read the repository. On every merge, CI compiles all accepted content into one **rule bundle**: a single file with a version, a manifest of every rule and its hash, and each rule's mode. Bundles are:

- **Signed** with TUF, the update framework PyPI and others use, with keys split among maintainers at different organizations, so no one person can ship a bundle and a stolen key isn't enough.
- **Mirrored** widely, since any mirror works when bundles are signed.
- **Released in channels:** `monitor` (new rules, log only), `stable` (rules that have earned blocking), and an `emergency` lane for attacks happening now, with expiry dates.
- **Rolled out in stages** with automatic rollback when false alarm reports spike.

A sensor that can't reach any mirror keeps its last good bundle and keeps protecting.

## 4. The corpus is the conformance suite

The same engine-neutral cases (`corpus/` today, `patterns/*/tests/` later) run against every implementation: the Python reference engine, a Go or Rust sensor, every client hook. Two engines that disagree on a case is a bug in one of them. This is how web browsers stay compatible (the shared web-platform-tests), and it's what lets the protocol have many implementations without fragmenting.

## 5. Checks that scale

- **Affected-only on pull requests, everything nightly.** A change to GP-0007 runs GP-0007's cases plus the full benign corpus; the nightly run covers everything.
- **Budgets per rule:** time, memory and false alarms. A rule that blows its budget can't merge, and a merged rule that later blows it drops to monitor mode.
- **A real benign corpus.** Ordinary agent traffic contributed by members, anonymized locally before it leaves, so false-alarm rates reflect real work rather than examples we wrote.

## 6. Stable identity and lifecycle

- IDs are never reused (already the rule). Patterns are **deprecated, not deleted**, with `superseded_by` when one replaces another.
- Every rule carries `version`, `last_verified` and the engine range it supports.
- A rule whose tests start failing drops to monitor mode automatically until someone fixes it.

## 7. Feedback from the field

Sensors can report, with the member's consent and no content, how often each rule ID and version fired and whether users marked it a false alarm. That is the signal for staged rollout, automatic rollback and demotion. It is also the start of the network in ARCHITECTURE.md.

## 8. People and process at scale

- Owners per pattern family in `CODEOWNERS`, and a rotating triage duty so new issues and pull requests get an answer within days.
- Templates and a scaffolding command (`check.py new-pattern`, later) so a first contribution takes minutes.
- The two-organization rule for anything that blocks traffic, and maintainers drawn from several organizations, as `GOVERNANCE.md` already requires.

## What exists today

| Piece | Status |
| --- | --- |
| Signatures as data, plain ASCII | Done |
| Rule lint, rule gate, engine-neutral corpus | Done |
| Before-and-after comparison on pull requests | Done |
| Declarative per-pattern rules | Proposal 0001 |
| One directory per pattern | This proposal |
| Signed bundles, channels, mirrors | Roadmap v0.2 |
| Field feedback | Roadmap v0.3, with the network |

## Recommended order

1. **Before v0.1 (Oct 29):** accept 0001 and the directory layout, and migrate while there are few patterns. Each month of waiting makes the move larger.
2. **v0.2:** bundles, signing, channels, staged rollout.
3. **v0.3:** field feedback and the shared benign corpus, with the network.

## Undecided

- Whether the benign corpus can accept real traffic before the anonymizer exists.
- How many signing keys, held by whom, and the threshold to release.
- The cadence of stable releases.
