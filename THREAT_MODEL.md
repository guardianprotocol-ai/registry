# Threat model

What could go wrong with Guardian Protocol itself, and what stops it. The protocol is a defense, so it is also a target: an attacker who can change what sensors detect, or stop them from detecting, wins against everyone who runs it.

This document covers the project and its supply chain. `SECURITY.md` covers how to report a problem.

## What we protect

1. **Integrity of the rules.** Sensors must enforce exactly the rules the project approved, and nothing else.
2. **Availability of protection.** A sensor must keep protecting even if every server the project runs is down.
3. **Integrity of releases.** Code and rule bundles users install must be the ones the project built.
4. **Privacy of members.** Anything shared through the network reveals nothing a member didn't approve.

## Where it runs

Sensors, hooks and the scanner run on the user's own machines with a local copy of the rules. They never need a live connection to work. GitHub holds the source and is where review happens. Packages and rule bundles are pulled down as updates, never fetched live per request. There is no central server whose loss turns protection off.

## Threats and defenses

| Threat | Defense | Status |
| --- | --- | --- |
| A change quietly weakens or disables a detection | Rule gate: every attack case in `corpus/attacks/` must still be caught, and the base and changed engines are compared on every pull request | Running |
| A rule that blocks ordinary work (denial of service by false alarm) | Rule gate: ordinary work in `corpus/benign/` must raise nothing; rule lint rejects signatures that match plain prose | Running |
| A rule that can be made to run for minutes on crafted input, stalling the sensor | Rule lint: nested repetition and slow signatures fail; speed tests in `sensor/tests/` | Running |
| Hidden characters in a rule that reviewers can't see | Rule lint: `signatures.json` must be plain ASCII, with invisible characters written as escapes | Running |
| A rule change with no proof | Pull requests that change the rules must add a test or corpus case | Running |
| Rules that can execute code | Signatures are data compiled by a fixed engine. Per-pattern conditions move to data in proposal 0001 | Partly done |
| A malicious pull request steals secrets or pushes code | Pull requests from forks run with read-only access and no secrets; workflows are pinned to commits; only maintainers merge | Running |
| Prompt injection against reviewers' AI tools | Pattern files contain injection text by design. Review AI tools run read-only and never hold write access | Practice |
| A stolen maintainer account | Two-factor authentication required in the organization; no single maintainer can enforce a rule globally | Two-factor: to turn on |
| One maintainer, or one company, forces a rule on everyone | `enforced` needs two maintainers from different organizations (GOVERNANCE.md) | Policy; tooling warns |
| A tampered release or rule update | Signed releases (Sigstore) and signed rule bundles (TUF), with protection against rollback and stale updates | Planned for v0.2 |
| A bad rule reaches every sensor at once | Monitor before block, staged rollout, automatic rollback; local override on every sensor | Planned for v0.2 |
| GitHub or the update server goes down | Sensors keep the last good rules; updates come from many mirrors | Local copy: yes. Mirrors: planned |
| Attackers read the open registry to evade it | Detections watch behavior, not exact strings; sensitive new signatures can be embargoed for members briefly | Behavior rules: yes. Embargo: planned |
| Fake sightings poison the network | Signatures shared only after several independent organizations see them; reporter reputation; rate limits | Planned for the network |
| Crashing the sensor to get past it | Fail open by default so agents keep working; fail closed is a configuration choice for high-security users | Configurable |

## Out of scope

Attacks on the model itself during training, and compromise of the user's own machine below the sensor, are outside what the sensor can see. The coverage map in `coverage/` says which MITRE ATLAS techniques fall where.

## Keeping this current

Every change that adds a component, a data flow or a new kind of rule updates this file. Rule safety policy is in [docs/RULE_SAFETY.md](docs/RULE_SAFETY.md).
