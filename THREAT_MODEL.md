# Threat model

What could go wrong with Guardian Protocol itself, and what stops it. The protocol is a defense, so it is also a target: an attacker who can change what sensors detect, or stop them from detecting, wins against everyone who runs it.

This document covers the project and its supply chain. `SECURITY.md` covers how to report a problem.

## An agent that wants its own sensor gone

The sensor is a proxy, not a tool. That distinction is the whole security argument and it
is worth stating plainly, because the obvious alternative looks friendlier and is not a
control at all.

A tool is something an agent chooses to call. An agent that would rather not be observed
simply does not call it, and nothing happens. Offering detection as a tool, or as a
plugin the model can reach, is asking an adversary to report itself.

A proxy is the transport. Every MCP message passes through it because there is no other
path, so an agent does not get a say in whether it is inspected. That is complete
mediation, and it is the only property that survives an agent that is actively unhelpful.

### What an agent at the same privilege can still do

Everything, and this should be said rather than implied. A sensor runs as a process the
client launched, configured in a file the user owns, writing state in that user's home.
An agent with shell access on that machine can:

- edit the client's configuration and remove the sensor from the path
- end the sensor's process
- delete the pins, the registered canaries, the evidence

No arrangement at equal privilege prevents this. The industry has the same problem with
endpoint monitoring on a machine where the attacker has root, and the honest answer there
is the honest answer here: tamper proofing is not available, tamper evidence is.

### Why silence is the control

A member sends a sign of life once a day whether or not it has anything to report, and a
receiver records when each was last heard from. A sensor that has been removed, killed or
quietly reconfigured stops sending. It cannot both be disabled and keep reporting.

So absence is visible from outside the machine, and visible to a network rather than only
to the machine's owner. `receiver/participation.py` separates a member with nothing to
report from a member nobody has heard from, and says in the output that silence is worth
asking about and is not proof of anything on its own, because it is also what a laptop
being closed looks like.

### What would make this stronger

Running the sensor as a different user from the agent, so its configuration and state are
not writable by the thing it watches. That is a real improvement and it is not done. It
costs an installation step on every machine, which at scale is the thing that decides
whether anybody runs it at all, so it belongs behind a flag for the people who want it
rather than in the default path.

### Where a harness implementing this itself helps, and where it does not

A vendor putting the protocol in their own transport layer is good: it is one fewer thing
to install, and the detection stays in the data path where the model cannot route around
it. A vendor exposing it as a tool the model can call is not the same thing and is not
worth having, however much easier it is to adopt.

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

## Rule updates in v0

`python3 -m guardian_sensor update` fetches the published rule set and checks every file
against a SHA-256 manifest published with it, refusing the whole update if anything does
not match.

**That is integrity, not authenticity.** It defends against a corrupted or truncated
download, a cache serving stale files, and a file swapped after the manifest was made. It
does not defend against anyone who can publish a release in this repository, because they
could publish a matching manifest alongside it. The protections that close that gap are
signed releases with Sigstore and signed rule updates with TUF, both on the roadmap for
v0.2.

Until then: the release is only as trustworthy as the repository's own access controls,
which is why `main` is protected, two-factor authentication is required, and every release
is built from a commit anyone can read.

## Out of scope

Attacks on the model itself during training, and compromise of the user's own machine below the sensor, are outside what the sensor can see. The coverage map in `coverage/` says which MITRE ATLAS techniques fall where.

## Keeping this current

Every change that adds a component, a data flow or a new kind of rule updates this file. Rule safety policy is in [docs/RULE_SAFETY.md](docs/RULE_SAFETY.md).
