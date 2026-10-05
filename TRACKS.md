# Tracks

Open tests, detections and measurements for attacks on AI agents, mapped to MITRE ATLAS. The work is organized into tracks. Everyone is a contributor: pick the track closest to what you know, move between them, and contribute as much as you like.

Reviewers are invited from among the most active contributors in each area, as described in `GOVERNANCE.md`. Reviewing is a responsibility, not a rank: it's how the project keeps every change checked by someone other than its author.

**Next milestone: Protocol v0.1**, the first public release, together with the group's first paper as preprint v1. Target: October 29, 2026. See [PROGRAM.md](PROGRAM.md).

| Track | Folder | What it covers |
| --- | --- | --- |
| Patterns | `patterns/`, `schema.yaml` | New attack patterns and better existing ones |
| Scanner and reference agents | `scanner/` | Runnable scenarios, reference agents, and measuring models and harnesses |
| Sensor and hooks | `sensor/`, `hooks/` | Real-time detection, client hooks, rule quality |
| Coverage and evidence | `coverage/` | MITRE ATLAS and OWASP mapping, real incidents behind each pattern |
| Deception and model behavior | `docs/research/` | Research on agents that mislead or hide what they did |
| Trial | `sensor/`, `scripts/` | Running the sharing hub: take part, operate it, analyze what comes back |
| Multi-agent | `patterns/`, the scanner lab, `docs/proposals/0003` | Attacks that need more than one agent, and seeing the traffic between them |

## Patterns

Every pattern is a known attack on AI agents with a stable ID, a harmless test and a detection. The goal for v0.1 is a broad set of draft patterns drawn from OWASP, MITRE ATLAS, AgentDojo, published MCP security research, lab write-ups and disclosed incidents.

Good first tasks: propose a pattern from a published source; tighten the mitigations or references on an existing one.

## Scanner and reference agents

**Measuring models and harnesses is the headline task on this track.** The same attack lands differently depending on the model, the agent software around it and the versions of both, and almost nobody has published those numbers. Running a pattern against a target and recording the result is the most useful thing a new contributor can do here. See `results/README.md` and the generated matrix in `docs/MATRIX.md`.

Nine of the twelve patterns validate but can't run yet, because the scan has no scenario for them. Each missing scenario is its own issue. Beyond that: reference agents on open-weight models, so attack success rates can be compared across models, and a benign traffic corpus so every detection's false-alarm rate can be measured.

Good first tasks: measure one target with `--record` and open a pull request with the result files; write a scenario for one pattern.

## Sensor and hooks

The sensor sits between an agent and its tools and enforces detections in real time. Hooks cover an agent's built-in tools, which never pass through MCP. Work here: rules for new patterns, hooks for more agent clients, and fewer false alarms.

Good first tasks: add attack and benign test cases for an existing rule.

## Trial

The distributed trial is the group's first experiment: real sensors on members' own
development agents, a real exchange of anonymized sightings, and a measured time to
protection across organizations. Three ways to help, in increasing order of commitment.

**Operate it.** The hub is built and small: `python3 -m guardian_sensor report --preview`,
`python3 -m guardian_sensor update`, `scripts/aggregate_sightings.py`. It needs more tests,
better failure messages, and a second pair of eyes on the privacy argument.

**Attack it.** The promise is that a sightings file contains no content. Try to break that.
`sensor/tests/test_hub.py` is where a successful attempt becomes a permanent test.

**Take part.** Your company runs the sensor in monitor mode on a development agent and
shares sightings. Opt-in, with your company's own written approval, and you can withdraw at
any time and have your data removed before publication. The protocol and the participation
guide live in the private research repository, because they involve named companies.

Good first tasks: review the allow-list in `sensor/guardian_sensor/hub.py` and try to find
a way through it.

## Multi-agent

Teams chain agents together: an orchestrator hands work to workers, peers message each other,
swarms vote. That creates attacks that cannot exist with one agent, and the registry has six
draft patterns for them, GP-0013 to GP-0018, with a `topology` field saying what setup each
one needs.

**Where it stands.** GP-0008 runs end to end against a scripted pair of agents in the lab:
100 percent unprotected, 0 percent with the sensor in front. The other six validate but do
not run, and most of their detections are written down as ideas rather than shipped as rules,
because the rule engine cannot yet express them and the corpus format cannot describe a
multi-agent session.

**The honest blocker** is in `docs/proposals/0003`: the sensor only sees agent-to-agent
traffic that happens to pass through MCP. Everything else is invisible to it.

Good first tasks: give one of GP-0013 to GP-0018 a scenario in the lab, the way GP-0008 has
one; or argue with proposal 0003, which needs disagreement more than it needs agreement.

## Coverage and evidence

`coverage/atlas-coverage.csv` triages every MITRE ATLAS technique by where the protocol can act on it. Every row is a draft and needs a second opinion. Real incidents mapped to patterns show which attacks matter in practice.

Good first tasks: review a block of coverage rows and correct the triage.

## Deception and model behavior

The registry starts with attacks on what agents do. This track looks at what agents say and think: agents that mislead their users under pressure, hide what they did, or say one thing and do another. Output here starts as research notes and scenario designs in `docs/research/`, published openly, and becomes patterns once a harmless test and a detection exist.

Good first tasks: write up a deception-under-pressure scenario design as a proposal.
