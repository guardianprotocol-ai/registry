# Tracks

The work is organized into tracks. Each track has a lead who reviews pull requests in that area and keeps its issues moving. Pick the one closest to what you know, or move between them.

**Next milestone: Protocol v0.1**, the first public release. Target: November 20, 2026.

| Track | Folder | What it covers | Lead |
| --- | --- | --- | --- |
| Patterns | `patterns/`, `schema.yaml` | New attack patterns and better existing ones | [chosen by the working group] |
| Scanner and reference agents | `scanner/` | Runnable scenarios, reference agents, attack success rates | [chosen by the working group] |
| Sensor and hooks | `sensor/`, `hooks/` | Real-time detection, client hooks, rule quality | [chosen by the working group] |
| Coverage and evidence | `coverage/` | MITRE ATLAS and OWASP mapping, real incidents behind each pattern | [chosen by the working group] |
| Deception and model behavior | `docs/research/` | Research on agents that mislead or hide what they did | [chosen by the working group] |

## Patterns

Every pattern is a known attack on AI agents with a stable ID, a harmless test and a detection. The goal for v0.1 is a broad set of draft patterns drawn from OWASP, MITRE ATLAS, AgentDojo, published MCP security research, lab write-ups and disclosed incidents.

Good first tasks: propose a pattern from a published source; tighten the mitigations or references on an existing one.

## Scanner and reference agents

Nine of the twelve patterns validate but can't run yet, because the scan has no scenario for them. Each missing scenario is its own issue. Beyond that: reference agents on open-weight models, so attack success rates can be compared across models, and a benign traffic corpus so every detection's false-alarm rate can be measured.

Good first tasks: write a scenario for one pattern.

## Sensor and hooks

The sensor sits between an agent and its tools and enforces detections in real time. Hooks cover an agent's built-in tools, which never pass through MCP. Work here: rules for new patterns, hooks for more agent clients, and fewer false alarms.

Good first tasks: add attack and benign test cases for an existing rule.

## Coverage and evidence

`coverage/atlas-coverage.csv` triages every MITRE ATLAS technique by where the protocol can act on it. Every row is a draft and needs a second opinion. Real incidents mapped to patterns show which attacks matter in practice.

Good first tasks: review a block of coverage rows and correct the triage.

## Deception and model behavior

The registry starts with attacks on what agents do. This track looks at what agents say and think: agents that mislead their users under pressure, hide what they did, or say one thing and do another. Output here starts as research notes and scenario designs in `docs/research/`, published openly, and becomes patterns once a harmless test and a detection exist.

Good first tasks: write up a deception-under-pressure scenario design as a proposal.
