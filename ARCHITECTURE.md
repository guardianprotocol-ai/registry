# Guardian Protocol architecture

MITRE ATLAS names the attacks on AI systems. Guardian Protocol is the open, executable layer for AI agents: runnable tests, working detections and measured results, each mapped to ATLAS. Built in the open by YC founders, headed for a neutral home. An attack caught at one organization becomes protection for every organization. This document is the starting point for the design; contributors are invited to challenge and improve every part of it.

## The idea in one paragraph

Every known attack on AI agents gets an entry in an open **registry**: a stable ID mapped to OWASP and MITRE ATLAS, a **test** that proves the attack works, and a **detection** that stops it. The **scan** runs the tests against an agent before it ships. The **sensor** enforces the detections while it runs. The **network** shares anonymized signatures, so a catch anywhere protects everyone. Everything here is open source under Apache 2.0.

## Relationship to MITRE ATLAS

ATLAS is the shared vocabulary for attacks on AI systems, and this project depends on it.
The two do different jobs, and the registry is built so the boundary stays clean.

| MITRE ATLAS | Guardian Protocol |
| --- | --- |
| Names and classifies techniques | Makes them runnable, catchable and measured |
| A taxonomy, maintained by MITRE | Tests, detections and results, maintained in the open |
| Tells you the attack exists | Tells you whether it works against your agent, how often, and what stops it |

Every pattern maps to one or more ATLAS techniques. A pattern may map to none, but only if
it argues why in `maps_to.custom_reason`, naming the closest technique considered and what
it misses. Attacks on agents often appear before any taxonomy catalogs them, so the registry
should be able to lead; a custom mapping is a claim that has to be made out loud, and
`check.py` prints the count on every run so it never quietly becomes the norm.

Custom patterns with good evidence behind them are meant to go **back** to ATLAS as proposed
techniques. The registry leading ATLAS is the point. The registry permanently diverging from
it is not. `docs/MAINTAINING.md` makes that a monthly step.

This project is not a replacement for ATLAS, an improved ATLAS, or a competing taxonomy.

## Three domains of defense

Agents can be attacked, misused, or deceptive at three depths. The protocol covers them in order, from what can be enforced today to what research is still maturing.

| Domain | What it watches | Techniques | Status |
| --- | --- | --- | --- |
| **Actions** | What the agent does: tool calls, data leaving, changes to tools | MCP sensor, client hooks, egress control, canary tokens, sandboxing | Now |
| **Words** | What the agent says and reasons | Reasoning monitors, output checks, words vs actions, follow-up questioning | Next |
| **Thoughts** | What happens inside the model | Linear probes, sparse autoencoder features, activation shifts after reading outside content | Research, for self-hosted models |

Detection in the words and thoughts domains is probabilistic. Every detector publishes its false-alarm rate, and a flag starts an investigation, not a verdict.

## Components

### Registry

One YAML file per attack pattern (`patterns/`), validated against `schema.yaml`.

- **ID and mappings:** stable `GP-` IDs, linked to OWASP and MITRE ATLAS entries.
- **Test:** a harmless, repeatable attack. Payloads use canary tokens and reserved `.test` domains.
- **Detection:** a rule the sensor enforces. Signatures are data (`sensor/guardian_sensor/signatures.json`) compiled by a fixed engine; proposal 0001 moves the per-pattern conditions into data too, so rules can never execute code.
- **Lifecycle:** `draft` → `verified` (checks pass, two reviewers approve) → `enforced` (approved to block traffic).

`coverage/atlas-coverage.csv` triages every MITRE ATLAS technique by where the protocol can act on it. Of 208 techniques in release 2026.09, 63 happen at agent runtime; those are the registry's first targets.

### Scan

The scan plays the hostile outside world; the agent never grades itself. It builds a sandbox of fake tools, canary data and `.test` destinations, connects an agent in staging, runs every verified pattern, and reports what got through.

AI agents don't behave the same way twice, so every test runs repeatedly and reports an **attack success rate**. Results are statistics, not a single pass or fail.

Delivery: a test MCP server, a command-line tool, and a CI check.

### Sensor

A checkpoint between agents and the tools they use, enforcing enforced patterns in milliseconds. `sensor/` holds the v0 prototype: an MCP stdio proxy that pins tool definitions, tracks when tool output carries instructions, and blocks sends to unapproved destinations and outbound secrets.

Design rules:

- **Simple at the edge, smart in the network.** Small, auditable code; declarative rules.
- **Works offline** with the last known rules.
- **Fails open** on its own faults, so a sensor bug never takes an agent down; customers choose where to fail closed.
- **Monitor before block:** new rules watch before they can block.

### Coverage beyond MCP

Agents also use built-in tools (shell, file editing, web fetch) that never pass through MCP. These layers close the gap:

| Layer | Where it sits | What it sees |
| --- | --- | --- |
| Client hooks | Inside the agent client (for example Claude Code's hooks that run before and after each tool call) | Every built-in tool call in that client |
| Model gateway | Between the agent and the model provider | Every tool call the model requests and every result sent back |
| Network egress control | All outbound traffic from the agent's machine or container | Data leaving by any route |
| Sandboxing | Containers with restricted files and network | Limits what any tool can reach |
| Canary tokens | Fake secrets planted in files, repos and environments | Any leak, through any tool |
| Host monitoring | Process and network monitoring for agent processes | Unexpected programs, secret reads, new connections |

### Network

1. An agent reports through its own organization's sensor, never directly to the network. Agent reports are hints; only evidence the sensor observed counts.
2. With sharing turned on, the sensor sends an anonymized sighting: a fixed set of fields, no free text, previewed by the member before anything leaves.
3. The network correlates across organizations and shares a signature only once several independent organizations have seen it.
4. Findings go to whoever can fix them, under coordinated disclosure: model weaknesses to the model's maker, tampered tools to the tool's maintainer, then a public advisory with a registry ID.
5. Verified protections ship to every sensor as signed updates, rolled out gradually with automatic rollback.

#### The hub v0: built

Steps 2 and 5 exist in their smallest honest form, enough to run the trial.

- `python3 -m guardian_sensor report --since <date> --preview` shows exactly what would be shared; add `--out` to write it. A sighting carries only `org`, `sensor_version`, `rules_version`, `pattern`, `action`, `hour` and `count`.
- `python3 -m guardian_sensor update --base <release url>` fetches the published rule set, checks every file against a SHA-256 manifest, refuses the whole update on any mismatch, and records the version in `.guardian/updates.jsonl`.
- `scripts/build_release_manifest.py` makes the manifest. `scripts/aggregate_sightings.py` merges members' files and withholds any total that fewer than three organizations contributed to.

**Privacy is by construction, not by redaction.** The output is built from an allow-list of fields, and the values are checked against a fixed shape before use: a pattern id must look like `GP-0000`, an action must be `flagged` or `blocked`, a timestamp is reduced to the hour. The parts of an evidence record that hold content, `detail` and `reasons`, are never read. A redactor is a filter someone can get past; an allow-list leaves nothing for content to be written into.

**What v0 does not do.** No STIX or TAXII. No signing: integrity rests on the GitHub release plus the hash manifest, which catches a corrupted download or a file swapped after the manifest was made, but not someone who can publish the release itself. No correlation service: step 3 is a script run over files members commit. No gradual rollout or automatic rollback.

Planned building blocks: STIX 2.1 for the alert format, TAXII 2.1 for sharing, TUF for signed updates, Sigstore for signed releases, and a public append-only log. The network is operated by a neutral body; no company, including its founders' companies, gets privileged access to its data.

## Safety principles

- **No single point of failure.** Protection works offline; updates come from many mirrors.
- **No single party can change the rules for everyone.** Globally enforced rules need approval from several maintainers at different organizations.
- **Every change is visible** in a public log.
- **Harmless by design.** Tests use canaries and `.test` destinations; evasion techniques are disclosed privately, not published.
- **Humans hold the keys** to anything global.

## Roadmap

| Stage | What ships |
| --- | --- |
| v0.1 | Registry with verified patterns, scanner, reference sensor, alert format |
| v0.2 | Client hooks, canaries in the scan, signed updates, monitor-before-block |
| v0.3 | Network preview: anonymized sharing, hub, embargo for members who share |
| Later | Words-domain detectors, then thoughts-domain probes for self-hosted models |

## The open project and companies

Guardian Protocol is neutral and open, headed for a home at the Linux Foundation. Anyone may build products and services on it. Companies that do, including the founders' own, get no special access to the network or its data, and every company building on the protocol is listed equally.

## Contribute

Start with the coverage map: review a row, or write the pattern for it (a test plus a detection). See `README.md` for how contributions are checked.
