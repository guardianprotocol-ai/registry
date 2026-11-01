# Season 1 status

Generated from the repository by `python3 scripts/build_status.py`. Do not edit by hand:
`python3 check.py` fails if this file and the repository disagree.

Season 1 runs **October 5 to October 29, 2026**. What this page tracks is the Map phase and
what follows from it: the 63 MITRE ATLAS techniques that happen while an agent is
running. See [../PROGRAM.md](../PROGRAM.md) for the phases and how to pick something up.

A technique is **resolved** when a pattern covers it, or when it is marked not testable at
runtime with a reason. Everything else is open work, and every one of them has an issue.

## Where Season 1 is

| Phase | Measure | Count |
| --- | --- | --- |
| Map | Resolved, out of 63 | **56** |
| Map | Covered by a pattern | 56 |
| Map | Marked not testable at runtime | 0 |
| Map | Still open | 7 |
| Prove | With a runnable test | 11 |
| Prove | With an attack case in the corpus | 16 |
| Measure | With a recorded result | 10 |

The benign corpus holds 24 cases of ordinary work that no rule may flag. It is shared by every rule rather than owned by one technique, so it is counted once here and not per row.

## What the columns mean

| Column | Meaning |
| --- | --- |
| Patterns | Registry patterns that map to this technique |
| Runnable | At least one of those patterns has a scanner scenario, so the attack can be run |
| Corpus | At least one of those patterns has an attack case in `corpus/attacks/` |
| Measured | At least one of those patterns has a recorded result in `results/` |
| State | `covered`, `not testable at runtime`, or `open` |

## Every technique

| Technique | Name | Patterns | Runnable | Corpus | Measured | State |
| --- | --- | --- | --- | --- | --- | --- |
| `AML.T0006.003` | Active Scanning: Probe AI Agent Trigger Channels | GP-0031 | no | no | no | covered |
| `AML.T0010.005` | AI Supply Chain Compromise: AI Agent Tool | GP-0003, GP-0019 | yes | no | yes | covered |
| `AML.T0011.002` | User Execution: Poisoned AI Agent Tool |  | no | no | no | open |
| `AML.T0018.003` | Manipulate AI Model: Modify Prompt Construction Logic | GP-0032 | no | no | no | covered |
| `AML.T0024` | Exfiltration via AI Inference API | GP-0034 | no | no | no | covered |
| `AML.T0025` | Exfiltration via Cyber Means |  | no | no | no | open |
| `AML.T0034.002` | Cost Harvesting: Agentic Resource Consumption | GP-0011, GP-0017 | no | yes | no | covered |
| `AML.T0051` | LLM Prompt Injection | GP-0021 | no | no | no | covered |
| `AML.T0051.000` | LLM Prompt Injection: Direct | GP-0021 | no | no | no | covered |
| `AML.T0051.001` | LLM Prompt Injection: Indirect | GP-0001, GP-0006 | yes | yes | yes | covered |
| `AML.T0051.002` | LLM Prompt Injection: Triggered | GP-0022 | no | no | no | covered |
| `AML.T0052.000` | Phishing: Spearphishing via Social Engineering LLM | GP-0033 | no | no | no | covered |
| `AML.T0053` | AI Agent Tool Invocation | GP-0014 | no | no | no | covered |
| `AML.T0054` | LLM Jailbreak | GP-0023 | no | no | no | covered |
| `AML.T0056` | Extract LLM System Prompt | GP-0012 | no | yes | no | covered |
| `AML.T0057` | LLM Data Leakage | GP-0002, GP-0041 | yes | yes | yes | covered |
| `AML.T0061` | LLM Prompt Self-Replication | GP-0013 | no | no | no | covered |
| `AML.T0062` | Discover LLM Hallucinations | GP-0024 | no | no | no | covered |
| `AML.T0065` | LLM Prompt Crafting | GP-0023 | no | no | no | covered |
| `AML.T0067` | LLM Trusted Output Components Manipulation | GP-0025 | no | no | no | covered |
| `AML.T0067.000` | LLM Trusted Output Components Manipulation: Citations | GP-0025 | no | no | no | covered |
| `AML.T0068` | LLM Prompt Obfuscation | GP-0006 | no | yes | no | covered |
| `AML.T0069` | Discover LLM System Information | GP-0026 | no | no | no | covered |
| `AML.T0069.000` | Discover LLM System Information: Special Character Sets | GP-0026 | no | no | no | covered |
| `AML.T0069.001` | Discover LLM System Information: System Instruction Keywords | GP-0026 | no | no | no | covered |
| `AML.T0069.002` | Discover LLM System Information: System Prompt | GP-0012 | no | yes | no | covered |
| `AML.T0070` | RAG Poisoning | GP-0027 | no | no | no | covered |
| `AML.T0071` | False RAG Entry Injection | GP-0027 | no | no | no | covered |
| `AML.T0077` | LLM Response Rendering | GP-0028 | no | no | no | covered |
| `AML.T0080` | AI Agent Context Poisoning | GP-0004, GP-0009, GP-0016 | yes | yes | yes | covered |
| `AML.T0080.000` | AI Agent Context Poisoning: Memory | GP-0004 | yes | yes | yes | covered |
| `AML.T0080.001` | AI Agent Context Poisoning: Thread | GP-0029 | no | no | no | covered |
| `AML.T0081` | Modify AI Agent Configuration |  | no | no | no | open |
| `AML.T0082` | RAG Credential Harvesting | GP-0030 | no | no | no | covered |
| `AML.T0083` | Credentials from AI Agent Configuration | GP-0007 | no | yes | no | covered |
| `AML.T0084` | Discover AI Agent Configuration | GP-0031 | no | no | no | covered |
| `AML.T0084.000` | Discover AI Agent Configuration: Embedded Knowledge | GP-0031 | no | no | no | covered |
| `AML.T0084.001` | Discover AI Agent Configuration: Tool Definitions | GP-0031 | no | no | no | covered |
| `AML.T0084.002` | Discover AI Agent Configuration: Activation Triggers | GP-0031 | no | no | no | covered |
| `AML.T0084.003` | Discover AI Agent Configuration: Call Chains | GP-0031 | no | no | no | covered |
| `AML.T0085.000` | Data from AI Services: RAG Databases | GP-0030 | no | no | no | covered |
| `AML.T0085.001` | Data from AI Services: AI Agent Tools | GP-0030 | no | no | no | covered |
| `AML.T0086` | Exfiltration via AI Agent Tool Invocation | GP-0002, GP-0020 | yes | yes | yes | covered |
| `AML.T0092` | Manipulate User LLM Chat History | GP-0029 | no | no | no | covered |
| `AML.T0093` | Prompt Infiltration via Public-Facing Application |  | no | no | no | open |
| `AML.T0094` | Delay Execution of LLM Instructions | GP-0022 | no | no | no | covered |
| `AML.T0098` | AI Agent Tool Credential Harvesting | GP-0007 | no | yes | no | covered |
| `AML.T0099` | AI Agent Tool Data Poisoning |  | no | no | no | open |
| `AML.T0100` | AI Agent Clickbait | GP-0036 | no | no | no | covered |
| `AML.T0101` | Data Destruction via AI Agent Tool Invocation | GP-0005 | yes | yes | no | covered |
| `AML.T0103` | Deploy AI Agent | GP-0037 | no | no | no | covered |
| `AML.T0108` | AI Agent | GP-0038 | no | no | no | covered |
| `AML.T0110` | AI Agent Tool Poisoning |  | no | no | no | open |
| `AML.T0110.000` | AI Agent Tool Poisoning: Definition and Instructions | GP-0003, GP-0019 | yes | no | yes | covered |
| `AML.T0110.001` | AI Agent Tool Poisoning: Implementation | GP-0035 | no | no | no | covered |
| `AML.T0110.002` | AI Agent Tool Poisoning: Runtime Response |  | no | no | no | open |
| `AML.T0112.000` | Machine Compromise: Local AI Agent | GP-0039 | no | no | no | covered |
| `AML.T0118` | Autonomous AI Agent Communication | GP-0008, GP-0013 | yes | yes | yes | covered |
| `AML.T0118.000` | Autonomous AI Agent Communication: Communication via Shared Artifacts | GP-0009, GP-0016 | yes | yes | yes | covered |
| `AML.T0118.001` | Autonomous AI Agent Communication: Direct Agent Communication | GP-0008, GP-0014, GP-0015, GP-0017 | yes | yes | yes | covered |
| `AML.T0121` | AI Agent Environment Reconstruction | GP-0040 | no | no | no | covered |
| `AML.T0130` | AI Agent Response Biasing | GP-0010 | no | yes | no | covered |
| `AML.T0133` | Discover AI Agent Runtime Capabilities | GP-0031 | no | no | no | covered |

Open a technique's issue to claim it. If none of the 7 open ones look right, [PROGRAM.md](../PROGRAM.md) lists the other phases.

## Canary benchmark

Generated from `benchmarks/canary-benchmark.json`, seed 20261031, 30 trials per scenario, Python 3.13.5. The full table is [../benchmarks/canary-benchmark.md](../benchmarks/canary-benchmark.md). GP-0020 only. The value is not stored. The tool calls are scripted: no model chose them. The regression suite is the set of forms the matcher was fixed against, so a full score there is a regression result, not a general detection rate.

| Slice | Sensor | Pre-fix matcher | Naive exact text |
| --- | --- | --- | --- |
| Designed carriers | 2100/2100, Wilson 95% [0.9982, 1.0000] | 1980/2100, Wilson 95% [0.9321, 0.9520] | 2100/2100, Wilson 95% [0.9982, 1.0000] |
| Formatting edges | 840/840, Wilson 95% [0.9954, 1.0000] | 0/840, Wilson 95% [0.0000, 0.0046] | 840/840, Wilson 95% [0.9954, 1.0000] |
| Encodings and a split across two calls | 1260/1260, Wilson 95% [0.9970, 1.0000] | 150/1260, Wilson 95% [0.1023, 0.1381] | 150/1260, Wilson 95% [0.1023, 0.1381] |
| All regression attacks | 4200/4200, Wilson 95% [0.9991, 1.0000] | 2130/4200, Wilson 95% [0.4920, 0.5222] | 3090/4200, Wilson 95% [0.7222, 0.7488] |
| Benign false alarms | 0/2100, Wilson 95% [0.0000, 0.0018] | 0/2100, Wilson 95% [0.0000, 0.0018] | 0/2100, Wilson 95% [0.0000, 0.0018] |

Held-out transforms (rot13, base32, gzip then base64, reverse-order halves, a zero-width character, ends only): 0/1260, Wilson 95% [0.0000, 0.0030]. A value that never appears in the arguments is not detected. The pre-fix column reproduces the local run that found the gaps: yes. Evidence contained the value in 0 of 4200 regression trials.


## Assumed-breach canaries

Generated from `benchmarks/assumed-breach.json`, 20 trials, Python 3.12.3. The full table is [../benchmarks/assumed-breach.md](../benchmarks/assumed-breach.md). The crawl is scripted. Live trial ran: no.

| Slice | Result | Wilson 95% |
| --- | --- | --- |
| Scripted crawl touched a decoy | 20/20 | [0.8389, 1.0000] |
| Quarantine ran | 20/20 | [0.8389, 1.0000] |
| A crown jewel was touched before the first decoy | 20/20 | [0.8389, 1.0000] |
| Something new appeared outside the sandbox | 0/20 | [0.0000, 0.1611] |
| Seeded copy of the dataset | 20/20 | [0.8389, 1.0000] |
| Seeded value in a tool call | 20/20 | [0.8389, 1.0000] |
| Real asset allowlist | 20/20 | [0.8389, 1.0000] |
| Decoy trip locks the real sibling | 20/20 | [0.8389, 1.0000] |
| Loopback sentinel | 20/20 | [0.8389, 1.0000] |
| Byte-for-byte copy of a real asset | 20/20 | [0.8389, 1.0000] |
| Allowlisted tool naming an outside URL | 20/20 | [0.8389, 1.0000] |
| git status false alarm | 20/20 | [0.8389, 1.0000] |
| Copy of a decoy outside the root, observed | 20/20 | [0.8389, 1.0000] |
| Allowlisted write outside the root, not followed | 20/20 | [0.8389, 1.0000] |

A descriptor opened before the watch is not seen. The poll backend misses a read when the access time does not move, and the `poll_read` probe depends on access-time updates being on. Timing medians depend on the machine. An allowlisted process can write bytes outside the root, and the watcher does not follow them. The limits are in [../benchmarks/ASSUMED_BREACH.md](../benchmarks/ASSUMED_BREACH.md).


## Multi-host assumed breach

Generated from `benchmarks/multi-host-breach.json`, 20 trials, Python 3.12.3. The full table is [../benchmarks/multi-host-breach.md](../benchmarks/multi-host-breach.md). The sweep is scripted. Live trial ran: no. The hosts are network namespaces with no default route.

| Slice | Result | Wilson 95% |
| --- | --- | --- |
| Workstation decoy tripped | 20/20 | [0.8389, 1.0000] |
| Workstation sibling quarantined | 20/20 | [0.8389, 1.0000] |
| Data sentinel saw the workstation | 20/20 | [0.8389, 1.0000] |
| Repo sentinel saw the workstation | 20/20 | [0.8389, 1.0000] |
| Data crown jewel quarantined by the end | 20/20 | [0.8389, 1.0000] |
| Repo crown jewel quarantined by the end | 20/20 | [0.8389, 1.0000] |
| Hub stored a counts-only drill sighting | 20/20 | [0.8389, 1.0000] |
| Seeded value written into a record | 0/20 | [0.0000, 0.1611] |
| Data jewel moved before the hop connected | 0/20 | [0.0000, 0.1611] |
| Repo jewel moved before the hop connected | 0/20 | [0.0000, 0.1611] |
| Seeded value arrived on the workstation | 15/20 | [0.5313, 0.8881] |
| Dataset download returned bytes | 15/20 | [0.5313, 0.8881] |
| Training file download returned bytes | 2/20 | [0.0279, 0.3010] |
| Data foothold recorded the crawl | 20/20 | [0.8389, 1.0000] |
| Repo foothold recorded the crawl | 20/20 | [0.8389, 1.0000] |
| A route or connection left the lab | 0/20 | [0.0000, 0.1611] |
| Benign workload tripped | 0/20 | [0.0000, 0.1611] |
| Trainer read the dataset and it stayed | 20/20 | [0.8389, 1.0000] |
| Sentinel connections received no bytes | 20/20 | [0.8389, 1.0000] |

Median seconds to the first workstation decoy: 0.0123. Median seconds from that stamp to the data handshake: -0.0095. A negative arrival means the handshake finished before the stamp. Protected-before counts a move that finished before the handshake, and that claim did not hold: both rows are 0. Download counts vary with timing. This table is one run (dataset 15/20, training file 2/20). A rerun of the same sweep got 11/20 and 1/20. A download that returned bytes is a leak. The limits are in [../benchmarks/MULTI_HOST.md](../benchmarks/MULTI_HOST.md).

