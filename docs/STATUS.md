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
| Map | Resolved, out of 63 | **20** |
| Map | Covered by a pattern | 20 |
| Map | Marked not testable at runtime | 0 |
| Map | Still open | 43 |
| Prove | With a runnable test | 7 |
| Prove | With an attack case in the corpus | 16 |
| Measure | With a recorded result | 5 |

The benign corpus holds 15 cases of ordinary work that no rule may flag. It is shared by every rule rather than owned by one technique, so it is counted once here and not per row.

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
| `AML.T0006.003` | Active Scanning: Probe AI Agent Trigger Channels |  | no | no | no | open |
| `AML.T0010.005` | AI Supply Chain Compromise: AI Agent Tool | GP-0003 | yes | no | yes | covered |
| `AML.T0011.002` | User Execution: Poisoned AI Agent Tool |  | no | no | no | open |
| `AML.T0018.003` | Manipulate AI Model: Modify Prompt Construction Logic |  | no | no | no | open |
| `AML.T0024` | Exfiltration via AI Inference API |  | no | no | no | open |
| `AML.T0025` | Exfiltration via Cyber Means |  | no | no | no | open |
| `AML.T0034.002` | Cost Harvesting: Agentic Resource Consumption | GP-0011, GP-0017 | no | yes | no | covered |
| `AML.T0051` | LLM Prompt Injection |  | no | no | no | open |
| `AML.T0051.000` | LLM Prompt Injection: Direct |  | no | no | no | open |
| `AML.T0051.001` | LLM Prompt Injection: Indirect | GP-0001, GP-0006 | yes | yes | yes | covered |
| `AML.T0051.002` | LLM Prompt Injection: Triggered |  | no | no | no | open |
| `AML.T0052.000` | Phishing: Spearphishing via Social Engineering LLM |  | no | no | no | open |
| `AML.T0053` | AI Agent Tool Invocation | GP-0014 | no | no | no | covered |
| `AML.T0054` | LLM Jailbreak |  | no | no | no | open |
| `AML.T0056` | Extract LLM System Prompt | GP-0012 | no | yes | no | covered |
| `AML.T0057` | LLM Data Leakage | GP-0002 | yes | yes | no | covered |
| `AML.T0061` | LLM Prompt Self-Replication | GP-0013 | no | no | no | covered |
| `AML.T0062` | Discover LLM Hallucinations |  | no | no | no | open |
| `AML.T0065` | LLM Prompt Crafting |  | no | no | no | open |
| `AML.T0067` | LLM Trusted Output Components Manipulation |  | no | no | no | open |
| `AML.T0067.000` | LLM Trusted Output Components Manipulation: Citations |  | no | no | no | open |
| `AML.T0068` | LLM Prompt Obfuscation | GP-0006 | no | yes | no | covered |
| `AML.T0069` | Discover LLM System Information |  | no | no | no | open |
| `AML.T0069.000` | Discover LLM System Information: Special Character Sets |  | no | no | no | open |
| `AML.T0069.001` | Discover LLM System Information: System Instruction Keywords |  | no | no | no | open |
| `AML.T0069.002` | Discover LLM System Information: System Prompt | GP-0012 | no | yes | no | covered |
| `AML.T0070` | RAG Poisoning |  | no | no | no | open |
| `AML.T0071` | False RAG Entry Injection |  | no | no | no | open |
| `AML.T0077` | LLM Response Rendering |  | no | no | no | open |
| `AML.T0080` | AI Agent Context Poisoning | GP-0004, GP-0009, GP-0016 | no | yes | no | covered |
| `AML.T0080.000` | AI Agent Context Poisoning: Memory | GP-0004 | no | yes | no | covered |
| `AML.T0080.001` | AI Agent Context Poisoning: Thread |  | no | no | no | open |
| `AML.T0081` | Modify AI Agent Configuration |  | no | no | no | open |
| `AML.T0082` | RAG Credential Harvesting |  | no | no | no | open |
| `AML.T0083` | Credentials from AI Agent Configuration | GP-0007 | no | yes | no | covered |
| `AML.T0084` | Discover AI Agent Configuration |  | no | no | no | open |
| `AML.T0084.000` | Discover AI Agent Configuration: Embedded Knowledge |  | no | no | no | open |
| `AML.T0084.001` | Discover AI Agent Configuration: Tool Definitions |  | no | no | no | open |
| `AML.T0084.002` | Discover AI Agent Configuration: Activation Triggers |  | no | no | no | open |
| `AML.T0084.003` | Discover AI Agent Configuration: Call Chains |  | no | no | no | open |
| `AML.T0085.000` | Data from AI Services: RAG Databases |  | no | no | no | open |
| `AML.T0085.001` | Data from AI Services: AI Agent Tools |  | no | no | no | open |
| `AML.T0086` | Exfiltration via AI Agent Tool Invocation | GP-0002 | yes | yes | no | covered |
| `AML.T0092` | Manipulate User LLM Chat History |  | no | no | no | open |
| `AML.T0093` | Prompt Infiltration via Public-Facing Application |  | no | no | no | open |
| `AML.T0094` | Delay Execution of LLM Instructions |  | no | no | no | open |
| `AML.T0098` | AI Agent Tool Credential Harvesting | GP-0007 | no | yes | no | covered |
| `AML.T0099` | AI Agent Tool Data Poisoning |  | no | no | no | open |
| `AML.T0100` | AI Agent Clickbait |  | no | no | no | open |
| `AML.T0101` | Data Destruction via AI Agent Tool Invocation | GP-0005 | no | yes | no | covered |
| `AML.T0103` | Deploy AI Agent |  | no | no | no | open |
| `AML.T0108` | AI Agent |  | no | no | no | open |
| `AML.T0110` | AI Agent Tool Poisoning |  | no | no | no | open |
| `AML.T0110.000` | AI Agent Tool Poisoning: Definition and Instructions | GP-0003 | yes | no | yes | covered |
| `AML.T0110.001` | AI Agent Tool Poisoning: Implementation |  | no | no | no | open |
| `AML.T0110.002` | AI Agent Tool Poisoning: Runtime Response |  | no | no | no | open |
| `AML.T0112.000` | Machine Compromise: Local AI Agent |  | no | no | no | open |
| `AML.T0118` | Autonomous AI Agent Communication | GP-0008, GP-0013 | yes | yes | yes | covered |
| `AML.T0118.000` | Autonomous AI Agent Communication: Communication via Shared Artifacts | GP-0009, GP-0016 | no | yes | no | covered |
| `AML.T0118.001` | Autonomous AI Agent Communication: Direct Agent Communication | GP-0008, GP-0014, GP-0015, GP-0017 | yes | yes | yes | covered |
| `AML.T0121` | AI Agent Environment Reconstruction |  | no | no | no | open |
| `AML.T0130` | AI Agent Response Biasing | GP-0010 | no | yes | no | covered |
| `AML.T0133` | Discover AI Agent Runtime Capabilities |  | no | no | no | open |

Open a technique's issue to claim it. If none of the 43 open ones look right, [PROGRAM.md](../PROGRAM.md) lists the other phases.
