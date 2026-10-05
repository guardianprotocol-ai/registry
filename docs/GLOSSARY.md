# Glossary

Seven words this project uses precisely. If a document here uses one of them loosely, that
is a bug worth a pull request.

| Term | What it means |
| --- | --- |
| **Technique** | A category of attack in MITRE ATLAS, such as `AML.T0051.001`. ATLAS names it; we do not. |
| **Pattern** | A specific, reproducible attack on agents in this registry, with a GP ID. A pattern maps to one or more techniques, or explains why none fits. |
| **Test** | The harmless, runnable version of a pattern. Canary tokens and reserved `.test` destinations only. |
| **Detection** | The rule a sensor uses to catch a pattern while an agent is running. |
| **Target** | What a test runs against: a model, inside an agent harness, at specific versions. |
| **Harness** | The agent software around a model, such as Claude Code, Cursor or a custom framework. |
| **Result** | A measured attack success rate for one pattern against one target, with run count, interval and date. |

## Why the distinction between technique and pattern matters

ATLAS is a taxonomy. It tells you that indirect prompt injection exists and gives it an
identifier. It does not hand you something you can run, something that catches it, or a
number saying how often it works against the agent you actually deployed.

A pattern is the executable form. One technique can have many patterns under it, because
the same idea shows up differently in a tool's output, a retrieved document and an agent's
own memory.

## Why the distinction between pattern and result matters

**Patterns describe attacks. Results describe targets.** A pattern is never forked per
model. When the same attack lands on one model and not another, that variation lives in
`results/`, never in a second copy of the pattern.

This is what lets one pattern accumulate evidence over time instead of splintering.
