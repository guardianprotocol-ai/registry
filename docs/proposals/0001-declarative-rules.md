# 0001: Declarative detection rules

**Status:** draft, for the working group to decide
**Author:** Frank Albanese

## Problem

Signatures are already data (`sensor/guardian_sensor/signatures.json`), but how they combine into a detection for each pattern is Python in `check_call` and `check_output`. So adding or changing a pattern's detection means changing engine code. At scale that is the wrong shape:

- **Review cost.** Reviewing code is harder than reviewing data, and a malicious code change can do anything. A malicious data change can only flag the wrong thing, which the rule gate catches.
- **Conflicts.** Every new pattern edits the same two functions.
- **Several engines.** The roadmap plans a sensor in Go or Rust, and hooks for several clients. Logic written in Python must be rewritten, and kept identical, in each.

## Proposal

Each pattern's detection becomes a small rule file that a fixed engine evaluates. The engine offers a short list of operators; rules combine them and can't do anything else.

```yaml
# patterns/GP-0007/detection.yaml (layout per proposal 0002)
rule_format: "1"
requires_engine: ">=0.2"
pattern: GP-0007
on: call                         # call | output
when:
  all:
    - session.tainted            # untrusted content with instructions was read earlier
    - any_path_matches: sensitive-path   # a signature id from signatures
raise:
  detail: [paths, tainted_by]
mode: monitor                    # monitor | block, set at release, not by the author
```

### Operators (first version)

| Operator | Meaning |
| --- | --- |
| `session.tainted` | Untrusted content with instructions was read earlier in the session |
| `tool_matches: <signature>` | The tool's name matches a tool-class signature |
| `any_path_matches`, `any_destination_matches`, `text_matches: <signature>` | A path, destination or the arguments match a signature |
| `destination_outside_allowlist` | A destination isn't on the user's allow-list |
| `has_instructions`, `hidden_content` | The existing content checks |
| `repeat_count_over: <config key>` | The same call has repeated past a budget |
| `all`, `any`, `not` | Combine conditions |

Every operator is bounded: no loops, no recursion, no network or file access, and a time budget per rule.

### Forward compatibility

- `rule_format` and `requires_engine` let an older sensor recognize a rule it can't evaluate. It **skips that rule and reports it**, rather than crashing or guessing. New operators can be added without breaking deployed sensors.
- Unknown fields are ignored, so fields can be added within a format version.
- Operators are never removed within a major format version.

### Alternatives considered

- **Keep Python rules.** Simplest today, wrong at scale for the reasons above.
- **CEL (Common Expression Language).** A proven, sandboxed expression language with implementations in several languages, used by Kubernetes. A strong candidate for the `when` clause once the project accepts a dependency. The operator list above could map onto CEL functions later without changing rule files.
- **Sigma.** The open format for SIEM detections, maintained by a large community. Its model of self-contained YAML rules with stable IDs is the model here; its log-oriented fields don't fit agent tool calls directly, but an export to Sigma is worth considering for teams that already run it.

## Migration

1. Write the engine that evaluates rule files, beside the current one.
2. Port GP-0001 to GP-0012 to rule files. The rule gate must show identical results before and after (the corpus is the proof).
3. Remove the Python per-pattern logic.
4. Port the corpus runner to each new engine as it's built; the corpus is the conformance suite.

## Undecided

- YAML or JSON for rule files.
- Whether `mode` lives in the rule file or only in the release bundle.
- Whether to adopt CEL now or later.
