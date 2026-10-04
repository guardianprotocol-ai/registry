# Rule safety

How the project keeps a bad rule from reaching the people the protocol protects. A rule can fail in two directions: it can stop catching an attack, or it can start blocking ordinary work. Both are checked automatically on every pull request, before anyone has to review the change.

## Automatic checks

| Check | What it proves | Where |
| --- | --- | --- |
| Rule lint | Every signature compiles, has a unique id, never matches empty text or plain prose, has no nested repetition, and finishes quickly on large crafted inputs. The rules file is plain ASCII | `scripts/lint_rules.py` |
| Attack regression | Every case in `corpus/attacks/` still raises its pattern | `scripts/rule_gate.py` |
| Ordinary work | Every case in `corpus/benign/` raises nothing, apart from known false alarms that are listed in the case | `scripts/rule_gate.py` |
| Evidence | A pull request that changes the rules also adds or changes a test or corpus case | `scripts/require_rule_tests.py` |
| Before and after | The base branch's engine and the change's engine run the same corpus; the run summary shows attacks newly missed or caught and ordinary work newly flagged | `.github/workflows/checks.yml` |
| Promotion warning | A pattern promoted to `enforced` is flagged for two-organization approval | `scripts/require_rule_tests.py` |

`python3 check.py` runs the lint and the gate locally.

## Policy

The values below are proposed defaults, written into `corpus/policy.json` so a change to them is itself a reviewed pull request. **The working group ratifies them** through the proposal process in `GOVERNANCE.md`.

| Question | Proposed default |
| --- | --- |
| How many new false alarms on the benign corpus can a change introduce? | None |
| Which patterns must have an attack case before merging? | `verified` and `enforced` |
| How long does a new rule run in monitor mode before it may block? | 14 days, and at least two organizations running it without a false alarm report |
| Who can promote a pattern to `enforced`? | Two maintainers from different organizations |
| When is a pattern's false-alarm rate written into its file? | Once the benign corpus has at least 200 cases, so the number means something |
| What happens when a rule's tests start failing? | The rule drops back to monitor mode until fixed |
| Emergency rules for an attack happening now | Same two-organization approval, monitor mode skipped only with a written reason, and an expiry date after which the rule must go through the normal process |

## Growing the corpus

The corpus is only as good as what's in it. Every new pattern brings at least one attack case, and every reported false alarm becomes a benign case so it can never come back. See `corpus/README.md` for the format.
