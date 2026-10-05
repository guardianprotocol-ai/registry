# Results

**Patterns describe attacks. Results describe targets.**

A pattern is never forked per model. When the same attack lands on one model and not
another, that variation lives here, in one JSON file per measurement set. This is what lets
a single pattern accumulate evidence over time instead of splintering into near-copies.

Every file is checked by `python3 check.py`, and the generated matrix in
[../docs/MATRIX.md](../docs/MATRIX.md) is built from these files and never written by hand.

## Producing one

```bash
cd scanner
python3 -m guardian_scanner run --target claude-code --repeat 10 --record ../results
python3 -m guardian_scanner run --target claude-code --repeat 10 --sensor --record ../results
```

The scanner fills in everything it knows and writes `unrecorded` where it cannot know, such
as the model behind a closed harness. Open the file afterwards and replace what you can:
your name in `credits`, the real `environment`, and the model and version if you know them.
`unrecorded` is an honest placeholder, not a target to leave in place.

Then open a pull request with the result files. Nothing else is needed.

## File name

```
<pattern>__<harness>__<model>__<date>__sensor-<state>.json
```

Lowercase, with anything else replaced by a hyphen. The sensor state is part of the name
because the same pattern, harness, model and date produce two different measurements
depending on whether the sensor was in front. `check.py` refuses a file whose name does not
match its contents.

## Fields

| Field | What it holds |
| --- | --- |
| `schema_version` | `"0.1"` for now |
| `pattern` | A pattern ID that exists in `patterns/` |
| `target.model` | The model, or `unrecorded` |
| `target.model_version` | The model version, or `unrecorded` |
| `target.harness` | The agent software, such as `claude-code` |
| `target.harness_version` | Its version, or `unrecorded` |
| `sensor.state` | `off` or `on` |
| `sensor.bundle` | Required when the state is `on`: the rule bundle or the commit the rules came from |
| `runs` | Total attempts, at least 5 |
| `successes` | Attempts where the attack worked |
| `errored` | Attempts excluded because the harness failed, not because the agent defended |
| `rate` | `successes / (runs - errored)`, recomputed and checked |
| `interval` | The 95% Wilson score interval on the same counts, recomputed and checked |
| `date` | `YYYY-MM-DD`, the day it was measured |
| `scanner_commit` | The scanner commit, or `unrecorded` |
| `environment` | Operating system, settings that matter, and anything that was not captured |
| `credits` | At least one `{name, organization}`. A measurement carries someone's name |
| `notes` | What happened, in plain language |

## What the checks enforce

- The pattern exists.
- At least 5 runs. Five clean runs give an interval of roughly 0 to 0.43, which is why the
  matrix prints the interval beside every rate.
- `successes + errored` is never more than `runs`.
- `rate` and `interval` are recomputed from the counts and have to match. A file whose
  arithmetic does not reproduce is refused, because a wrong number published here is worse
  than no number.
- Errored runs are excluded from the rate rather than counted as a defence, so a broken
  harness cannot be mistaken for a protected agent.
- A result for a pattern the scanner has no scenario for must explain in `environment` how
  the test was actually run.
- The file name matches the contents.

## Before you publish

Read the responsible publication section of [../SECURITY.md](../SECURITY.md). Results for
publicly documented techniques can be published once they pass the checks. A new technique,
or a severe result not already public for that model or harness, goes to the model maker or
tool maintainer first.

A result is a statement about one version on one date. It is never a statement about a
vendor in general.
