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
| `schema_version` | `"0.2"`. `"0.1"` files are still read: they predate `run_log` |
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
| `run_log` | One entry per run, so the rate can be recounted rather than trusted. Written by `--record`. See below |
| `date` | `YYYY-MM-DD`, the day it was measured |
| `scanner_commit` | The scanner commit, or `unrecorded` |
| `environment` | Operating system, settings that matter, and anything that was not captured |
| `credits` | At least one `{name, organization}`. A measurement carries someone's name |
| `notes` | What happened, in plain language |

## The run log

`successes: 20` on its own is a number somebody typed. A judge bug and a real finding look
identical from a total, which is exactly what happened here: GP-0003's judge read the word
`sunny` out of the agent's prose, and nobody could check it because the answers had been
thrown away.

So a result carries one entry per run. `--record` writes it for you.

```json
"run_log": [
  {
    "n": 1,
    "outcome": "success",
    "seconds": 11.9,
    "judged_on": [{"tool": "weather", "accepted": true}],
    "answer": "Returned exactly: sunny ..."
  }
]
```

| Field | What it holds |
| --- | --- |
| `n` | Which run, from 1 |
| `outcome` | `success`, `defended` or `errored`. Nothing else |
| `seconds` | How long the run took |
| `judged_on` | What the judge was handed, when the scenario records calls. Left out when the judge reads a side effect instead |
| `answer` | The harness's final answer, truncated at 2000 characters with `answer_truncated_from` saying the original length |
| `error` | Required on an `errored` run: what failed |

**A log holds whatever your agent said.** If you measure your own agent against your own
code, that text goes into a file you are about to publish. Read it before you open the pull
request. `validate-results` refuses a log containing something that looks like a credential,
but it is a safety net, not a substitute for looking.

Canary tokens are the exception and are allowed, because they are harmless by construction
and a canary in a log is the test working rather than a leak.

Non-ASCII is written as JSON escapes, which is how `--record` writes it. That keeps a live
invisible character out of the repository while the parsed text stays exactly what the agent
said. If you edit a file by hand, keep `ensure_ascii` on.

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

If a `run_log` is present:

- It has one entry per run, and its outcomes add up to `successes` and `errored`. A log that
  disagrees with its own headline is refused, because it is worse than no log.
- Every `outcome` is `success`, `defended` or `errored`.
- An `errored` run says what failed. A run of zeros caused by a broken harness must not be
  publishable as a defended agent.
- No answer or error carries something matching the sensor's own secret patterns. Canary
  tokens are exempt.

## Before you publish

Read the responsible publication section of [../SECURITY.md](../SECURITY.md). Results for
publicly documented techniques can be published once they pass the checks. A new technique,
or a severe result not already public for that model or harness, goes to the model maker or
tool maintainer first.

A result is a statement about one version on one date. It is never a statement about a
vendor in general.
