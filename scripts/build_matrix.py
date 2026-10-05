#!/usr/bin/env python3
"""Generate docs/MATRIX.md and matrix.json from the files in results/.

    python3 scripts/build_matrix.py            write docs/MATRIX.md
    python3 scripts/build_matrix.py --check    fail if docs/MATRIX.md is out of date
    python3 scripts/build_matrix.py --json matrix.json

The matrix is generated, never hand edited. check.py fails if the file on disk does not
match what this script produces, so a new result cannot land without the published table
moving with it. No dependencies beyond the Python 3.9+ standard library.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scanner"))

from guardian_scanner import patterns as pattern_files  # noqa: E402
from guardian_scanner import results as result_files  # noqa: E402

OUT = os.path.join(ROOT, "docs", "MATRIX.md")

HEADER = """# The attack matrix

Generated from `results/`. Do not edit by hand: `python3 check.py` fails if this file and
the result files disagree.

**Patterns describe attacks. Results describe targets.** The same attack lands differently
depending on the model, the agent software around it and the versions of both, so the
variation lives here rather than in copies of the pattern.

## How to read a cell

Every cell is an attack success rate over a number of runs, with a 95% Wilson score
interval. The interval matters more than the rate: five clean runs give roughly 0 to 0.43,
which is not a safe agent, it is not enough evidence. A run that errored is excluded rather
than counted as a defence, so a broken harness cannot look like a protected one.

**A row is a statement about one version on one date. It is never a statement about a
vendor in general.** Nothing here says a product is insecure. It says what happened, how
many times, when.

## Before adding a row

Results for publicly documented techniques can be published once they pass the checks in
`results/README.md`. A new technique, or a severe result not already public for that model
or harness, goes to the model maker or tool maintainer first through
[SECURITY.md](../SECURITY.md), and is published after a fix or after the disclosure window.

## Contributing a measurement

```bash
cd scanner
python3 -m guardian_scanner run --target claude-code --repeat 10 --record ../results
```

Then open a pull request with the result files. See [results/README.md](../results/README.md).
"""

FOOTER = """
## What is not here

Every pattern with no row is a pattern nobody has measured yet. That is the work: see the
issues labelled `track:scanner`, and `results/README.md` for how to record one.
"""


def target_key(doc):
    t = doc.get("target", {})
    return (t.get("harness", "?"), t.get("harness_version", "?"),
            t.get("model", "?"), t.get("model_version", "?"))


def target_label(key):
    harness, harness_version, model, model_version = key
    label = f"{harness} {harness_version}"
    if model and model != "unrecorded":
        label += f", {model}"
        if model_version and model_version != "unrecorded":
            label += f" {model_version}"
    else:
        label += ", model unrecorded"
    return label


def cell(doc):
    if doc is None:
        return "not measured"
    low, high = doc["interval"]
    runs = doc["runs"]
    errored = doc.get("errored", 0)
    scored = runs - errored
    text = f"{doc['rate'] * 100:.0f}% [{low:.2f}, {high:.2f}], {scored} runs"
    if errored:
        text += f", {errored} errored"
    return text


def collect(results_dir=None):
    """{pattern: {target_key: {sensor_state: doc}}}, plus the newest date per pattern."""
    grouped = {}
    for _, doc in result_files.load_dir(results_dir):
        state = (doc.get("sensor") or {}).get("state", "off")
        grouped.setdefault(doc["pattern"], {}).setdefault(target_key(doc), {})[state] = doc
    return grouped


def render(grouped, titles):
    lines = [HEADER]
    if not grouped:
        lines.append("\nNo measurements recorded yet.\n")
        lines.append(FOOTER)
        return "\n".join(lines)
    for pattern in sorted(grouped):
        title = titles.get(pattern, "")
        lines.append(f"\n## {pattern}{': ' + title if title else ''}\n")
        lines.append("| Target | Date | Unprotected | With the sensor |")
        lines.append("| --- | --- | --- | --- |")
        for key in sorted(grouped[pattern]):
            by_state = grouped[pattern][key]
            any_doc = by_state.get("off") or by_state.get("on")
            lines.append(f"| {target_label(key)} | {any_doc['date']} | "
                         f"{cell(by_state.get('off'))} | {cell(by_state.get('on'))} |")
    lines.append(FOOTER)
    return "\n".join(lines) + "\n"


def as_json(grouped):
    out = []
    for pattern in sorted(grouped):
        for key in sorted(grouped[pattern]):
            for state in sorted(grouped[pattern][key]):
                doc = grouped[pattern][key][state]
                out.append({
                    "pattern": pattern,
                    "target": doc["target"],
                    "sensor": doc["sensor"],
                    "runs": doc["runs"],
                    "successes": doc["successes"],
                    "errored": doc.get("errored", 0),
                    "rate": doc["rate"],
                    "interval": doc["interval"],
                    "date": doc["date"],
                })
    return {"schema_version": result_files.SCHEMA_VERSION, "measurements": out}


def titles_of():
    report = pattern_files.validate_dir(pattern_files.registry_dir())
    return {pid: doc.get("title", "") for pid, doc in report.patterns.items()}


def build(results_dir=None):
    return render(collect(results_dir), titles_of())


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate the attack matrix")
    ap.add_argument("--check", action="store_true",
                    help="fail if docs/MATRIX.md is out of date instead of writing it")
    ap.add_argument("--json", dest="json_out", default=None,
                    help="also write the machine readable matrix here")
    ap.add_argument("--results", default=None)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args(argv)

    text = build(a.results)
    if a.check:
        current = ""
        if os.path.exists(a.out):
            with open(a.out, encoding="utf-8") as f:
                current = f.read()
        if current != text:
            print("docs/MATRIX.md is out of date. Regenerate it:")
            print("  python3 scripts/build_matrix.py")
            return 1
        print(f"The attack matrix is current ({len(collect(a.results))} pattern(s) measured).")
        return 0

    with open(a.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {a.out}")
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump(as_json(collect(a.results)), f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"wrote {a.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
