#!/usr/bin/env python3
"""Build the Season 1 Map issues, one per agent runtime technique.

    python3 scripts/season_one_issues.py            human readable summary
    python3 scripts/season_one_issues.py --jsonl    one JSON object per line

This only builds the text. `scripts/create_season_one_issues.sh` is what talks to GitHub,
so the wording can be reviewed and tested without a token and without creating anything.
Python 3.9+ standard library only.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import build_status  # noqa: E402
import coverage  # noqa: E402


def title_for(row):
    return f"Map {row['id']}: {row['name']}"


def body_for(row, patterns):
    linked = ", ".join(patterns)
    lines = [
        f"Part of the **Map** phase of Season 1. See [PROGRAM.md](../blob/main/PROGRAM.md).",
        "",
        f"**Technique:** `{row['id']}` {row['name']}",
        f"**Tactics:** {row['tactics']}",
        f"**Maturity in ATLAS:** {row['maturity']}",
        "",
        "**Current triage row in `coverage/atlas-coverage.csv`:**",
        "",
        "| Category | Sensor can act | Scan can test | Status |",
        "| --- | --- | --- | --- |",
        f"| {row['category']} | {row['sensor']} | {row['scan']} | {row['status']} |",
        "",
    ]
    if patterns:
        lines += [
            f"**Already linked to:** {linked}.",
            "",
            "This one is mostly a review. Read the pattern and confirm the triage row is "
            "right, or say what is wrong with it. No security background needed.",
            "",
        ]
    else:
        lines += [
            "**No pattern covers this yet.** That is the work.",
            "",
        ]
    lines += [
        "## Done when one of these is true",
        "",
        "- [ ] Triage confirmed: the category, and whether a sensor or a scan can act, are right",
        "- [ ] A pattern is linked, or a new draft pattern is written "
        "(`python3 check.py new-pattern \"Title\"`)",
        "- [ ] Or the technique is marked `not_testable_at_runtime` in "
        "`coverage/atlas-coverage.csv`, with a `reason` saying what a sensor or a scan would "
        "have to see and why it cannot",
        "",
        "## Nice to have, and separate pull requests are fine",
        "",
        "- [ ] The pattern's test is runnable by the scanner",
        "- [ ] An attack case in `corpus/attacks/`",
        "- [ ] A recorded result in `results/`",
        "",
        "Claim it by commenting here. Progress for every technique is in "
        "[docs/STATUS.md](../blob/main/docs/STATUS.md), which is generated, so it updates itself.",
    ]
    return "\n".join(lines)


def labels_for(row, patterns):
    out = ["season-1"]
    out.append("track:patterns" if patterns else "track:coverage")
    if patterns:
        # Already covered, so the task is a review. That is the right first contribution.
        out.append("good first issue")
    return out


def build(coverage_path=None):
    rows = coverage.agent_runtime(coverage.load(coverage_path))
    links = build_status.patterns_by_technique()
    out = []
    for row in sorted(rows, key=lambda r: r["id"]):
        patterns = links.get(row["id"], [])
        out.append({"title": title_for(row),
                    "labels": labels_for(row, patterns),
                    "body": body_for(row, patterns)})
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the Season 1 Map issues")
    ap.add_argument("--jsonl", action="store_true", help="one JSON object per line")
    ap.add_argument("--coverage", default=None)
    a = ap.parse_args(argv)
    issues = build(a.coverage)
    if a.jsonl:
        for issue in issues:
            print(json.dumps(issue))
        return 0
    covered = sum(1 for i in issues if "good first issue" in i["labels"])
    print(f"{len(issues)} issues: {covered} already covered by a pattern "
          f"(labelled good first issue), {len(issues) - covered} with no pattern yet.")
    print("Nothing was created. Run scripts/create_season_one_issues.sh to create them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
