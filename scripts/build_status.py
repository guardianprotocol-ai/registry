#!/usr/bin/env python3
"""Generate docs/STATUS.md: how far Season 1 has got, from the repository alone.

    python3 scripts/build_status.py            write docs/STATUS.md
    python3 scripts/build_status.py --check    fail if docs/STATUS.md is out of date

No API calls and no network: everything here is read from the triage file, the pattern
files, the scanner's scenarios, the corpus and the recorded results. That is deliberate.
Progress nobody has to ask about is the point, and a page that needs a token to rebuild
would quietly stop being rebuilt. Python 3.9+ standard library only.
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "scanner"))

import coverage  # noqa: E402
from guardian_scanner import results as result_files  # noqa: E402
from guardian_scanner import scenarios  # noqa: E402

OUT = os.path.join(ROOT, "docs", "STATUS.md")

HEADER = """# Season 1 status

Generated from the repository by `python3 scripts/build_status.py`. Do not edit by hand:
`python3 check.py` fails if this file and the repository disagree.

Season 1 runs **October 5 to October 29, 2026**. What this page tracks is the Map phase and
what follows from it: the {total} MITRE ATLAS techniques that happen while an agent is
running. See [../PROGRAM.md](../PROGRAM.md) for the phases and how to pick something up.

A technique is **resolved** when a pattern covers it, or when it is marked not testable at
runtime with a reason. Everything else is open work, and every one of them has an issue.
"""

LEGEND = """
## What the columns mean

| Column | Meaning |
| --- | --- |
| Patterns | Registry patterns that map to this technique |
| Runnable | At least one of those patterns has a scanner scenario, so the attack can be run |
| Corpus | At least one of those patterns has an attack case in `corpus/attacks/` |
| Measured | At least one of those patterns has a recorded result in `results/` |
| State | `covered`, `not testable at runtime`, or `open` |
"""


def patterns_by_technique(folder=None):
    """ATLAS technique id -> sorted pattern ids that claim it."""
    folder = folder or os.path.join(ROOT, "patterns")
    out = {}
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".yaml"):
            continue
        with open(os.path.join(folder, name), encoding="utf-8") as f:
            text = f.read()
        pid = re.search(r"^id:\s*(\S+)", text, re.M)
        atlas = re.search(r"^\s*atlas:\s*\[(.*?)\]", text, re.M | re.S)
        if not pid or not atlas:
            continue
        for quoted in re.findall(r'"([^"]+)"', atlas.group(1)):
            out.setdefault(quoted.split(" ", 1)[0], set()).add(pid.group(1))
    return {k: sorted(v) for k, v in out.items()}


def attack_cases(folder=None):
    """pattern id -> how many attack cases in the corpus name it.

    Benign cases are deliberately not keyed to a pattern: the benign corpus is ordinary
    work that no rule may flag, so it applies to every rule at once rather than belonging
    to one. Counting it per technique would be inventing a relationship that is not there.
    """
    folder = folder or os.path.join(ROOT, "corpus", "attacks")
    counts = {}
    if not os.path.isdir(folder):
        return counts
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(folder, name), encoding="utf-8") as f:
                doc = json.load(f)
        except (ValueError, OSError):
            continue
        expect = doc.get("expect")
        for pid in ([expect] if isinstance(expect, str) else list(expect or [])):
            counts[pid] = counts.get(pid, 0) + 1
    return counts


def benign_cases(folder=None):
    """How many benign cases the whole corpus holds. Shared by every rule."""
    folder = folder or os.path.join(ROOT, "corpus", "benign")
    if not os.path.isdir(folder):
        return 0
    return len([n for n in os.listdir(folder) if n.endswith(".json")])


def measured_patterns(results_dir=None):
    return {doc["pattern"] for _, doc in result_files.load_dir(results_dir)}


def collect(coverage_path=None, results_dir=None):
    rows = coverage.agent_runtime(coverage.load(coverage_path))
    links = patterns_by_technique()
    corpus = attack_cases()
    measured = measured_patterns(results_dir)
    runnable = set(scenarios.available())
    out = []
    for row in rows:
        pats = links.get(row["id"], [])
        has_corpus = any(corpus.get(p, 0) > 0 for p in pats)
        if pats:
            state = "covered"
        elif row.get("status") == coverage.NOT_TESTABLE:
            state = "not testable at runtime"
        else:
            state = "open"
        out.append({
            "id": row["id"],
            "name": row["name"],
            "patterns": pats,
            "runnable": any(p in runnable for p in pats),
            "corpus": has_corpus,
            "measured": any(p in measured for p in pats),
            "state": state,
            "reason": (row.get("reason") or "").strip(),
        })
    return out


def summary(items):
    return {
        "total": len(items),
        "covered": sum(1 for i in items if i["state"] == "covered"),
        "not_testable": sum(1 for i in items if i["state"] == "not testable at runtime"),
        "open": sum(1 for i in items if i["state"] == "open"),
        "runnable": sum(1 for i in items if i["runnable"]),
        "corpus": sum(1 for i in items if i["corpus"]),
        "measured": sum(1 for i in items if i["measured"]),
        "benign": benign_cases(),
    }


def tick(value):
    return "yes" if value else "no"


def render(items):
    n = summary(items)
    resolved = n["covered"] + n["not_testable"]
    lines = [HEADER.format(total=n["total"])]
    lines.append("## Where Season 1 is\n")
    lines.append("| Phase | Measure | Count |")
    lines.append("| --- | --- | --- |")
    lines.append(f"| Map | Resolved, out of {n['total']} | **{resolved}** |")
    lines.append(f"| Map | Covered by a pattern | {n['covered']} |")
    lines.append(f"| Map | Marked not testable at runtime | {n['not_testable']} |")
    lines.append(f"| Map | Still open | {n['open']} |")
    lines.append(f"| Prove | With a runnable test | {n['runnable']} |")
    lines.append(f"| Prove | With an attack case in the corpus | {n['corpus']} |")
    lines.append(f"| Measure | With a recorded result | {n['measured']} |")
    lines.append(f"\nThe benign corpus holds {n['benign']} cases of ordinary work that no rule "
                 "may flag. It is shared by every rule rather than owned by one technique, so it "
                 "is counted once here and not per row.")
    lines.append(LEGEND)
    lines.append("## Every technique\n")
    lines.append("| Technique | Name | Patterns | Runnable | Corpus | Measured | State |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for i in sorted(items, key=lambda x: x["id"]):
        pats = ", ".join(i["patterns"]) if i["patterns"] else ""
        state = i["state"]
        if state == "not testable at runtime" and i["reason"]:
            state = f"not testable at runtime: {i['reason']}"
        lines.append(f"| `{i['id']}` | {i['name']} | {pats} | {tick(i['runnable'])} | "
                     f"{tick(i['corpus'])} | {tick(i['measured'])} | {state} |")
    lines.append("")
    lines.append("Open a technique's issue to claim it. If none of the {0} open ones look "
                 "right, [PROGRAM.md](../PROGRAM.md) lists the other phases."
                 .format(n["open"]))
    return "\n".join(lines) + "\n"


def build(coverage_path=None, results_dir=None):
    return render(collect(coverage_path, results_dir))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate the Season 1 status page")
    ap.add_argument("--check", action="store_true",
                    help="fail if docs/STATUS.md is out of date instead of writing it")
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--coverage", default=None)
    ap.add_argument("--results", default=None)
    a = ap.parse_args(argv)

    text = build(a.coverage, a.results)
    if a.check:
        current = ""
        if os.path.exists(a.out):
            with open(a.out, encoding="utf-8") as f:
                current = f.read()
        if current != text:
            print("docs/STATUS.md is out of date. Regenerate it:")
            print("  python3 scripts/build_status.py")
            return 1
        n = summary(collect(a.coverage, a.results))
        print(f"The status page is current: {n['covered'] + n['not_testable']} of "
              f"{n['total']} techniques resolved.")
        return 0

    with open(a.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
