#!/usr/bin/env python3
"""Merge members' sightings files into counts nobody can trace back to one member.

    python3 scripts/aggregate_sightings.py trial/sightings
    python3 scripts/aggregate_sightings.py trial/sightings --json out.json

Reads `<folder>/<org>/*.json`, merges them by pattern, rules version and hour, and reports
how many independent organizations saw each pattern.

**It will not print a count that belongs to one member.** Below three contributing
organizations, a pattern's totals are withheld and only the fact that it was seen is shown.
With two members, publishing a total lets either one subtract its own and read the other's.
Three is the smallest number where that stops working, and it is checked here rather than
left to whoever runs the script.

This lives in the public registry on purpose: the code that decides what is safe to publish
should be readable by the people whose data it is. Python 3.9+ standard library only.
"""
import argparse
import json
import os
import sys

# Below this many contributing organizations, totals stay private.
MIN_ORGS = 3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "sensor"))

from guardian_sensor import hub  # noqa: E402


class Suppressed:
    """A count that exists but must not be shown. Prints as 'withheld', never as a number."""

    def __repr__(self):
        return "withheld"

    def __str__(self):
        return "withheld"


WITHHELD = Suppressed()

# Fields added after the format was first published. An older file predates them and is
# still a valid file, so each one needs a default that cannot overstate what it claims.
# `source` defaults to live: a drill marks itself at the moment of detection, so the only
# way to be unmarked is to be a record no drill ever touched.
OPTIONAL_FIELDS = {"source"}


def load_folder(folder):
    """[(org, entry)] from <folder>/<org>/*.json, skipping anything malformed."""
    out = []
    if not os.path.isdir(folder):
        return out
    for org in sorted(os.listdir(folder)):
        org_dir = os.path.join(folder, org)
        if not os.path.isdir(org_dir):
            continue
        for name in sorted(os.listdir(org_dir)):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(org_dir, name), encoding="utf-8") as f:
                    doc = json.load(f)
            except (ValueError, OSError):
                continue
            for entry in (doc or {}).get("sightings", []):
                if not isinstance(entry, dict):
                    continue
                extra = set(entry) - set(hub.ALLOWED_FIELDS)
                missing = set(hub.ALLOWED_FIELDS) - set(entry) - OPTIONAL_FIELDS
                if extra or missing:
                    # An entry with a field we do not know is refused rather than
                    # aggregated, because we cannot say what it carries. A field we added
                    # after someone wrote their file is a different case: refusing those
                    # would make every new field a breaking change to a format other
                    # organizations have already written to disk.
                    continue
                entry = {"source": "live", **entry}
                out.append((entry["org"], entry))
    return out


def aggregate(pairs, min_orgs=MIN_ORGS, source=None):
    """Counts by pattern, rules version and hour, with per-pattern organization counts.

    `source` keeps only entries from live traffic or only from fire drills. An entry that
    predates the field counts as live, which is the safe default for old files and the
    reason the drill marks its own records at the moment of detection rather than later.

    Mixing the two in one total would let an exercise somebody ran against their own
    machine be reported as an observed incident. The aggregate says which it is counting.
    """
    by_pattern = {}
    for org, entry in pairs:
        if source and entry.get("source", "live") != source:
            continue
        p = by_pattern.setdefault(entry["pattern"], {"orgs": set(), "total": 0, "cells": {}})
        p["orgs"].add(org)
        p["total"] += entry["count"]
        key = (entry["rules_version"], entry["hour"])
        p["cells"][key] = p["cells"].get(key, 0) + entry["count"]

    out = []
    for pattern in sorted(by_pattern):
        p = by_pattern[pattern]
        enough = len(p["orgs"]) >= min_orgs
        out.append({
            "pattern": pattern,
            "organizations": len(p["orgs"]),
            "total": p["total"] if enough else WITHHELD,
            "cells": ([{"rules_version": rv, "hour": h, "count": c}
                       for (rv, h), c in sorted(p["cells"].items())] if enough else WITHHELD),
            "withheld": not enough,
        })
    return out


def text(rows, min_orgs=MIN_ORGS):
    if not rows:
        return "No sightings found."
    lines = [f"{'pattern':<10} {'orgs':>5} {'total':>10}", "-" * 27]
    for row in rows:
        lines.append(f"{row['pattern']:<10} {row['organizations']:>5} {str(row['total']):>10}")
    withheld = [r["pattern"] for r in rows if r["withheld"]]
    lines.append("")
    if withheld:
        lines.append(f"Withheld: {', '.join(withheld)}. Fewer than {min_orgs} organizations "
                     "contributed, so a total would be traceable to one of them.")
    else:
        lines.append(f"Every pattern above had at least {min_orgs} contributing organizations.")
    return "\n".join(lines)


def as_json(rows):
    return [{**row,
             "total": None if row["withheld"] else row["total"],
             "cells": None if row["withheld"] else row["cells"]}
            for row in rows]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Merge members' sightings files")
    ap.add_argument("folder", help="a folder of <org>/ directories holding sightings files")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--min-orgs", type=int, default=MIN_ORGS)
    ap.add_argument("--source", choices=("live", "drill"), default=None,
                    help="count only live traffic, or only fire drills. Mixing them would "
                         "report an exercise as an incident")
    a = ap.parse_args(argv)

    rows = aggregate(load_folder(a.folder), min_orgs=a.min_orgs, source=a.source)
    if a.source:
        print(f"Counting {a.source} entries only.\n")
    else:
        print("Counting live traffic and fire drills together. Pass --source to separate "
              "them before quoting any of this.\n")
    print(text(rows, a.min_orgs))
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump(as_json(rows), f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"\nwrote {a.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
