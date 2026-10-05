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
                if tuple(sorted(entry)) != tuple(sorted(hub.ALLOWED_FIELDS)):
                    # A file with extra fields is not one of ours. Refuse the entry rather
                    # than aggregating something whose shape we do not know.
                    continue
                out.append((entry["org"], entry))
    return out


def aggregate(pairs, min_orgs=MIN_ORGS):
    """Counts by pattern, rules version and hour, with per-pattern organization counts."""
    by_pattern = {}
    for org, entry in pairs:
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
    a = ap.parse_args(argv)

    rows = aggregate(load_folder(a.folder), min_orgs=a.min_orgs)
    print(text(rows, a.min_orgs))
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as f:
            json.dump(as_json(rows), f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"\nwrote {a.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
