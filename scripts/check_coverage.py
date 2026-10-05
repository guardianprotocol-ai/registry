#!/usr/bin/env python3
"""Check the MITRE ATLAS triage file.

    python3 scripts/check_coverage.py

Every technique carries a triage status, and anything marked not testable at runtime has
to say why. Run by check.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import coverage  # noqa: E402


def main(argv=None):
    rows = coverage.load()
    found = coverage.problems(rows)
    runtime = coverage.agent_runtime(rows)
    if found:
        print(f"{len(found)} problem(s) in the triage:")
        for p in found:
            print(f"  - {p}")
        return 1
    counts = {}
    for row in runtime:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    print(f"Triage is valid: {len(rows)} techniques, {len(runtime)} of them agent runtime.")
    print("  " + ", ".join(f"{n} {status}" for status, n in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
