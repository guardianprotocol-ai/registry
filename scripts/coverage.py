"""Read and check the MITRE ATLAS triage.

One place that knows what the triage file means, so the status page and the check cannot
drift apart. No dependencies beyond the Python 3.9+ standard library.
"""
import csv
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(ROOT, "coverage", "atlas-coverage.csv")

AGENT_RUNTIME = "Agent runtime"

# A technique is resolved when a defense is linked to it, or when we have said out loud
# that nothing at runtime can act on it and why. Anything still 'draft triage' is open work.
DRAFT = "draft triage"
CONFIRMED = "confirmed"
NOT_TESTABLE = "not_testable_at_runtime"
STATUSES = (DRAFT, CONFIRMED, NOT_TESTABLE)

# Long enough to name the reason rather than wave at it.
MIN_REASON = 30


def load(path=None):
    with open(path or PATH, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def agent_runtime(rows):
    return [r for r in rows if r.get("category") == AGENT_RUNTIME]


def problems(rows):
    """Everything wrong with the triage, as a list of strings."""
    out = []
    seen = set()
    for row in rows:
        tid = (row.get("id") or "").strip()
        if not tid:
            out.append("a row has no technique id")
            continue
        if tid in seen:
            out.append(f"{tid}: appears more than once")
        seen.add(tid)
        status = (row.get("status") or "").strip()
        if status not in STATUSES:
            out.append(f"{tid}: status {status!r} is not one of " + ", ".join(repr(s) for s in STATUSES))
        reason = (row.get("reason") or "").strip()
        if status == NOT_TESTABLE and len(reason) < MIN_REASON:
            out.append(f"{tid}: marked {NOT_TESTABLE} but gives no reason. Say what a sensor "
                       "or a scan would have to see, and why it cannot")
        if status != NOT_TESTABLE and reason:
            out.append(f"{tid}: has a reason but its status is {status!r}. The reason field "
                       f"explains {NOT_TESTABLE} only")
    return out
