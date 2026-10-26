#!/usr/bin/env python3
"""Who is taking part, and how much of the network reported.

    python3 receiver/participation.py

The denominator. A rate needs one: "twenty organizations saw this attack" says nothing
without knowing how many were running, and before this there was no way to tell a quiet
machine from a machine nobody installed.

What it cannot tell you is how many people installed the sensor. Nothing is sent when
somebody installs, on purpose: the tool promises that nothing leaves until they agree,
and a silent ping on install would make that promise false in the first minute. So this
counts members who agreed to report, which is a smaller number than installs and the only
one that can be measured honestly.
"""
import argparse
import datetime
import os
import sys


def record_for(org, document, existing=None, now=None):
    """What to store about a member reporting. No cloud dependency, so it is testable.

    Nothing here is more revealing than the document that carried it: the member id is
    already in the envelope and the versions are already in every entry. What they saw is
    not duplicated here, because that is what the sightings are for.
    """
    at = now or datetime.datetime.now(datetime.timezone.utc)
    stamp = at.isoformat(timespec="seconds")
    versions = {e.get("sensor_version") for e in document.get("sightings", [])}
    record = {"org": org, "last_seen": stamp,
              "last_entries": len(document.get("sightings", []))}
    if versions and None not in versions:
        record["sensor_version"] = sorted(versions)[0]
    # Kept from the first time they appeared. Without this a member who reports every
    # hour looks new every hour, the denominator grows, and every rate shrinks.
    if existing and existing.get("first_seen"):
        record["first_seen"] = existing["first_seen"]
    else:
        record["first_seen"] = stamp
    return record


# A member sends a sign of life once a day even with nothing to report. Two days of
# silence is therefore not quiet, it is absent: switched off, uninstalled, broken, or
# stopped. Which of those it is cannot be told from here, and that is the point: a sensor
# cannot be made tamper proof against an agent running at the same privilege on the same
# machine, so it is made tamper evident instead. Silence is the evidence.
SILENT_HOURS = 48


def silent(seen, now=None, hours=SILENT_HOURS):
    """Members who have stopped reporting, with how long since each was last heard from.

    Worth separating from members who have nothing to report. One is a result and the
    other is a gap, and before this they looked the same in the table.
    """
    at = now or datetime.datetime.now(datetime.timezone.utc)
    out = []
    for org, record in sorted(seen.items()):
        when = record.get("last_seen")
        try:
            last = datetime.datetime.fromisoformat(when)
        except (TypeError, ValueError):
            continue
        if last.tzinfo is None:
            last = last.replace(tzinfo=datetime.timezone.utc)
        quiet_for = (at - last).total_seconds() / 3600.0
        if quiet_for >= hours:
            out.append((org, quiet_for))
    return out


def rows(client, participants="participants", sightings="sightings"):
    seen = {}
    for document in client.collection(participants).stream():
        record = document.to_dict()
        seen[record.get("org") or document.id] = record
    reported = {}
    for document in client.collection(sightings).stream():
        entry = document.to_dict()
        org = entry.get("org")
        reported[org] = reported.get(org, 0) + int(entry.get("count") or 0)
    return seen, reported


def text(seen, reported, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if not seen:
        # Said plainly. A report of zero that reads like a report of something is the
        # failure this project keeps finding in its own checks.
        return ("No organization has reported yet. Nobody has agreed to share, or nobody "
                "has run it.\n")
    lines = ["%-24s %-22s %-22s %s" % ("member", "first seen", "last seen", "sightings"),
             "-" * 78]
    quiet = 0
    for org in sorted(seen):
        record = seen[org]
        total = reported.get(org, 0)
        if not total:
            quiet += 1
        lines.append("%-24s %-22s %-22s %s"
                     % (org[:24], (record.get("first_seen") or "")[:19],
                        (record.get("last_seen") or "")[:19], total or "none yet"))
    lines.append("")
    lines.append("%d organization%s reporting, of which %d have seen nothing."
                 % (len(seen), "" if len(seen) == 1 else "s", quiet))
    gone = silent(seen, now=now)
    if gone:
        lines.append("")
        lines.append("%d have stopped reporting altogether:" % len(gone))
        for org, hours in gone:
            lines.append("  %-24s last heard from %.0f hours ago" % (org[:24], hours))
        lines.append("A sign of life goes once a day even with nothing to report, so this")
        lines.append("is absence rather than quiet. A sensor cannot be made tamper proof")
        lines.append("against an agent running at the same privilege on the same machine.")
        lines.append("It can be made tamper evident, and this is that evidence: worth")
        lines.append("asking about, and not proof of anything on its own.")
    lines.append("An organization seeing nothing is a result, not a gap: it is the "
                 "denominator")
    lines.append("every rate in the research is divided by.")
    lines.append("")
    lines.append("This counts members who agreed to report. It is not a count of "
                 "installs, because")
    lines.append("nothing is sent when somebody installs and nothing should be.")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project", default=os.environ.get("GUARDIAN_PROJECT",
                                                        "guardian-protocol-site"))
    a = ap.parse_args(argv)
    from google.cloud import firestore
    client = firestore.Client(project=a.project)
    seen, reported = rows(client)
    sys.stdout.write(text(seen, reported))
    return 0


if __name__ == "__main__":
    sys.exit(main())
