"""Turn an aggregate into alerts a member's sensor can read.

This is the step that closes the loop. Until now a sighting reached an aggregate and stopped:
there was nothing a member's machine could read to learn what everybody else had seen, so
"the network told me" was a description rather than a mechanism.

An alert says a pattern cleared the threshold, how many organizations contributed, and when.
It says nothing about who, which is the same guarantee the sightings format makes, because an
alert derived from anonymous reports must not be less anonymous than the reports.

Published as a static file, polled by members, the same shape as the agenda. Nothing is
pushed to anybody: the operator publishes, machines read.

    python3 scripts/publish_alerts.py trial/sightings --out site/season1/alerts.json

Python 3.9+ standard library only.
"""
import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "scripts"))
import aggregate_sightings as agg  # noqa: E402

SCHEMA_VERSION = "1"


def build(rows, source="live", now=None):
    """Alerts from aggregated rows. Only what cleared the threshold is said out loud.

    A row below the floor is withheld in the aggregate and must be withheld here too. The
    whole point of the floor is that a total from fewer than three organizations could be
    attributed to one of them, and an alert is a more public thing than an aggregate.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    alerts = []
    for row in rows:
        if row.get("withheld"):
            continue
        alerts.append({
            "pattern": row["pattern"],
            "organizations": row["organizations"],
            "total": row["total"],
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "published": now.isoformat(timespec="seconds"),
        "source": source,
        "alerts": sorted(alerts, key=lambda a: a["pattern"]),
        "note": ("Patterns seen by at least three independent organizations. Counts only, "
                 "no reporter identified."),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Publish alerts from aggregated sightings")
    ap.add_argument("folder", help="a folder of <org>/ directories holding sightings files")
    ap.add_argument("--out", required=True, help="where to write alerts.json")
    ap.add_argument("--source", choices=("live", "drill"), default="drill",
                    help="which kind of sighting to count. Never both: an exercise is not an "
                         "incident")
    ap.add_argument("--min-orgs", type=int, default=agg.MIN_ORGS)
    a = ap.parse_args(argv)

    rows = agg.aggregate(agg.load_folder(a.folder), min_orgs=a.min_orgs, source=a.source)
    document = build(rows, source=a.source)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2, sort_keys=True)
        f.write("\n")

    print("wrote %s" % a.out)
    print("%d alert(s), from %s sightings, at or above %d organizations"
          % (len(document["alerts"]), a.source, a.min_orgs))
    for alert in document["alerts"]:
        print("  %-9s %d organizations, %s total"
              % (alert["pattern"], alert["organizations"], alert["total"]))
    withheld = [r["pattern"] for r in rows if r.get("withheld")]
    if withheld:
        print("\nWithheld, below %d organizations: %s" % (a.min_orgs, ", ".join(withheld)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
