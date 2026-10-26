#!/usr/bin/env python3
"""Publish how big the network is, so a count can be read as a share.

    python3 scripts/publish_network.py --organizations 1042 --out site/season1/network.json

Without this a member reads that forty organizations saw an attack and cannot tell
whether that is most of the network or a rounding error. Worse, as the network grows
every count grows with it, so a node watching for a pattern spreading sees a spike every
time the protocol gains members, which is exactly when false alarms are least welcome.

A separate document rather than a field in alerts.json, on purpose. The alerts format
refuses keys it does not recognise, which is right for something machines read
unattended: an alert must never be able to smuggle in an instruction. The cost is that it
cannot grow a field without every existing reader refusing the whole document. So the
denominator is published beside it, where a reader that wants it fetches it and a reader
that does not never notices.

It says one number. Nothing here identifies anybody, and a count of members is not a
member. Python 3.9+ standard library only.
"""
import argparse
import datetime
import json
import sys

SCHEMA_VERSION = "1"


def document(organizations, now=None):
    at = now or datetime.datetime.now(datetime.timezone.utc)
    return {"schema_version": SCHEMA_VERSION,
            "published": at.isoformat(timespec="seconds"),
            "organizations_reporting": int(organizations),
            "note": ("How many organizations reported in the period these alerts cover. "
                     "Published so a count can be read as a share. Identifies nobody.")}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--organizations", type=int, required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if a.organizations < 1:
        print("guardian: a network with no organizations has nothing to publish",
              file=sys.stderr)
        return 1
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(document(a.organizations), f, indent=2, sort_keys=True)
        f.write("\n")
    print("published: %d organizations reporting" % a.organizations)
    return 0


if __name__ == "__main__":
    sys.exit(main())
