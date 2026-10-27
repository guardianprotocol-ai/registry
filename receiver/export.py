#!/usr/bin/env python3
"""Write what the receiver has collected into the folder the aggregator reads.

    python3 receiver/export.py --out trial/sightings

The aggregator and the alert publisher are standard library only and live in the public
repository on purpose: the code that decides what is safe to publish should be readable by
the people whose data it is. Putting a database client inside them would end that, so the
database stops here. This exports, and everything downstream reads files.

That also means the published alerts can be reproduced by anybody holding the exported
folder, without access to our infrastructure, which is the property that lets somebody
check our arithmetic instead of trusting it.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import validate  # noqa: E402


def read_all(client, collection="sightings"):
    """Every stored sighting, grouped by the member that reported it."""
    by_org = {}
    for document in client.collection(collection).stream():
        entry = document.to_dict()
        org = entry.get("org")
        if not org:
            continue
        by_org.setdefault(org, []).append(entry)
    return by_org


def write(by_org, out):
    """One file per member, in the folder shape the aggregator expects.

    Each file is checked on the way out. The receiver checked it on the way in, but a
    store can be written to by more than the thing that was supposed to write it, and an
    aggregate is only as trustworthy as the worst record in it.
    """
    written = 0
    for org, entries in sorted(by_org.items()):
        # Only the eight fields. A stored row also carries the receiver's own
        # bookkeeping, the expiry that drives retention, and that is not a sighting:
        # handing it to the validator refused the whole export, which is correct of the
        # validator and was the export's mistake.
        #
        # Projecting rather than deleting known extras, so a field added to storage
        # later cannot leak into an exported document by nobody remembering this.
        clean = [{f: e[f] for f in validate.ALLOWED_FIELDS if f in e} for e in entries]
        document = {"schema_version": "0.2", "org": org,
                    "sightings": sorted(clean, key=validate.key_for)}
        validate.check_document(document)
        folder = os.path.join(out, org)
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "sightings.json"), "w", encoding="utf-8") as f:
            json.dump(document, f, indent=2, sort_keys=True)
            f.write("\n")
        written += 1
    return written


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, help="folder to write <org>/sightings.json into")
    ap.add_argument("--project", default=os.environ.get("GUARDIAN_PROJECT",
                                                        "guardian-protocol-site"))
    ap.add_argument("--collection", default="sightings")
    a = ap.parse_args(argv)

    from google.cloud import firestore
    by_org = read_all(firestore.Client(project=a.project), a.collection)
    count = write(by_org, a.out)
    total = sum(len(v) for v in by_org.values())
    print("exported %d sighting%s from %d organization%s into %s"
          % (total, "" if total == 1 else "s", count, "" if count == 1 else "s", a.out))
    # The number that decides whether anything can be published at all, said out loud, so
    # running this never leaves somebody guessing why the alerts file came back empty.
    print("the threshold for publishing a pattern is %d organizations" % validate.MIN_ORGS
          if hasattr(validate, "MIN_ORGS") else
          "patterns below the aggregator's threshold will be withheld")
    return 0


if __name__ == "__main__":
    sys.exit(main())
