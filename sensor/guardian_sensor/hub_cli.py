"""Command line for the sharing hub: `report` and `update`.

The logic lives in hub.py, which touches no network and no arguments, so the privacy
guarantee can be tested on its own. This file is the thin part: parsing, reading files and
fetching a release. Python 3.9+ standard library only.
"""
import argparse
import json
import os
import sys
import urllib.request

from . import hub

DEFAULT_UPDATES = ".guardian/updates.jsonl"
MANIFEST_NAME = "manifest.json"


def _fetch(url, opener=None):
    opener = opener or urllib.request.urlopen
    with opener(url, timeout=30) as response:
        return response.read()


def report(argv, out=sys.stdout):
    ap = argparse.ArgumentParser(prog="guardian_sensor report",
                                 description="Build an anonymized sightings file")
    ap.add_argument("--since", default=None, metavar="YYYY-MM-DD")
    ap.add_argument("--out", default=None, metavar="FILE")
    ap.add_argument("--preview", action="store_true",
                    help="print exactly what would be shared and write nothing")
    ap.add_argument("--org", default=os.environ.get("GUARDIAN_ORG"),
                    help="your pseudonymous member id, never a company name")
    ap.add_argument("--evidence", action="append", default=None,
                    help="evidence log to read; repeatable. Defaults to .guardian/evidence.jsonl")
    ap.add_argument("--rules-version", default=None)
    ap.add_argument("--updates", default=DEFAULT_UPDATES)
    a = ap.parse_args(argv)

    paths = a.evidence or list(hub.DEFAULT_EVIDENCE)
    rules_version = a.rules_version or hub.current_rules_version(a.updates) or "unrecorded"

    try:
        records = hub.read_evidence(paths, since=a.since)
        document = hub.build_sightings(records, a.org, rules_version)
    except hub.HubError as e:
        print(f"guardian: {e}", file=sys.stderr)
        return 1

    if a.preview or not a.out:
        print(hub.preview_text(document), file=out)
        if not a.out:
            print("\nNothing was written. Pass --out FILE to write it.", file=out)
            return 0
        print(f"\nNothing was written. Run again without --preview to write {a.out}.", file=out)
        return 0

    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {a.out} with {len(document['sightings'])} entr"
          f"{'y' if len(document['sightings']) == 1 else 'ies'}", file=out)
    print("Check it before sharing it: every value in it is listed by --preview.", file=out)
    return 0


def update(argv, opener=None, out=sys.stdout):
    ap = argparse.ArgumentParser(prog="guardian_sensor update",
                                 description="Fetch and verify the published rule set")
    ap.add_argument("--base", required=True,
                    help="base URL of the published release, holding manifest.json")
    ap.add_argument("--dest", default=".guardian/rules",
                    help="where to write the verified files")
    ap.add_argument("--updates", default=DEFAULT_UPDATES)
    ap.add_argument("--dry-run", action="store_true",
                    help="verify and report, but write nothing")
    a = ap.parse_args(argv)

    base = a.base.rstrip("/")
    try:
        manifest = json.loads(_fetch(f"{base}/{MANIFEST_NAME}", opener).decode("utf-8"))
    except hub.HubError:
        raise
    except Exception as e:
        print(f"guardian: could not fetch the manifest: {e}", file=sys.stderr)
        return 1

    names = sorted((manifest or {}).get("files", {}))
    files = {}
    try:
        for name in names:
            files[name] = _fetch(f"{base}/{name}", opener)
    except Exception as e:
        print(f"guardian: could not fetch {name}: {e}", file=sys.stderr)
        return 1

    try:
        rules_version = hub.verify_against_manifest(manifest, files)
    except hub.HubError as e:
        print(f"guardian: {e}", file=sys.stderr)
        return 1

    if a.dry_run:
        print(f"verified {len(files)} file(s) against the manifest, rules version "
              f"{rules_version}. Nothing was written.", file=out)
        return 0

    os.makedirs(a.dest, exist_ok=True)
    for name, data in sorted(files.items()):
        with open(os.path.join(a.dest, os.path.basename(name)), "wb") as f:
            f.write(data)
    hub.record_update(a.updates, rules_version, base)
    print(f"updated to rules version {rules_version}: {len(files)} file(s) in {a.dest}", file=out)
    print(f"recorded in {a.updates}", file=out)
    return 0


def main(argv):
    command, rest = argv[0], argv[1:]
    if command == "report":
        return report(rest)
    if command == "update":
        return update(rest)
    raise SystemExit(f"unknown command {command!r}")
