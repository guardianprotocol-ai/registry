"""How a participant wants to be credited in the research.

This is the only place in the sensor that holds a real name, and it is deliberately the only
place. Everything else uses a pseudonym the member chose, because a sighting that could be
traced to its reporter is not an anonymous sighting.

So the two never travel together. The pseudonym goes into sightings, which are shared. The
credit goes into a separate file, which the participant sends separately and only if they
want to be named. An operator holding both can join them; nobody else can, and the
participant decides whether an operator ever gets the second one.

Keeping them in one file would have been more convenient and would have quietly undone the
privacy argument the whole format rests on.

Python 3.9+ standard library only.
"""
import argparse
import json
import os
import re
import sys

SCHEMA_VERSION = 1
DEFAULT_PATH = os.path.join(".guardian", "credit.json")

# A GitHub handle, for attribution in a contributors list. Shape checked because this ends up
# in a published document and a typo there is somebody's name spelled wrong in print.
HANDLE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
MAX_NAME = 80
MAX_ORG = 80


class CreditError(Exception):
    pass


def build(name, handle=None, organization=None, acknowledge_only=False):
    """A credit record. Pure, so what it contains can be seen without running anything."""
    name = (name or "").strip()
    if not name:
        raise CreditError("a name is required. It is how you will appear in the research.")
    if len(name) > MAX_NAME:
        raise CreditError("a name may be at most %d characters" % MAX_NAME)
    handle = (handle or "").strip().lstrip("@")
    if handle and not HANDLE_RE.match(handle):
        raise CreditError(
            "%r is not a GitHub handle. Letters, digits and single hyphens, up to 39 "
            "characters." % handle)
    organization = (organization or "").strip()
    if len(organization) > MAX_ORG:
        raise CreditError("an organization may be at most %d characters" % MAX_ORG)

    return {"schema_version": SCHEMA_VERSION,
            "name": name,
            "github": handle,
            "organization": organization,
            # Authorship under docs/RESEARCH.md needs a substantive contribution, approval of
            # the final draft, and willingness to answer for the part you did. Somebody who
            # ran an exercise may want none of that, and acknowledgement is not a lesser
            # thing. Asked here rather than assumed, because assuming is how people end up
            # as authors of papers they never read.
            "acknowledge_only": bool(acknowledge_only)}


def load(path=DEFAULT_PATH):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save(record, path=DEFAULT_PATH):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


def main(argv=None, out=sys.stdout):
    ap = argparse.ArgumentParser(
        prog="guardian_sensor credit",
        description="Record how you want to be credited in the research. Kept apart from "
                    "your sightings on purpose.")
    ap.add_argument("--name", default=None, help="how you want to appear")
    ap.add_argument("--github", default=None, help="your GitHub handle, without the at sign")
    ap.add_argument("--organization", default="",
                    help="optional, and it is published, so use what you are happy to see")
    ap.add_argument("--acknowledge-only", action="store_true",
                    help="credit me in the acknowledgements rather than as an author")
    ap.add_argument("--file", default=DEFAULT_PATH)
    ap.add_argument("--show", action="store_true", help="print what is recorded and stop")
    ap.add_argument("--remove", action="store_true", help="forget it")
    a = ap.parse_args([] if argv is None else argv)

    if a.remove:
        try:
            os.remove(a.file)
            out.write("Removed. Nothing about you is recorded here now.\n")
        except OSError:
            out.write("Nothing was recorded.\n")
        return 0

    if a.show or not a.name:
        existing = load(a.file)
        if existing is None:
            out.write("Nothing recorded. To be credited in the research:\n\n")
            out.write("  python3 -m guardian_sensor credit --name \"Your Name\" "
                      "--github your-handle\n\n")
            out.write("This is optional, and it is kept in a separate file from your "
                      "sightings.\nYour sightings carry a pseudonym and never your name.\n")
            return 0 if a.show else 1
        out.write("Recorded in %s, and shared only if you send it:\n\n" % a.file)
        for key in ("name", "github", "organization"):
            if existing.get(key):
                out.write("  %-14s %s\n" % (key, existing[key]))
        out.write("  %-14s %s\n" % ("credit as",
                                    "acknowledgement" if existing.get("acknowledge_only")
                                    else "author, if the contribution is substantive"))
        return 0

    try:
        record = build(a.name, a.github, a.organization, a.acknowledge_only)
    except CreditError as e:
        out.write("Refused: %s\n" % e)
        return 1
    save(record, a.file)

    out.write("Recorded. This is the whole of it:\n\n")
    out.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
    out.write("\nIt is in %s and goes nowhere on its own. Send it when you are ready to be\n"
              "credited, separately from your sightings.\n" % a.file)
    out.write("\nYour sightings carry the pseudonym you chose and never your name, which is "
              "why these\nare two files rather than one.\n")
    if not record["acknowledge_only"]:
        out.write("\nAuthorship needs a substantive contribution, approval of the final "
                  "draft, and being\nwilling to answer for your part. Pass "
                  "--acknowledge-only if you would rather be thanked\nthan listed.\n")
    return 0
