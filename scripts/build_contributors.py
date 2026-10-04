#!/usr/bin/env python3
"""Build contributors.json from the repository, so credit is never maintained by hand.

    python3 scripts/build_contributors.py [--out contributors.json] [--ref main]

Three sources, joined on email and on name:

  * `Signed-off-by` lines in the git history. Everyone who contributed signed off, so this
    is the record of who did and when they first did.
  * `CONTRIBUTORS.md`, which is the opt-in: display name, GitHub handle, organization, and
    whether the organization may be listed.
  * `credits` in the pattern files, which names pattern authors and their organizations.

People and organizations come out ordered by the date of their first contribution, so the
list reads as a history rather than a ranking. An organization appears only when someone
opted it in, and the list is labelled "Contributing organizations", never "partners": being
listed says someone contributed, not that anyone endorses anything.
"""
import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scanner"))

SIGNOFF = re.compile(r"^Signed-off-by:\s*(.+?)\s*<([^>]+)>\s*$", re.I | re.M)
HANDLE = re.compile(r"\[@([A-Za-z0-9-]+)\]")
# Affiliations that name no real organization. "Founding maintainer" is a role.
NOT_AN_ORGANIZATION = {"founding maintainer", "individual", "none", "independent", "-", "",
                       "your organization"}
# Template text someone forgot to replace. Not a person, so not a contributor.
PLACEHOLDER_NAMES = {"your name"}


def _git(args):
    return subprocess.run(["git"] + args, cwd=ROOT, capture_output=True, text=True).stdout


def from_history(ref="HEAD"):
    """Each signer, with the date they first signed off. Oldest commit first."""
    raw = _git(["log", "--reverse", "--no-merges", "--date=short",
                "--format=%x01%cd%x02%B%x03", ref])
    people = {}
    for entry in raw.split("\x01"):
        if "\x02" not in entry:
            continue
        date, _, body = entry.partition("\x02")
        body = body.split("\x03")[0]
        for name, email in SIGNOFF.findall(body):
            key = email.strip().lower()
            if key not in people:
                people[key] = {"name": name.strip(), "email": key, "first": date.strip()}
    return people


def from_contributors_file(path=None):
    """The opt-in table. Returns rows keyed by lowercased display name."""
    path = path or os.path.join(ROOT, "CONTRIBUTORS.md")
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return {}
    rows = {}
    for line in lines:
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or cells[0].lower() in ("name", "") or set(cells[0]) <= set("- "):
            continue
        handles = HANDLE.findall(cells[1])
        organization = cells[2]
        rows[cells[0].lower()] = {
            "name": cells[0],
            "github": handles[0] if handles else None,
            "organization": None if organization.lower() in NOT_AN_ORGANIZATION else organization,
        }
    return rows


def from_patterns(folder=None):
    """Pattern authors, with the pattern ids they are credited on."""
    from guardian_scanner import patterns as validator
    report = validator.validate_dir(folder or os.path.join(ROOT, "patterns"))
    out = {}
    for pattern_id, doc in sorted(report.patterns.items()):
        for entry in doc.get("credits") or []:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            if not name or name.lower() in PLACEHOLDER_NAMES:
                continue
            row = out.setdefault(name.lower(), {"name": name, "organization": None, "patterns": []})
            row["patterns"].append(pattern_id)
            organization = str(entry.get("organization") or "").strip()
            if organization and organization.lower() not in NOT_AN_ORGANIZATION:
                row["organization"] = organization
    return out


def build(ref="HEAD"):
    history = from_history(ref)
    opted_in = from_contributors_file()
    credited = from_patterns()

    people = []
    by_name = {}
    for row in sorted(history.values(), key=lambda r: (r["first"], r["name"].lower())):
        person = {"name": row["name"], "first_contribution": row["first"],
                  "github": None, "organization": None, "patterns": []}
        extra = opted_in.get(row["name"].lower())
        if extra:
            person["github"] = extra["github"]
            person["organization"] = extra["organization"]
        pattern_row = credited.get(row["name"].lower())
        if pattern_row:
            person["patterns"] = sorted(pattern_row["patterns"])
            if not person["organization"] and pattern_row["organization"]:
                person["organization"] = pattern_row["organization"]
        people.append(person)
        by_name[row["name"].lower()] = person

    # Anyone credited on a pattern but not in the history yet, for example a pattern
    # contributed on someone else's behalf.
    for key, row in sorted(credited.items()):
        if key in by_name:
            continue
        people.append({"name": row["name"], "first_contribution": None, "github": None,
                       "organization": row["organization"], "patterns": sorted(row["patterns"])})

    organizations = []
    seen = set()
    for person in people:
        organization = person["organization"]
        if organization and organization.lower() not in seen:
            seen.add(organization.lower())
            organizations.append({"name": organization,
                                  "first_contribution": person["first_contribution"]})

    return {
        "generated_from": "git history, CONTRIBUTORS.md and pattern credits",
        "note": ("Ordered by first contribution. Organizations are listed only where a "
                 "contributor opted in. Contributing organizations, not partners: being "
                 "listed says someone contributed, not that anyone endorses anything."),
        "people": people,
        "organizations": organizations,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=os.path.join(ROOT, "contributors.json"))
    ap.add_argument("--ref", default="HEAD")
    ap.add_argument("--print", action="store_true", help="write to stdout instead of a file")
    args = ap.parse_args(argv)
    data = build(args.ref)
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if args.print:
        sys.stdout.write(text)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"Wrote {os.path.relpath(args.out, ROOT)}: "
              f"{len(data['people'])} people, {len(data['organizations'])} organizations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
