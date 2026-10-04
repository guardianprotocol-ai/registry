#!/usr/bin/env python3
"""What landed on main since a date, ready to paste into Slack.

    python3 scripts/shipped.py --since 2026-09-29

Git history only, so it needs no token and works offline. Use it before each working group
meeting: the people named are the ones who demo.
"""
import argparse
import collections
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATTERN_PATH = re.compile(r"^patterns/(GP-\d{4})\.yaml$")
SIGNOFF = re.compile(r"^Signed-off-by:\s*(.+?)\s*<", re.I | re.M)
SEPARATOR = "\x01"


DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def normalise(since):
    """Pin a bare date to the start of that day.

    `git log --since=2026-10-04` returns nothing on 2026-10-04, even when commits landed
    that day, while `--since="2026-10-04 00:00"` returns them all. Left alone that reports
    an empty week to a meeting that had a busy one.
    """
    return f"{since} 00:00:00" if DATE_ONLY.match(since.strip()) else since


def _git(args):
    return subprocess.run(["git"] + args, cwd=ROOT, capture_output=True, text=True).stdout


def commits(since, ref="HEAD"):
    """Each commit since the date: hash, date, subject, author, and the files it touched."""
    raw = _git(["log", f"--since={normalise(since)}", "--no-merges", "--date=short", "--name-only",
                f"--format={SEPARATOR}%h%x02%cd%x02%s%x02%an%x02%B%x03", ref])
    out = []
    for entry in raw.split(SEPARATOR):
        if "\x02" not in entry:
            continue
        head, _, rest = entry.partition("\x03")
        parts = head.split("\x02")
        if len(parts) < 5:
            continue
        sha, date, subject, author, body = parts[0], parts[1], parts[2], parts[3], parts[4]
        signers = [n.strip() for n in SIGNOFF.findall(body)]
        files = [line.strip() for line in rest.splitlines() if line.strip()]
        out.append({"sha": sha, "date": date, "subject": subject,
                    "author": signers[0] if signers else author, "files": files})
    out.reverse()          # oldest first, so the list reads forwards
    return out


def patterns_touched(entries, since, ref="HEAD"):
    added, changed = set(), set()
    for entry in entries:
        for path in entry["files"]:
            match = PATTERN_PATH.match(path)
            if match:
                changed.add(match.group(1))
    # Added means added inside the window. Without the date bound every pattern the
    # repository has ever had would be reported as new at every meeting.
    for pattern_id in sorted(changed):
        path = f"patterns/{pattern_id}.yaml"
        first = _git(["log", f"--since={normalise(since)}", "--diff-filter=A", "--format=%h",
                      ref, "--", path]).split()
        if first:
            added.add(pattern_id)
    return sorted(added), sorted(changed)


def markdown(entries, since, ref="HEAD"):
    if not entries:
        return f"Nothing has landed on main since {since}.\n"
    lines = [f"## Shipped since {since}", ""]
    by_author = collections.OrderedDict()
    for entry in entries:
        by_author.setdefault(entry["author"], []).append(entry)
    for author, items in by_author.items():
        lines.append(f"**{author}**")
        for entry in items:
            lines.append(f"- {entry['subject']} (`{entry['sha']}`, {entry['date']})")
        lines.append("")
    added, changed = patterns_touched(entries, since, ref)
    only_changed = [p for p in changed if p not in added]
    if added:
        lines.append(f"**Patterns added:** {', '.join(added)}")
    if only_changed:
        lines.append(f"**Patterns changed:** {', '.join(only_changed)}")
    if added or only_changed:
        lines.append("")
    people = len(by_author)
    lines.append(f"{len(entries)} change{'' if len(entries) == 1 else 's'} from {people} "
                 f"{'person' if people == 1 else 'people'}. "
                 f"{'They demo' if people == 1 else 'Those people demo'}.")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--since", required=True, help="a date, for example 2026-09-29")
    ap.add_argument("--ref", default="HEAD")
    args = ap.parse_args(argv)
    sys.stdout.write(markdown(commits(args.since, args.ref), args.since, args.ref))
    return 0


if __name__ == "__main__":
    sys.exit(main())
