#!/usr/bin/env python3
"""Fail if any commit in a range lacks a Developer Certificate of Origin sign-off.

    python3 scripts/check_signoff.py <base> <head>

CONTRIBUTING.md, README.md and GOVERNANCE.md all require `git commit -s`, and nothing
checked it. Needs no third-party action: a sign-off is a trailer in the commit message, and
git can read it.

A sign-off has to name the commit's own author, so one commit cannot certify another
person's work. Merge commits are skipped: their parents carry the sign-offs.
"""
import re
import subprocess
import sys

TRAILER = re.compile(r"^Signed-off-by:\s*(.+?)\s*<([^>]+)>\s*$", re.I | re.M)


def commits(base, head):
    out = subprocess.run(["git", "rev-list", "--no-merges", f"{base}..{head}"],
                         capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines() if line]


def field(sha, fmt):
    return subprocess.run(["git", "show", "-s", f"--format={fmt}", sha],
                          capture_output=True, text=True, check=True).stdout.strip()


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip())
        return 2
    base, head = argv[1], argv[2]
    problems = []
    checked = 0
    for sha in commits(base, head):
        checked += 1
        author_email = field(sha, "%ae").lower()
        subject = field(sha, "%s")
        signoffs = [email.lower() for _, email in TRAILER.findall(field(sha, "%B"))]
        if not signoffs:
            problems.append(f"{sha[:8]} {subject}\n    no Signed-off-by trailer. Use: git commit -s")
        elif author_email not in signoffs:
            problems.append(
                f"{sha[:8]} {subject}\n    signed off by {', '.join(signoffs)}, "
                f"but authored by {author_email}. A sign-off must name the author.")
    if problems:
        print(f"{len(problems)} of {checked} commits are not signed off:\n")
        for p in problems:
            print(f"  {p}\n")
        print("Fix the last one with:  git commit --amend -s")
        print("Fix several with:       git rebase --signoff " + base)
        return 1
    print(f"All {checked} commits are signed off.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
