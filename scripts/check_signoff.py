#!/usr/bin/env python3
"""Fail if any commit in a range lacks a Developer Certificate of Origin sign-off.

    python3 scripts/check_signoff.py <base> <head>

CONTRIBUTING.md, README.md and GOVERNANCE.md all require `git commit -s`, and nothing
checked it. Needs no third-party action: a sign-off is a trailer in the commit message, and
git can read it.

A sign-off has to name the commit's own author, so one commit cannot certify another
person's work. Merge commits are skipped: their parents carry the sign-offs.

Automated authors are skipped too. The DCO is a statement a person makes about their
right to contribute the code, and a dependency bump opened by a bot has no person to make
it. Signing it on the bot's behalf would be a human certifying work they did not write
and did not review line by line, which is worse than saying plainly that nobody did.
Responsibility for a bot's change sits with the maintainer who merges it, the same as any
other review. The check still runs on every human commit, which is what the DCO is for.
"""
import re
import subprocess
import sys

TRAILER = re.compile(r"^Signed-off-by:\s*(.+?)\s*<([^>]+)>\s*$", re.I | re.M)

# Matched against the author's email. Narrow on purpose: it names the automation this
# repository actually uses rather than anything with "bot" in the address, because a
# person called Abbot should not be exempt from certifying their own work.
BOT_AUTHORS = (
    "dependabot[bot]@users.noreply.github.com",
    "49699333+dependabot[bot]@users.noreply.github.com",
    "actions@github.com",
    "github-actions[bot]@users.noreply.github.com",
)


def is_a_bot(email):
    return email.lower() in BOT_AUTHORS


def commits(base, head):
    result = subprocess.run(["git", "rev-list", "--no-merges", f"{base}..{head}"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise LookupError(f"cannot compare {base}..{head}: "
                          f"{result.stderr.strip().splitlines()[0] if result.stderr.strip() else 'unknown ref'}")
    return [line for line in result.stdout.splitlines() if line]


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
    skipped = []
    try:
        to_check = commits(base, head)
    except LookupError as failure:
        print(failure)
        return 2
    for sha in to_check:
        author_email = field(sha, "%ae").lower()
        subject = field(sha, "%s")
        if is_a_bot(author_email):
            skipped.append(f"{sha[:8]} {subject} (authored by {author_email})")
            continue
        # Counted after the skip, so "all N commits are signed off" never includes one
        # that nobody certified.
        checked += 1
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
    for entry in skipped:
        # Said out loud rather than passed over silently, so a reader of the log can see
        # which commits nobody certified and who merged them.
        print(f"Not certified by a person, which automation cannot do: {entry}")
    if checked:
        print(f"All {checked} commits are signed off.")
    else:
        # "All 0 commits are signed off" is a pass that checked nothing, which is the one
        # sentence this project will not print.
        print("No commits by a person in this range, so there was nothing to certify.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
