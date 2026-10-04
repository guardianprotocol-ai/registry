#!/usr/bin/env python3
"""Only maintainers may add a non-draft pattern or change a pattern's status.

    python3 scripts/check_status_changes.py <base> <head> <pull-request-author>

Contributors add patterns as `draft`. Moving one to `verified` or `enforced` is a
maintainer's decision and belongs in its own pull request, so that promoting a pattern is
never a side effect of writing one.

The author is passed in by the workflow from the pull request event. It is never read from
the pull request's own files, because those files are written by the person being checked.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAINTAINERS = os.path.join(ROOT, "MAINTAINERS.md")
PATTERN_PATH = re.compile(r"^patterns/GP-\d{4}\.yaml$")
STATUS_LINE = re.compile(r"^status:\s*(\S+)", re.M)
# A row of the maintainers table: the handle is a link whose text is @name.
HANDLE = re.compile(r"\[@([A-Za-z0-9-]+)\]")


def maintainers(path=None):
    """GitHub handles in the Maintainers table of MAINTAINERS.md.

    Only that table. Reviewers approve, they do not promote, so a reviewer listed further
    down the same file must not pass this check.
    """
    try:
        with open(path or MAINTAINERS, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return set()
    section = text.split("## Maintainers", 1)
    if len(section) < 2:
        return set()
    body = section[1]
    # Stop at the next heading of the same level, so the Reviewers table is excluded.
    body = re.split(r"\n## ", body, 1)[0]
    found = set()
    for line in body.splitlines():
        if line.strip().startswith("|"):
            found.update(m.lower() for m in HANDLE.findall(line))
    return found


def _git(args):
    return subprocess.run(["git"] + args, cwd=ROOT, capture_output=True, text=True).stdout


def changed_patterns(base, head):
    out = _git(["diff", "--name-status", f"{base}...{head}"])
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        state, path = parts[0], parts[-1]
        if PATTERN_PATH.match(path):
            yield state[0], path


def status_in(ref, path):
    text = _git(["show", f"{ref}:{path}"])
    match = STATUS_LINE.search(text)
    return match.group(1) if match else None


def findings(base, head):
    """What this change does to pattern statuses."""
    out = []
    for state, path in changed_patterns(base, head):
        after = status_in(head, path)
        if state == "A":
            if after and after != "draft":
                out.append(f"{path} is added with status '{after}'. New patterns start as draft.")
        elif state == "M":
            before = status_in(base, path)
            if before and after and before != after:
                out.append(f"{path} changes status from '{before}' to '{after}'.")
    return out


def main(argv):
    if len(argv) != 4:
        print(__doc__.strip())
        return 2
    base, head, author = argv[1], argv[2], argv[3].strip().lstrip("@").lower()
    problems = findings(base, head)
    if not problems:
        print("No pattern status changes in this pull request.")
        return 0
    allowed = maintainers()
    if author in allowed:
        print(f"Status changes by maintainer @{author}:")
        for p in problems:
            print(f"  {p}")
        return 0
    print(f"@{author} is not listed as a maintainer in MAINTAINERS.md, so this pull request "
          "cannot change a pattern's status:\n")
    for p in problems:
        print(f"  {p}")
    print("\nContributors add patterns as draft. A maintainer promotes them in a separate")
    print("pull request, once the scan has measured the pattern. See GOVERNANCE.md.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
