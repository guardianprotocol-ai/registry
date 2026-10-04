#!/usr/bin/env python3
"""Every relative link in the docs points at a file that exists, and every command shown
in START_HERE.md refers to a script that exists.

    python3 scripts/check_docs.py

Docs are the single source of truth here, including for the website, which links to them
rather than copying them. A link that rots is a contributor who gets stuck, so it fails the
build rather than waiting for someone to notice.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".github/ISSUE_TEMPLATE"}
LINK = re.compile(r"\[[^\]]*\]\(\s*<?([^)>]+?)>?\s*(?:\"[^\"]*\")?\s*\)")
# A command a contributor is told to run.
COMMAND = re.compile(r"python3\s+((?:check\.py|scripts/[\w./-]+))")
SUBCOMMANDS = {"new-pattern"}


def markdown_files():
    for folder, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".git")]
        for name in sorted(files):
            if name.endswith(".md"):
                yield os.path.join(folder, name)


def link_problems(path):
    out = []
    with open(path, encoding="utf-8") as f:
        text = f.read()
    here = os.path.dirname(path)
    for target in LINK.findall(text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        # Strip an anchor: the file has to exist, the heading is not checked.
        target = target.split("#", 1)[0]
        if not target:
            continue
        resolved = os.path.normpath(os.path.join(here, target))
        if not os.path.exists(resolved):
            out.append(f"{os.path.relpath(path, ROOT)}: link to {target} does not exist")
    return out


def command_problems(path):
    out = []
    with open(path, encoding="utf-8") as f:
        text = f.read()
    for script in COMMAND.findall(text):
        resolved = os.path.join(ROOT, script)
        if not os.path.exists(resolved):
            out.append(f"{os.path.relpath(path, ROOT)}: `python3 {script}` refers to a "
                       f"script that does not exist")
    return out


def main():
    problems = []
    checked = 0
    for path in markdown_files():
        checked += 1
        problems += link_problems(path)
        problems += command_problems(path)
    if problems:
        print(f"{len(problems)} problem(s) in the docs:\n")
        for p in problems:
            print(f"  {p}")
        return 1
    print(f"Checked {checked} Markdown files: every relative link and every "
          f"`python3 check.py` or `python3 scripts/` command points at a file that exists. "
          f"Anchors within a page are not checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
