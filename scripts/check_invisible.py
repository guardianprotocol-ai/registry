#!/usr/bin/env python3
"""No tracked text file may contain live invisible characters.

    python3 scripts/check_invisible.py

The registry describes attacks that hide text from a human reader: zero-width characters,
Unicode tag characters, bidirectional overrides. Describing them is the job. Shipping the
real bytes is not: anyone copying that line out of the repository gets a working primitive,
and the project's own rule is that payloads stay harmless.

Write them as escapes instead (`\\u200b`), which every test and corpus case already does
except where this check was added to catch.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INVISIBLE = {
    "​": "U+200B ZERO WIDTH SPACE",
    "‌": "U+200C ZERO WIDTH NON-JOINER",
    "‍": "U+200D ZERO WIDTH JOINER",
    "⁠": "U+2060 WORD JOINER",
    "﻿": "U+FEFF ZERO WIDTH NO-BREAK SPACE",
    "‪": "U+202A LEFT-TO-RIGHT EMBEDDING",
    "‫": "U+202B RIGHT-TO-LEFT EMBEDDING",
    "‭": "U+202D LEFT-TO-RIGHT OVERRIDE",
    "‮": "U+202E RIGHT-TO-LEFT OVERRIDE",
    "⁦": "U+2066 LEFT-TO-RIGHT ISOLATE",
    "⁧": "U+2067 RIGHT-TO-LEFT ISOLATE",
    "⁨": "U+2068 FIRST STRONG ISOLATE",
    "⁩": "U+2069 POP DIRECTIONAL ISOLATE",
}
TAG_CHARACTERS = re.compile(r"[\U000E0000-\U000E007F]")
BINARY = (".png", ".ico", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".woff", ".woff2")


def tracked_files():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True)
    return [f for f in out.stdout.splitlines() if f and not f.lower().endswith(BINARY)]


def problems_in(path):
    full = os.path.join(ROOT, path)
    try:
        with open(full, encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError):
        return []
    found = []
    for character, name in INVISIBLE.items():
        if character in text:
            line = text[:text.index(character)].count("\n") + 1
            found.append(f"{path}:{line}: live {name}. Write it as an escape instead.")
    match = TAG_CHARACTERS.search(text)
    if match:
        line = text[:match.start()].count("\n") + 1
        found.append(f"{path}:{line}: live Unicode tag characters. Write them as escapes instead.")
    return found


def main():
    problems = []
    files = tracked_files()
    for path in files:
        problems += problems_in(path)
    if problems:
        print(f"{len(problems)} file(s) carry invisible characters as real bytes:\n")
        for p in problems:
            print(f"  {p}")
        return 1
    print(f"Checked {len(files)} tracked text files: no live invisible characters.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
