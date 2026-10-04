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

# Built from codepoints on purpose. Writing the characters themselves would put the very
# bytes this check exists to forbid into the file doing the forbidding.
INVISIBLE = {
    0x200B: "U+200B ZERO WIDTH SPACE",
    0x200C: "U+200C ZERO WIDTH NON-JOINER",
    0x200D: "U+200D ZERO WIDTH JOINER",
    0x2060: "U+2060 WORD JOINER",
    0xFEFF: "U+FEFF ZERO WIDTH NO-BREAK SPACE",
    0x202A: "U+202A LEFT-TO-RIGHT EMBEDDING",
    0x202B: "U+202B RIGHT-TO-LEFT EMBEDDING",
    0x202D: "U+202D LEFT-TO-RIGHT OVERRIDE",
    0x202E: "U+202E RIGHT-TO-LEFT OVERRIDE",
    0x2066: "U+2066 LEFT-TO-RIGHT ISOLATE",
    0x2067: "U+2067 RIGHT-TO-LEFT ISOLATE",
    0x2068: "U+2068 FIRST STRONG ISOLATE",
    0x2069: "U+2069 POP DIRECTIONAL ISOLATE",
}
TAG_CHARACTERS = re.compile("[%s-%s]" % (chr(0xE0000), chr(0xE007F)))
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
    for codepoint, name in INVISIBLE.items():
        character = chr(codepoint)
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
