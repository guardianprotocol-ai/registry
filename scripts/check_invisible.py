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

# Decided by Unicode category rather than by a list of codepoints. A hand written list is
# wrong the moment someone reaches for a character nobody thought of: this one missed the
# directional marks, the invisible maths operators, the soft hyphen and the variation
# selectors, which are the vector in current invisible-text encoding attacks.
#
# Cf is the format category, which covers the zero-width characters, every bidirectional
# control, the Arabic letter mark, the soft hyphen and the Unicode tag block. Cc is the
# control characters, with the three whitespace ones every text file needs allowed through.
INVISIBLE_CATEGORIES = ("Cf", "Cc")
ALLOWED_CONTROLS = ("\t", "\n", "\r")

# Invisible but not Cf, so named individually. Written as codepoints on purpose: putting the
# characters themselves here would place the very bytes this check forbids into the file
# doing the forbidding.
ALSO_INVISIBLE = {
    0x034F: "U+034F COMBINING GRAPHEME JOINER",
    0x2800: "U+2800 BRAILLE PATTERN BLANK",
    0x3164: "U+3164 HANGUL FILLER",
    0xFFA0: "U+FFA0 HALFWIDTH HANGUL FILLER",
    0x115F: "U+115F HANGUL CHOSEONG FILLER",
    0x1160: "U+1160 HANGUL JUNGSEONG FILLER",
}
VARIATION_SELECTORS = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))

# The project's own rule is no em dashes anywhere. It was enforced only for generated
# Season 1 issues, so it is checked here across every tracked file instead.
EM_DASHES = {0x2014: "U+2014 EM DASH", 0x2015: "U+2015 HORIZONTAL BAR"}

BINARY = (".png", ".ico", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".woff", ".woff2")


def describe(character):
    """A name for the report, without importing a table of our own."""
    import unicodedata
    try:
        return "U+%04X %s" % (ord(character), unicodedata.name(character))
    except ValueError:
        return "U+%04X unnamed" % ord(character)


def is_invisible(character):
    import unicodedata
    codepoint = ord(character)
    if character in ALLOWED_CONTROLS:
        return False
    if codepoint in ALSO_INVISIBLE:
        return True
    if any(low <= codepoint <= high for low, high in VARIATION_SELECTORS):
        return True
    return unicodedata.category(character) in INVISIBLE_CATEGORIES


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
    reported = set()
    for index, character in enumerate(text):
        if ord(character) < 128 or character in reported:
            continue
        codepoint = ord(character)
        if is_invisible(character):
            reported.add(character)
            line = text[:index].count("\n") + 1
            found.append(f"{path}:{line}: live {ALSO_INVISIBLE.get(codepoint) or describe(character)}"
                         ". Write it as an escape instead.")
        elif codepoint in EM_DASHES:
            reported.add(character)
            line = text[:index].count("\n") + 1
            found.append(f"{path}:{line}: live {EM_DASHES[codepoint]}. The project uses none: "
                         "write a comma, a colon or a full stop, or an escape if the character "
                         "itself is the subject.")
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
