#!/usr/bin/env python3
"""Does this diff add a pattern that maps to no ATLAS technique?

    python3 scripts/detect_custom_mapping.py <diff-file>

Prints `yes` or `no`. Used by the labeler workflow to apply `custom-mapping`, which the
path based labeler cannot decide: whether a mapping is custom depends on what the file
says, not on its name.

The diff is read as text and never executed. An empty `custom_reason` does not count: the
validator rejects it anyway, so labelling it would be noise.
"""
import re
import sys

# An added line, a custom_reason key, and something other than whitespace or an empty
# string after the colon.
ADDS_CUSTOM_REASON = re.compile(r'^\+\s*custom_reason:\s*(?:"\s*"|\'\s*\'|)\s*$', re.M)
ADDED_LINE = re.compile(r'^\+\s*custom_reason:\s*(.*)$', re.M)


def adds_custom_mapping(diff_text):
    for value in ADDED_LINE.findall(diff_text or ""):
        stripped = value.split("#")[0].strip().strip('"').strip("'").strip()
        if stripped:
            return True
    return False


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip())
        return 2
    try:
        with open(argv[1], encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        text = ""
    print("yes" if adds_custom_mapping(text) else "no")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
