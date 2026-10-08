"""The invisible character check decides by Unicode category, not by a list.

A hand written list of codepoints is wrong the moment somebody reaches for a character
nobody thought of. The original list held thirteen and missed sixteen, including the
directional marks and the variation selectors, which are the vector in current
invisible-text encoding attacks. These tests pin the category behaviour so the check cannot
quietly narrow back to a list.

Run from the repository root:  python3 scripts/tests/test_check_invisible.py
"""
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import check_invisible  # noqa: E402

failures = []

# Written as codepoints, never as characters: this file is tracked, and the check forbids
# the raw bytes in any tracked file, including the tests for the check.
ONCE_LISTED = (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x202A, 0x202B, 0x202D, 0x202E,
               0x2066, 0x2067, 0x2068, 0x2069)
ONCE_MISSED = (0x200E, 0x200F, 0x202C, 0x061C, 0x00AD, 0x034F, 0x2061, 0x2062, 0x2063,
               0x2064, 0xFE00, 0xFE0F, 0x180E, 0x3164, 0xFFA0, 0x2800)
TAG_BLOCK = (0xE0001, 0xE0041, 0xE007F)
EM_DASH = 0x2014


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def flagged(text):
    folder = tempfile.mkdtemp()
    try:
        path = os.path.join(folder, "probe.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return check_invisible.problems_in(path)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_everything_the_old_list_held_is_still_caught():
    missed = [f"U+{cp:04X}" for cp in ONCE_LISTED if not flagged("a" + chr(cp) + "b\n")]
    check("every character the old list held is still caught", not missed, str(missed))


def test_the_characters_the_old_list_missed_are_caught():
    missed = [f"U+{cp:04X}" for cp in ONCE_MISSED if not flagged("a" + chr(cp) + "b\n")]
    check("the sixteen the old list missed are caught", not missed, str(missed))


def test_the_unicode_tag_block_is_caught():
    missed = [f"U+{cp:04X}" for cp in TAG_BLOCK if not flagged("a" + chr(cp) + "b\n")]
    check("the tag block is caught", not missed, str(missed))


def test_ordinary_whitespace_is_allowed():
    check("tabs, newlines and carriage returns pass",
          not flagged("one\ttwo\r\nthree\n"), str(flagged("one\ttwo\r\nthree\n")))


def test_visible_non_ascii_is_allowed():
    """The repository uses an arrow and a middle dot. Those are visible, so they are fine."""
    text = "an arrow \u2192 and a middle dot \u00b7\n"
    check("visible non-ascii passes", not flagged(text), str(flagged(text)))


def test_an_escaped_codepoint_is_allowed():
    """Writing the escape is the documented way to describe one of these characters."""
    check("the text of an escape passes", not flagged('payload = "\\u200b"\n'))


def test_a_live_em_dash_is_refused():
    found = flagged("a line with an em dash " + chr(EM_DASH) + " in it\n")
    check("a raw em dash is caught", bool(found), "not caught")
    check("the message says what to write instead",
          any("comma" in f for f in found), str(found))


def test_the_report_names_the_character_and_the_line():
    found = flagged("first line\nsecond line has one " + chr(0x200B) + "\n")
    check("the report gives the line number", any(":2:" in f for f in found), str(found))
    check("the report names the codepoint", any("U+200B" in f for f in found), str(found))


def test_the_repository_itself_is_clean():
    problems = []
    for path in check_invisible.tracked_files():
        problems.extend(check_invisible.problems_in(path))
    check("every tracked file is clean", not problems, "; ".join(problems[:3]))


def main():
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print()
    if failures:
        print(f"FAIL ({len(failures)}): {', '.join(failures)}")
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
