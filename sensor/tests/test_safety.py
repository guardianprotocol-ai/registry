"""Tests for the check that decides whether a rule bundle is safe to run.

A manifest proves a bundle arrived from the publisher unaltered. It says nothing about
what the patterns do. The sensor runs them against every tool call, so one pattern that
backtracks catastrophically does not slow a member down, it stops them, and stops every
member who adopted the same bundle. One such pattern measured while writing this ran for
over ten minutes against thirty three characters.

Run from the sensor folder:  python3 tests/test_safety.py
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from guardian_sensor import rules, safety  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + str(detail)}")
    if not condition:
        failures.append(name)


def refuses(name, pattern):
    try:
        safety.check_pattern(pattern)
        check(name, False, "it was accepted")
    except safety.Unsafe:
        check(name, True)


def test_the_bundle_this_project_ships_is_safe():
    """The check is worthless if it refuses our own rules, and it would be switched off.

    This is also the guard on anything added to signatures.json later.
    """
    with open(rules.INSTALLED_SIGNATURES, encoding="utf-8") as f:
        document = json.load(f)
    started = time.time()
    try:
        count = safety.check_signatures(document)
        check("every shipped pattern is safe", count > 0, count)
    except safety.Unsafe as e:
        check("every shipped pattern is safe", False, e)
    check("and checking them is quick enough to do on every update",
          time.time() - started < 5.0, f"{time.time() - started:.2f}s")


def test_catastrophic_patterns_are_refused():
    refuses("a quantifier inside a quantifier", r"(a+)+$")
    refuses("alternation of the same thing", r"(a|a)*$")
    refuses("a word and optional space, repeated", r"(\w+\s?)+$")
    refuses("a star over a plus", r"([a-zA-Z]+)*$")


def test_a_bundle_with_no_patterns_is_refused():
    """Adopting it would replace a working rule set with one that matches nothing, and
    report success. A sensor that detects nothing is worse than no sensor, because
    somebody is relying on it."""
    try:
        safety.check_signatures({})
        check("an empty bundle is refused", False, "it was accepted")
    except safety.Unsafe as e:
        check("an empty bundle is refused", True, e)


def test_a_pattern_that_does_not_compile_is_refused():
    refuses("an unclosed group", r"(unclosed")


def test_one_bad_pattern_fails_the_whole_bundle():
    """A partly adopted rule set is a state nobody can describe."""
    document = {"instruction": [{"id": "fine", "pattern": "send notes"},
                                {"id": "bad", "pattern": r"(a+)+$"}]}
    try:
        safety.check_signatures(document)
        check("a bundle with one bad pattern is refused", False, "it was accepted")
    except safety.Unsafe as e:
        check("a bundle with one bad pattern is refused", True, e)


def test_patterns_are_found_wherever_they_are_nested():
    """signatures.json nests patterns under several keys and inside lists. A check that
    only looked at the top level would pass a bundle whose dangerous pattern was one
    level down."""
    document = {"hidden": {"zero_width": {"pattern": r"(a+)+$"}}}
    try:
        safety.check_signatures(document)
        check("a nested pattern is still checked", False, "it was accepted")
    except safety.Unsafe:
        check("a nested pattern is still checked", True)


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
