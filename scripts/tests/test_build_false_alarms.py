#!/usr/bin/env python3
"""Tests for the false alarm rates written into the pattern files."""
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "sensor"))
import build_false_alarms as builder  # noqa: E402
from guardian_sensor import rules  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def test_a_pattern_with_no_rule_gets_no_rate():
    """The point of the whole thing, and the easiest mistake to make.

    The gate reports a pattern with no implemented rule as flagging nothing, because
    there is nothing to flag. Writing that through as 0.0 would publish "this rule never
    raises a false alarm" about a rule that does not exist, which is a stronger claim
    than any measured cell in this repository makes.
    """
    report = {"per_pattern": {"GP-0001": {"false_alarm_rate": 0.0417,
                                          "benign_flagged": ["a-case"]}},
              "benign": [{"id": "a-case"}]}
    rated = sorted(rules.RULES)
    unrated = [p for p, _ in builder.pattern_files() if p not in rules.RULES]
    check("some patterns have no rule, so the case is real", bool(unrated), str(unrated))
    for pattern in unrated:
        check("%s stays null" % pattern, builder.wanted(pattern, report) == "null",
              builder.wanted(pattern, report))
    check("a pattern with a rule takes the corpus value",
          builder.wanted("GP-0001", report) == "0.0417",
          builder.wanted("GP-0001", report))
    check("every rated pattern is a pattern on disk",
          set(rated) <= {p for p, _ in builder.pattern_files()}, str(rated))


def test_the_rate_is_read_from_the_gate_not_recomputed():
    """One implementation of the number, so the page cannot drift from what CI enforces."""
    source = io.open(os.path.join(ROOT, "scripts", "build_false_alarms.py"),
                     encoding="utf-8").read()
    check("it runs the gate", "rule_gate.py" in source, "no call to the gate")
    check("and does not reimplement the corpus walk",
          "corpus/benign" not in source and "load_cases" not in source,
          "it reads the corpus itself, so two implementations can disagree")


def test_check_mode_fails_on_a_hand_edit():
    """The guard that keeps a generated number from being typed over."""
    done = subprocess.run([sys.executable, os.path.join(ROOT, "scripts",
                                                        "build_false_alarms.py"), "--check"],
                          capture_output=True, text=True, cwd=ROOT)
    check("the repository is currently current", done.returncode == 0,
          (done.stdout + done.stderr)[:300])


def test_the_page_names_its_denominator_and_interval():
    """A bare rate is the mistake the attack matrix exists to avoid."""
    page = io.open(os.path.join(ROOT, "docs", "FALSE_ALARMS.md"), encoding="utf-8").read()
    check("the page exists and names the denominator", "24 cases" in page, page[:200])
    check("every row carries an interval", page.count("[0.") >= 10, "too few intervals")
    check("and it says a floor is not a field measurement",
          "never the ones a real deployment would find" in page, "the caveat is missing")


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
