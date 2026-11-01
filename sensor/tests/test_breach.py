"""What the watcher catches, against the claims in breach_probe.

Run from the sensor folder:  python3 tests/test_breach.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from guardian_sensor import breach_probe  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print("%s %s%s" % ("ok  " if condition else "FAIL", name, "" if condition else "  <- " + detail))
    if not condition:
        failures.append(name)


def test_probes_match_the_claims():
    problems = breach_probe.expectations_hold(breach_probe.run())
    check("every probe matches its claim", not problems, "; ".join(problems))


def main():
    test_probes_match_the_claims()
    print()
    if failures:
        print("FAIL (%d): %s" % (len(failures), ", ".join(failures)))
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
