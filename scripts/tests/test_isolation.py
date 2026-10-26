"""The suite must not write to the records of whoever runs it.

Three times in one day a new way to reach real state was added and the tests kept
isolating the old ones. Hooks wrote into a real settings file, a read only client read a
real Codex config, and the sensor's own defaults wrote detections into a real evidence
log, which a sharing machine then reported to the network as live traffic. Test runs were
being counted as findings.

Each was fixed where it happened. This checks the thing that makes all of them impossible:
that check.py hands every test a throwaway home.

Run from the repository root:  python3 scripts/tests/test_isolation.py
"""
import inspect
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
import check as checks  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + str(detail)}")
    if not condition:
        failures.append(name)


def test_every_check_runs_against_a_throwaway_home():
    source = inspect.getsource(checks.main) + inspect.getsource(checks._run_checks)
    check("a temporary directory is made for the run",
          "TemporaryDirectory" in source, source[:0])
    check("and it is given to the tests as GUARDIAN_HOME",
          'GUARDIAN_HOME' in source, source[:0])
    check("every check is run with that environment",
          "env=environment" in source, source[:0])


def test_the_real_home_is_not_what_tests_see():
    """The property itself, not the implementation: with the variable set, nothing
    resolves under the real home."""
    sys.path.insert(0, os.path.join(ROOT, "sensor"))
    from guardian_sensor import home

    previous = os.environ.get("GUARDIAN_HOME")
    os.environ["GUARDIAN_HOME"] = "/tmp/guardian-isolation-probe"
    try:
        real = os.path.join(os.path.expanduser("~"), ".guardian")
        for name, value in (("data directory", home.data_dir()),
                            ("drill directory", home.drill_dir()),
                            ("evidence paths", " ".join(home.evidence_paths()))):
            check("%s is not under the real home" % name, real not in value, value)
    finally:
        if previous is None:
            os.environ.pop("GUARDIAN_HOME", None)
        else:
            os.environ["GUARDIAN_HOME"] = previous


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
