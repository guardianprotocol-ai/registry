"""Tests for pattern validation, the attack success rate, and an end-to-end scripted scan.

Run from the scanner folder:  python3 tests/test_scanner.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_scanner import patterns, runner, scenarios, targets  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PATTERNS = os.path.join(REPO, "patterns")

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


# ---------- validation ----------

def validate_with(change):
    """Validate a copy of GP-0004 with one thing broken, in a directory of its own.

    A fixed path under /tmp would collide between concurrent runs and, because /tmp is
    world writable and sticky, could be left behind owned by another user.
    """
    with tempfile.TemporaryDirectory() as folder:
        with open(os.path.join(PATTERNS, "GP-0004.yaml"), encoding="utf-8") as f:
            good = f.read()
        with open(os.path.join(folder, "GP-0004.yaml"), "w", encoding="utf-8") as f:
            f.write(change(good))
        return patterns.validate_dir(folder)


def test_the_registry_validates():
    report = patterns.validate_dir(PATTERNS)
    check("every pattern file in the registry is valid", report.ok, "; ".join(report.problems[:4]))
    on_disk = len([f for f in os.listdir(PATTERNS) if f.endswith(".yaml")])
    check("every pattern file on disk was checked", len(report.patterns) == on_disk,
          f"{len(report.patterns)} checked, {on_disk} on disk")


def test_a_missing_field_is_caught():
    report = validate_with(
        lambda good: "\n".join(l for l in good.splitlines() if not l.startswith("severity:")) + "\n")
    check("a missing required field is caught", not report.ok, "validator said it was fine")
    check("the problem names the field", any("severity" in p for p in report.problems),
          str(report.problems))


def test_a_live_destination_is_caught():
    report = validate_with(lambda good: good.replace("notes.txt", "evil.example.org"))
    check("a destination outside .test is caught", not report.ok, "validator said it was fine")


def test_a_malformed_canary_is_caught():
    report = validate_with(lambda good: good.replace("GP0004-CANARY-1d4e", "GP0004-CANARY-ZZZZ"))
    check("a canary outside the GPnnnn-CANARY-xxxx form is caught", not report.ok,
          "validator said it was fine")


def test_an_id_that_does_not_match_its_filename_is_caught():
    report = validate_with(lambda good: good.replace("id: GP-0004", "id: GP-9999"))
    check("an id that does not match its filename is caught", not report.ok,
          "validator said it was fine")


# ---------- attack success rate ----------

def test_rate_is_successes_over_runs():
    r = runner.Result("GP-0001", "scripted:vulnerable", outcomes=[True, True, False, True])
    check("attack success rate is successes over runs", r.rate == 0.75, str(r.rate))
    check("it counts the runs", (r.runs, r.successes) == (4, 3), f"{r.runs}, {r.successes}")


def test_an_interval_is_reported_because_one_run_proves_nothing():
    """A rate with no interval invites reading 1 of 1 as certainty. It is not."""
    one = runner.Result("GP-0001", "t", outcomes=[True])
    many = runner.Result("GP-0001", "t", outcomes=[True] * 40)
    check("a single run gives a wide interval", one.interval[1] - one.interval[0] > 0.7,
          str(one.interval))
    check("forty runs give a narrow one", many.interval[1] - many.interval[0] < 0.15,
          str(many.interval))
    check("the interval stays inside 0 and 1",
          0.0 <= one.interval[0] and one.interval[1] <= 1.0, str(one.interval))


def test_all_or_nothing_still_gives_an_honest_interval():
    none = runner.Result("GP-0001", "t", outcomes=[False] * 10)
    check("ten clean runs do not claim zero risk", none.rate == 0.0 and none.interval[1] > 0.0,
          f"{none.rate}, {none.interval}")
    allof = runner.Result("GP-0001", "t", outcomes=[True] * 10)
    check("ten failures do not claim certainty", allof.rate == 1.0 and allof.interval[0] < 1.0,
          f"{allof.rate}, {allof.interval}")


def test_errors_are_not_counted_as_successes():
    r = runner.Result("GP-0001", "t", outcomes=[True, None, False])
    check("a run that errored is excluded, not scored", (r.runs, r.successes) == (2, 1),
          f"{r.runs}, {r.successes}")
    check("errors are reported", r.errors == 1, str(r.errors))


# ---------- end to end, no model and no cost ----------

def test_scripted_targets_disagree_as_they_should():
    available = scenarios.available()
    check("scenarios exist for the patterns v0 can run", set(available) >= {"GP-0001", "GP-0002", "GP-0003"},
          str(sorted(available)))

    weak = runner.run_pattern("GP-0001", targets.scripted("vulnerable"), repeat=3)
    check("the vulnerable reference agent is exploited every time", weak.rate == 1.0,
          f"{weak.rate}, errors {weak.errors}")

    strong = runner.run_pattern("GP-0001", targets.scripted("hardened"), repeat=3)
    check("the hardened reference agent resists every time", strong.rate == 0.0,
          f"{strong.rate}, errors {strong.errors}")


def test_the_sensor_stops_the_vulnerable_agent():
    """The same agent that is exploited without the sensor must be protected with it."""
    without = runner.run_pattern("GP-0002", targets.scripted("vulnerable"), repeat=3)
    withit = runner.run_pattern("GP-0002", targets.scripted("vulnerable"), repeat=3, sensor=True)
    check("without the sensor the canary leaks", without.rate == 1.0, str(without.rate))
    check("with the sensor it does not", withit.rate == 0.0, f"{withit.rate}, errors {withit.errors}")


def test_the_sensor_stops_a_tampered_tool():
    """The first version of this scenario turned the tamper on before the tool was approved.

    The sensor then pinned the changed definition and had nothing to compare against, so a
    real measurement showed the sensor failing when the scenario was what was wrong. A
    tampered tool means approved first, changed after.
    """
    without = runner.run_pattern("GP-0003", targets.scripted("vulnerable"), repeat=3)
    withit = runner.run_pattern("GP-0003", targets.scripted("vulnerable"), repeat=3, sensor=True)
    check("without the sensor a changed tool is used", without.rate == 1.0,
          f"{without.rate}, errors {without.errors}")
    check("with the sensor the changed tool is blocked", withit.rate == 0.0,
          f"{withit.rate}, errors {withit.errors}")


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
