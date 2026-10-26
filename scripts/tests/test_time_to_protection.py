"""Tests for the paper's headline number.

Everything else this project measures is already true of systems that existed before it.
The claim that is new is that a detection found at one organization becomes a working
defence at others faster than any human process, and that is an interval.

So these tests are mostly about the three ways to report an interval flatteringly.

Run from the repository root:  python3 scripts/tests/test_time_to_protection.py
"""
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import time_to_protection as ttp  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + str(detail)}")
    if not condition:
        failures.append(name)


def build(members, published="2026-10-27T09:00:00+00:00", version="r2026.10.27"):
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "releases.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"rules_version": version, "published": published}) + "\n")
    for org, reported_version, hour in members:
        folder = os.path.join(root, "sightings", org)
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "s.json"), "w", encoding="utf-8") as f:
            json.dump({"schema_version": "0.2", "org": org, "sightings": [
                {"org": org, "sensor_version": "guardian-sensor v0",
                 "rules_version": reported_version, "pattern": "GP-0003",
                 "action": "blocked", "hour": hour, "count": 1, "source": "drill"}]}, f)
    return root


def measure(root, version=None):
    return ttp.intervals(os.path.join(root, "sightings"),
                         os.path.join(root, "releases.jsonl"), version)


def test_the_interval_is_measured_from_publication():
    """Not from when a member first looked.

    Polling delay is part of how long somebody was exposed. Subtracting it measures our
    software instead of their safety.
    """
    root = build([("a-lab", "r2026.10.27", "2026-10-27T12")])
    try:
        version, published, took, never = measure(root)
        check("one member, measured", [o for o, _ in took] == ["a-lab"], str(took))
        check("three hours after publication, not zero", took[0][1] == 3.0, str(took))
        check("and nobody is missing", never == [], str(never))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_a_member_who_never_adopted_is_counted():
    """They are the result, not missing data, and the ones an attacker still reaches."""
    root = build([("quick", "r2026.10.27", "2026-10-27T10"),
                  ("stale", "r2026.10.26", "2026-10-27T12")])
    try:
        _, _, took, never = measure(root)
        check("the adopter is measured", [o for o, _ in took] == ["quick"], str(took))
        check("the one still on the old rules is named", never == ["stale"], str(never))
        out = ttp.text(measure(root))
        check("the report says one of two, not one of one",
              "1 of 2" in out, out[:200])
        check("and names them rather than dropping them", "stale" in out, out[:300])
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_a_clock_behind_publication_does_not_pull_the_median_down():
    """A member reporting under a version before it existed means a wrong clock
    somewhere, not a negative wait."""
    root = build([("backwards", "r2026.10.27", "2026-10-27T06")])
    try:
        _, _, took, _ = measure(root)
        check("it is not negative", took[0][1] >= 0.0, str(took))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_the_earliest_hour_is_the_adoption():
    """A member reports many times under one version. The first is when they adopted."""
    root = tempfile.mkdtemp()
    try:
        with open(os.path.join(root, "releases.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"rules_version": "r1",
                                "published": "2026-10-27T09:00:00+00:00"}) + "\n")
        folder = os.path.join(root, "sightings", "a-lab")
        os.makedirs(folder)
        for n, hour in enumerate(["2026-10-27T15", "2026-10-27T10", "2026-10-27T20"]):
            with open(os.path.join(folder, "s%d.json" % n), "w", encoding="utf-8") as f:
                json.dump({"schema_version": "0.2", "org": "a-lab", "sightings": [
                    {"org": "a-lab", "sensor_version": "v0", "rules_version": "r1",
                     "pattern": "GP-0003", "action": "blocked", "hour": hour,
                     "count": 1, "source": "drill"}]}, f)
        _, _, took, _ = measure(root)
        check("the earliest report is the adoption", took[0][1] == 1.0, str(took))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_nothing_is_claimed_without_a_publication_time():
    """Without knowing when a rule was published there is no interval, and a guess here
    would be a made up headline number."""
    root = build([("a-lab", "r2026.10.27", "2026-10-27T12")])
    try:
        os.remove(os.path.join(root, "releases.jsonl"))
        check("no release history means no result", measure(root) is None)
        out = ttp.text(None)
        check("and it says why", "when the rule was published" in out, out)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_an_empty_network_says_so():
    root = build([])
    try:
        out = ttp.text(measure(root))
        check("nothing measured is stated plainly",
              "nothing to measure" in out, out)
    finally:
        shutil.rmtree(root, ignore_errors=True)


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
