#!/usr/bin/env python3
"""Tests for the detection coverage report that replays fixtures through the proxy.

Run from the repository root:  python3 scripts/tests/test_detection_coverage.py
"""
import io
import os
import sys
import tempfile
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import detection_coverage as coverage  # noqa: E402

failures = []
RESULT = coverage.run()


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + str(detail)}")
    if not condition:
        failures.append(name)


def test_the_same_tree_gives_the_same_report():
    check("two runs produce the same page",
          coverage.markdown(coverage.run()) == coverage.markdown(RESULT))


def test_every_catalog_pattern_is_reported_once():
    ids = [p["id"] for p in RESULT["patterns"]]
    on_disk = sorted(n[:-5] for n in os.listdir(os.path.join(ROOT, "patterns"))
                     if n.startswith("GP-") and n.endswith(".yaml"))
    check("one row per pattern file", ids == on_disk, ids)


def test_no_fixture_is_authored_here():
    """Every fixture is an existing corpus case or the existing test server."""
    for f in RESULT["fixtures"]:
        check("%s comes from a file that exists" % f["id"],
              os.path.exists(os.path.join(ROOT, f["source"])), f["source"])
        check("%s is a corpus case or the test server" % f["id"],
              f["source"].startswith("corpus/attacks/")
              or f["source"] == "sensor/tests/fake_server.py", f["source"])


def test_runs_stay_small():
    per = {}
    for f in RESULT["fixtures"]:
        per[f["expect"]] = per.get(f["expect"], 0) + 1
    check("at most two fixtures per pattern",
          all(n <= coverage.MAX_PER_PATTERN for n in per.values()), per)


def test_a_pattern_with_no_fixture_is_a_gap_not_silence():
    gaps = [p for p in RESULT["patterns"] if not p["fixtures"]]
    check("some patterns have no fixture, so the case is real", bool(gaps))
    check("each is reported as no fixture",
          all(p["coverage"] == "no fixture" for p in gaps),
          [(p["id"], p["coverage"]) for p in gaps])


def test_a_missed_fixture_fails_the_run():
    """The regression this exists for: a case that stops being caught."""
    benign = coverage.load_cases("benign")[0]
    import json
    with open(os.path.join(ROOT, "corpus", "policy.json")) as f:
        policy = json.load(f)
    verdict = coverage.replay_case(dict(benign, expect="GP-0001"), policy)
    check("ordinary work expected to raise GP-0001 is missed",
          verdict["outcome"] == "missed", verdict)
    check("a missed verdict names nothing it did not raise",
          coverage._verdict("GP-0001", [], 0)["outcome"] == "missed")
    problems = coverage.find_problems(
        [{"id": "pretend", "expect": "GP-0001", "outcome": "missed", "raised": []}], [])
    check("and is reported as a problem",
          len(problems) == 1 and "pretend" in problems[0], problems)
    problems = coverage.find_problems([], [
        {"id": "ordinary", "outcome": "blocked", "raised": ["GP-0005"],
         "known_false_alarm": None},
        {"id": "tracked", "outcome": "blocked", "raised": ["GP-0005"],
         "known_false_alarm": "GP-0005"}])
    check("ordinary work blocked fails unless it is a tracked false alarm",
          len(problems) == 1 and "ordinary" in problems[0], problems)
    check("the real tree has no missed fixture", RESULT["problems"] == [], RESULT["problems"])


def test_blocked_means_refused_before_forwarding():
    blocked = [f for f in RESULT["fixtures"] if f["outcome"] == "blocked"]
    check("some fixtures are blocked", bool(blocked))
    check("each blocked fixture had a call refused",
          all(f["refused_calls"] >= 1 for f in blocked),
          [f["id"] for f in blocked if not f["refused_calls"]])


def test_output_side_detections_are_flagged_not_blocked():
    for f in RESULT["fixtures"]:
        if f["expect"] in ("GP-0006", "GP-0010"):
            check("%s is flagged" % f["id"], f["outcome"] == "flagged", f["outcome"])


def test_tool_definition_fixtures_run_through_the_real_proxy():
    for pid in ("GP-0003", "GP-0019"):
        mine = [f for f in RESULT["fixtures"] if f["expect"] == pid]
        check("%s has a proxy process fixture" % pid,
              any(f["via"] == "proxy process" for f in mine), mine)
        for f in mine:
            check("%s is blocked" % f["id"], f["outcome"] == "blocked", f)
            check("and the test server never saw the call", f["reached_server"] is False, f)


def test_ordinary_work_is_not_blocked_unless_a_known_false_alarm():
    for b in RESULT["benign"]:
        if b["outcome"] == "blocked":
            check("%s is blocked only as a tracked false alarm" % b["id"],
                  b["known_false_alarm"] in b["raised"], b)


def test_check_fails_on_a_stale_page():
    real = coverage.PAGE
    with tempfile.TemporaryDirectory() as tmp:
        coverage.PAGE = os.path.join(tmp, "DETECTION_COVERAGE.md")
        try:
            with open(coverage.PAGE, "w") as f:
                f.write("stale\n")
            with redirect_stdout(io.StringIO()) as out:
                code = coverage.main(["--check"])
            check("a stale page fails", code == 1, code)
            check("and says how to fix it", "--write" in out.getvalue(), out.getvalue())
            with redirect_stdout(io.StringIO()):
                coverage.main(["--write"])
                code = coverage.main(["--check"])
            check("a fresh page passes", code == 0, code)
        finally:
            coverage.PAGE = real


def test_wired_into_check_py():
    sys.path.insert(0, ROOT)
    import check as checks
    commands = [args for _, _, args in checks.CHECKS]
    check("check.py runs the coverage check",
          ["scripts/detection_coverage.py", "--check"] in commands)
    check("and these tests",
          ["scripts/tests/test_detection_coverage.py"] in commands)


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
