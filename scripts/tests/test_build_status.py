"""Tests for the triage check and the generated status page.

Run from the repository root:  python3 scripts/tests/test_build_status.py
"""
import csv
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import build_status  # noqa: E402
import coverage  # noqa: E402

failures = []

FIELDS = ["id", "name", "tactics", "maturity", "category", "sensor", "scan", "status", "reason"]


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def row(tid, status=coverage.DRAFT, reason="", category=coverage.AGENT_RUNTIME, name="A technique"):
    return {"id": tid, "name": name, "tactics": "Execution", "maturity": "Realized",
            "category": category, "sensor": "yes", "scan": "yes", "status": status,
            "reason": reason}


def csv_with(rows):
    folder = tempfile.mkdtemp()
    path = os.path.join(folder, "atlas-coverage.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    return folder, path


# ---------- the triage check ----------

def test_a_clean_triage_has_no_problems():
    check("a draft row is fine", coverage.problems([row("AML.T0051")]) == [])
    good = row("AML.T0062", coverage.NOT_TESTABLE,
               "Happens before the agent runs, so no runtime checkpoint ever sees it.")
    check("not testable with a reason is fine", coverage.problems([good]) == [],
          str(coverage.problems([good])))


def test_an_unknown_status_is_refused():
    found = coverage.problems([row("AML.T0051", "probably fine")])
    check("an unknown status is refused", any("is not one of" in p for p in found), str(found))


def test_not_testable_needs_a_reason():
    found = coverage.problems([row("AML.T0051", coverage.NOT_TESTABLE)])
    check("not testable with no reason is refused",
          any("gives no reason" in p for p in found), str(found))
    found = coverage.problems([row("AML.T0051", coverage.NOT_TESTABLE, "too short")])
    check("a hand wave is refused", any("gives no reason" in p for p in found), str(found))


def test_a_reason_without_that_status_is_refused():
    found = coverage.problems([row("AML.T0051", coverage.CONFIRMED,
                                   "A reason long enough to pass the length check easily.")])
    check("a reason on the wrong status is refused",
          any("explains" in p for p in found), str(found))


def test_a_duplicate_technique_is_refused():
    found = coverage.problems([row("AML.T0051"), row("AML.T0051")])
    check("a duplicated technique id is refused",
          any("more than once" in p for p in found), str(found))


def test_the_committed_triage_is_valid():
    check("the real triage file passes", coverage.problems(coverage.load()) == [],
          str(coverage.problems(coverage.load())))
    runtime = coverage.agent_runtime(coverage.load())
    check("there are 63 agent runtime techniques", len(runtime) == 63, str(len(runtime)))


# ---------- the status page ----------

def test_a_technique_with_no_pattern_is_open():
    folder, path = csv_with([row("AML.T9001")])
    try:
        items = build_status.collect(path)
        check("an unmapped technique is open", items[0]["state"] == "open", str(items[0]))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_not_testable_counts_as_resolved_and_carries_its_reason():
    reason = "Happens before the agent runs, so no runtime checkpoint ever sees it."
    folder, path = csv_with([row("AML.T9002", coverage.NOT_TESTABLE, reason)])
    try:
        items = build_status.collect(path)
        check("not testable is its own state",
              items[0]["state"] == "not testable at runtime", str(items[0]))
        n = build_status.summary(items)
        check("it counts as resolved, not as covered",
              n["not_testable"] == 1 and n["covered"] == 0 and n["open"] == 0, str(n))
        check("the reason reaches the page", reason in build_status.render(items))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_mapped_technique_is_covered_and_shows_its_pattern():
    """AML.T0086 is claimed by GP-0002 in the real pattern files."""
    folder, path = csv_with([row("AML.T0086")])
    try:
        items = build_status.collect(path)
        check("a mapped technique is covered", items[0]["state"] == "covered", str(items[0]))
        check("its pattern is named", "GP-0002" in items[0]["patterns"], str(items[0]))
        check("a scenario is not a measurement: GP-0002 runs but has no recorded result",
              items[0]["runnable"] and not items[0]["measured"], str(items[0]))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_measured_means_a_recorded_result_exists():
    """AML.T0051.001 is claimed by GP-0001, which results/ has a measurement for."""
    folder, path = csv_with([row("AML.T0051.001")])
    try:
        items = build_status.collect(path)
        check("a technique with a recorded result shows as measured",
              items[0]["measured"], str(items[0]))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_only_agent_runtime_rows_are_tracked():
    folder, path = csv_with([row("AML.T9003", category="Attacker preparation (before contact)")])
    try:
        check("rows outside agent runtime are left out", build_status.collect(path) == [])
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_attack_cases_are_counted_per_pattern_and_benign_cases_once():
    folder = tempfile.mkdtemp()
    try:
        attacks = os.path.join(folder, "attacks")
        benign = os.path.join(folder, "benign")
        os.makedirs(attacks)
        os.makedirs(benign)
        for i in range(2):
            with open(os.path.join(attacks, f"a{i}.json"), "w", encoding="utf-8") as f:
                json.dump({"expect": "GP-0001"}, f)
        for i in range(3):
            with open(os.path.join(benign, f"b{i}.json"), "w", encoding="utf-8") as f:
                json.dump({"id": f"b{i}"}, f)
        check("attack cases are counted per pattern",
              build_status.attack_cases(attacks) == {"GP-0001": 2},
              str(build_status.attack_cases(attacks)))
        check("benign cases are counted once for the whole corpus",
              build_status.benign_cases(benign) == 3)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_check_mode_catches_a_stale_page():
    folder, path = csv_with([row("AML.T9004")])
    out_dir = tempfile.mkdtemp()
    try:
        out = os.path.join(out_dir, "STATUS.md")
        check("check mode fails when the page is missing",
              build_status.main(["--check", "--out", out, "--coverage", path]) == 1)
        build_status.main(["--out", out, "--coverage", path])
        check("check mode passes once it is generated",
              build_status.main(["--check", "--out", out, "--coverage", path]) == 0)
        with open(out, "a", encoding="utf-8") as f:
            f.write("edited by hand\n")
        check("check mode catches a hand edit",
              build_status.main(["--check", "--out", out, "--coverage", path]) == 1)
    finally:
        shutil.rmtree(folder, ignore_errors=True)
        shutil.rmtree(out_dir, ignore_errors=True)


def test_the_committed_status_page_is_current():
    check("docs/STATUS.md matches the repository", build_status.main(["--check"]) == 0)


def test_the_page_names_every_agent_runtime_technique():
    text = build_status.build()
    runtime = coverage.agent_runtime(coverage.load())
    missing = [r["id"] for r in runtime if f"`{r['id']}`" not in text]
    check("every agent runtime technique has a row", not missing, str(missing[:5]))


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
