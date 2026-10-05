"""Tests for the generated attack matrix.

Run from the repository root:  python3 scripts/tests/test_build_matrix.py
"""
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "scanner"))

import build_matrix  # noqa: E402
from guardian_scanner import results as result_files  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def result(pattern, state, successes, runs=5, errored=0, model="unrecorded",
           harness="claude-code", harness_version="2.1.274", date="2026-09-29"):
    scored = runs - errored
    low, high = result_files.wilson(successes, scored)
    doc = {
        "schema_version": "0.1", "pattern": pattern,
        "target": {"model": model, "model_version": "unrecorded",
                   "harness": harness, "harness_version": harness_version},
        "sensor": {"state": state} if state == "off" else {"state": state, "bundle": "abc"},
        "runs": runs, "successes": successes, "errored": errored,
        "rate": round(result_files.rate_of(successes, scored), 4),
        "interval": [round(low, 4), round(high, 4)],
        "date": date, "scanner_commit": "unrecorded",
        "environment": "A test fixture, not a real measurement.",
        "credits": [{"name": "Dana Reed"}], "notes": "fixture",
    }
    return doc


def folder_with(docs):
    folder = tempfile.mkdtemp()
    for doc in docs:
        with open(os.path.join(folder, result_files.filename_for(doc)), "w", encoding="utf-8") as f:
            json.dump(doc, f)
    return folder


def test_a_pattern_gets_a_table_with_both_sensor_states():
    folder = folder_with([result("GP-0003", "off", 5), result("GP-0003", "on", 0)])
    try:
        text = build_matrix.render(build_matrix.collect(folder), {"GP-0003": "Tampered MCP tool"})
        check("the pattern heading carries its title", "## GP-0003: Tampered MCP tool" in text, text[:200])
        check("the unprotected cell shows rate, interval and runs",
              "100% [0.57, 1.00], 5 runs" in text, text)
        check("the sensor cell shows the protected rate", "0% [0.00, 0.43], 5 runs" in text, text)
        check("one row per target", text.count("| claude-code 2.1.274") == 1, text)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_missing_sensor_measurement_says_so_rather_than_implying_zero():
    folder = folder_with([result("GP-0001", "off", 0)])
    try:
        text = build_matrix.render(build_matrix.collect(folder), {})
        check("an unmeasured sensor cell says not measured", "not measured" in text, text)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_errored_runs_are_shown_and_excluded_from_the_denominator():
    folder = folder_with([result("GP-0001", "off", 3, runs=7, errored=2)])
    try:
        text = build_matrix.render(build_matrix.collect(folder), {})
        check("the cell counts scored runs, not attempts", "60% [0.23, 0.88], 5 runs" in text, text)
        check("errored runs are named in the cell", "2 errored" in text, text)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_recorded_model_appears_in_the_target_label():
    check("an unrecorded model is said out loud",
          build_matrix.target_label(("claude-code", "2.1.274", "unrecorded", "unrecorded"))
          == "claude-code 2.1.274, model unrecorded")
    check("a recorded model and version are shown",
          build_matrix.target_label(("ollama", "0.5.1", "llama3.1", "8b"))
          == "ollama 0.5.1, llama3.1 8b")


def test_targets_are_separate_rows():
    folder = folder_with([result("GP-0001", "off", 0),
                          result("GP-0001", "off", 4, harness="cursor", harness_version="1.2.3")])
    try:
        text = build_matrix.render(build_matrix.collect(folder), {})
        check("each target gets its own row", text.count("| claude-code") == 1 and text.count("| cursor") == 1, text)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_an_empty_results_folder_is_honest():
    folder = tempfile.mkdtemp()
    try:
        text = build_matrix.render(build_matrix.collect(folder), {})
        check("an empty matrix says there are no measurements",
              "No measurements recorded yet." in text, text[:300])
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_the_json_carries_every_measurement():
    folder = folder_with([result("GP-0003", "off", 5), result("GP-0003", "on", 0)])
    try:
        data = build_matrix.as_json(build_matrix.collect(folder))
        check("both measurements are in the json", len(data["measurements"]) == 2, str(data))
        check("the json carries the counts, not just the rate",
              all("successes" in m and "runs" in m for m in data["measurements"]), str(data))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_check_mode_catches_a_stale_file():
    folder = tempfile.mkdtemp()
    try:
        out = os.path.join(folder, "MATRIX.md")
        results = folder_with([result("GP-0001", "off", 0)])
        try:
            check("check mode fails when the file is missing",
                  build_matrix.main(["--check", "--out", out, "--results", results]) == 1)
            build_matrix.main(["--out", out, "--results", results])
            check("check mode passes once it is generated",
                  build_matrix.main(["--check", "--out", out, "--results", results]) == 0)
            with open(out, "a", encoding="utf-8") as f:
                f.write("edited by hand\n")
            check("check mode catches a hand edit",
                  build_matrix.main(["--check", "--out", out, "--results", results]) == 1)
        finally:
            shutil.rmtree(results, ignore_errors=True)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_the_committed_matrix_is_current():
    check("docs/MATRIX.md matches results/", build_matrix.main(["--check"]) == 0)


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
