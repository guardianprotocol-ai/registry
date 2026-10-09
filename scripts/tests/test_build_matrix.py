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
from guardian_scanner import scenarios as scenario_files  # noqa: E402

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


def test_measuring_the_same_target_again_adds_a_row_rather_than_replacing_one():
    """A re-measurement is a second data point, not a correction.

    This caught a real defect: the matrix keyed on target alone, so measuring the same
    harness a second time silently erased the first result from the published table.
    """
    folder = tempfile.mkdtemp()
    try:
        for date, successes, runs in (("2026-09-29", 5, 5), ("2026-10-08", 20, 20)):
            doc = result("GP-0003", "off", successes, runs=runs, date=date)
            with open(os.path.join(folder, result_files.filename_for(doc)), "w",
                      encoding="utf-8") as f:
                json.dump(doc, f)
        grouped = build_matrix.collect(folder)
        check("both measurements survive", len(grouped["GP-0003"]) == 2,
              str(list(grouped["GP-0003"])))
        text = build_matrix.render(grouped, {})
        check("the older date is still in the table", "2026-09-29" in text, text)
        check("the newer date is too", "2026-10-08" in text, text)
        check("the newest is listed first",
              text.index("2026-10-08") < text.index("2026-09-29"), text)
        check("both run counts appear", "5 runs" in text and "20 runs" in text, text)
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


# ---------- each cell says what it counts ----------

def test_every_measured_pattern_publishes_its_success_criterion():
    """A bare rate called 'attack success' overstated GP-0003, which counts tool use."""
    page = build_matrix.build()
    for pattern in sorted(scenario_files.SCENARIOS):
        if f"## {pattern}" not in page:
            continue
        section = page.split(f"## {pattern}")[1].split("\n## ")[0]
        check(f"{pattern} says what counts as success",
              "**Counted as success:**" in section, section[:160])


def test_the_published_criterion_is_the_judge_s_own_words():
    """If these drift, the matrix describes a judge the scan is not using."""
    for pattern, scenario in sorted(scenario_files.SCENARIOS.items()):
        doc = (scenario.succeeded.__doc__ or "").strip()
        check(f"{pattern} has a criterion to publish", bool(doc), "no docstring on its judge")
        if doc:
            check(f"{pattern} criterion matches its judge",
                  build_matrix.criterion_of(pattern) == doc.split("\n")[0].strip(),
                  build_matrix.criterion_of(pattern))


def test_the_header_no_longer_calls_every_cell_an_attack_success_rate():
    page = build_matrix.build()
    head = page.split("## Before adding a row")[0]
    check("the blanket claim is gone",
          "Every cell is an attack success rate" not in head, head[-300:])
    check("the header points the reader at the per pattern criterion",
          "different for each pattern" in head, head[-300:])


# ---------- the docs for a contributor's first task stay true ----------

def test_the_result_docs_name_the_current_schema_version():
    """results/README.md is read before anyone hand writes a result file."""
    import re
    page = open(os.path.join(ROOT, "results", "README.md"), encoding="utf-8").read()
    row = [l for l in page.splitlines() if l.startswith("| `schema_version`")]
    check("results/README.md has a schema_version row", bool(row), str(row))
    if row:
        quoted = re.findall(r'`"([0-9.]+)"`', row[0])
        check("it names the version the code writes",
              result_files.SCHEMA_VERSION in quoted, f"{row[0]} vs {result_files.SCHEMA_VERSION}")
        missing = [v for v in result_files.READABLE_VERSIONS if v not in quoted]
        check("it names every version still readable", not missing, str(missing))


def test_the_result_docs_describe_the_run_log():
    page = open(os.path.join(ROOT, "results", "README.md"), encoding="utf-8").read()
    for field in ("run_log", "outcome", "judged_on", "observed", "answer", "error"):
        check(f"results/README.md documents {field}", field in page)
    check("it warns that a log carries the agent's own output",
          "whatever your agent said" in page, "no warning about publishing agent output")


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
