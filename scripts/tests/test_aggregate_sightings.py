"""Tests for merging members' sightings.

Run from the repository root:  python3 scripts/tests/test_aggregate_sightings.py

The rule being tested is the one that protects members: below three contributing
organizations, totals are withheld, because with two anyone can subtract their own.
"""
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import aggregate_sightings as agg  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def entry(org, pattern="GP-0002", action="blocked", hour="2026-10-04T11",
          rules="r2026.10.04", count=1):
    return {"org": org, "sensor_version": "guardian-sensor v0", "rules_version": rules,
            "pattern": pattern, "action": action, "hour": hour, "count": count}


def folder_with(by_org):
    root = tempfile.mkdtemp()
    for org, entries in by_org.items():
        os.makedirs(os.path.join(root, org))
        with open(os.path.join(root, org, "sightings.json"), "w", encoding="utf-8") as f:
            json.dump({"schema_version": "0.1", "org": org, "sightings": entries}, f)
    return root


def test_counts_merge_across_organizations():
    root = folder_with({"a-labs": [entry("a-labs", count=2)],
                        "b-labs": [entry("b-labs", count=3)],
                        "c-labs": [entry("c-labs", count=5)]})
    try:
        rows = agg.aggregate(agg.load_folder(root))
        check("one row for the pattern", len(rows) == 1, str(rows))
        check("three organizations counted", rows[0]["organizations"] == 3, str(rows[0]))
        check("counts are summed", rows[0]["total"] == 10, str(rows[0]))
        check("nothing is withheld at three", not rows[0]["withheld"], str(rows[0]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_totals_are_withheld_below_three_organizations():
    for n in (1, 2):
        orgs = {f"org{i}-labs": [entry(f"org{i}-labs", count=7)] for i in range(n)}
        root = folder_with(orgs)
        try:
            rows = agg.aggregate(agg.load_folder(root))
            check(f"with {n} organization(s) the total is withheld",
                  rows[0]["withheld"] and rows[0]["total"] is agg.WITHHELD, str(rows[0]))
            check(f"with {n} organization(s) the cells are withheld too",
                  rows[0]["cells"] is agg.WITHHELD, str(rows[0]))
            printed = agg.text(rows)
            check(f"with {n} the count 7 is not printed", "7" not in printed.split("orgs")[-1]
                  or "withheld" in printed, printed)
            check(f"with {n} the output says it is withheld", "withheld" in printed.lower(), printed)
            check(f"with {n} the json carries null, not a number",
                  agg.as_json(rows)[0]["total"] is None, str(agg.as_json(rows)))
            check(f"with {n} the organization count is still shown",
                  rows[0]["organizations"] == n, str(rows[0]))
        finally:
            shutil.rmtree(root, ignore_errors=True)


def test_the_threshold_is_exactly_three():
    orgs = {f"org{i}-labs": [entry(f"org{i}-labs")] for i in range(3)}
    root = folder_with(orgs)
    try:
        rows = agg.aggregate(agg.load_folder(root))
        check("three organizations is enough", not rows[0]["withheld"], str(rows[0]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_an_entry_with_unexpected_fields_is_refused():
    bad = entry("a-labs")
    bad["detail"] = {"body": "a secret"}
    root = folder_with({"a-labs": [bad], "b-labs": [entry("b-labs")], "c-labs": [entry("c-labs")]})
    try:
        pairs = agg.load_folder(root)
        check("an entry with an extra field is dropped", len(pairs) == 2, str(pairs))
        check("the secret never reaches the aggregate",
              "a secret" not in json.dumps(agg.as_json(agg.aggregate(pairs)), default=str))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_an_entry_missing_a_field_is_refused():
    short = entry("a-labs")
    del short["hour"]
    root = folder_with({"a-labs": [short]})
    try:
        check("an entry missing a field is dropped", agg.load_folder(root) == [])
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_broken_files_and_stray_files_are_skipped():
    root = folder_with({"a-labs": [entry("a-labs")]})
    try:
        with open(os.path.join(root, "a-labs", "broken.json"), "w", encoding="utf-8") as f:
            f.write("{not json")
        with open(os.path.join(root, "a-labs", "notes.txt"), "w", encoding="utf-8") as f:
            f.write("ignored")
        with open(os.path.join(root, "loose.json"), "w", encoding="utf-8") as f:
            f.write("{}")
        check("only the good entry survives", len(agg.load_folder(root)) == 1,
              str(agg.load_folder(root)))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_a_missing_folder_is_not_an_error():
    check("a missing folder gives nothing", agg.load_folder("/nope/none") == [])
    check("nothing aggregates to nothing", agg.aggregate([]) == [])
    check("the text says so", agg.text([]) == "No sightings found.")


def test_cells_are_grouped_by_rules_version_and_hour():
    root = folder_with({
        "a-labs": [entry("a-labs", hour="2026-10-04T11", count=1),
                   entry("a-labs", hour="2026-10-04T12", count=2)],
        "b-labs": [entry("b-labs", hour="2026-10-04T11", count=3)],
        "c-labs": [entry("c-labs", hour="2026-10-04T11", rules="r2026.10.05", count=4)],
    })
    try:
        rows = agg.aggregate(agg.load_folder(root))
        cells = {(c["rules_version"], c["hour"]): c["count"] for c in rows[0]["cells"]}
        check("the same hour and rules version are summed across organizations",
              cells[("r2026.10.04", "2026-10-04T11")] == 4, str(cells))
        check("a different hour is its own cell",
              cells[("r2026.10.04", "2026-10-04T12")] == 2, str(cells))
        check("a different rules version is its own cell",
              cells[("r2026.10.05", "2026-10-04T11")] == 4, str(cells))
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
