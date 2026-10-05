"""Tests for the Season 1 Map issue text.

Run from the repository root:  python3 scripts/tests/test_season_one_issues.py

The issues are created by a shell script that cannot be tested without a token, so the
wording and the labels are built in Python and checked here instead.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import coverage  # noqa: E402
import season_one_issues as issues  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def built():
    return issues.build()


def test_one_issue_per_agent_runtime_technique():
    made = built()
    runtime = coverage.agent_runtime(coverage.load())
    check("one issue per agent runtime technique", len(made) == len(runtime),
          f"{len(made)} issues for {len(runtime)} techniques")
    check("there are 63 of them", len(made) == 63, str(len(made)))


def test_titles_are_stable_and_unique():
    """The shell script skips by exact title, so duplicates would break idempotence."""
    titles = [i["title"] for i in built()]
    check("every title is unique", len(set(titles)) == len(titles),
          str(len(titles) - len(set(titles))) + " duplicates")
    check("titles start with Map and the technique id",
          all(t.startswith("Map AML.T") for t in titles), titles[0])


def test_every_issue_carries_the_season_label():
    check("every issue is labelled season-1",
          all("season-1" in i["labels"] for i in built()))


def test_covered_techniques_are_good_first_issues():
    made = built()
    covered = [i for i in made if "good first issue" in i["labels"]]
    check("some techniques are already covered", len(covered) > 0, str(len(covered)))
    check("a covered technique is labelled track:patterns",
          all("track:patterns" in i["labels"] for i in covered))
    check("a covered technique says it is mostly a review",
          all("mostly a review" in i["body"] for i in covered))
    uncovered = [i for i in made if "good first issue" not in i["labels"]]
    check("an uncovered technique is labelled track:coverage",
          all("track:coverage" in i["labels"] for i in uncovered))
    check("an uncovered technique says no pattern covers it",
          all("No pattern covers this yet" in i["body"] for i in uncovered))


def test_the_body_carries_the_triage_row_and_the_checklist():
    one = built()[0]
    for needle in ("Current triage row", "Done when one of these is true",
                   "Triage confirmed", "not_testable_at_runtime", "docs/STATUS.md",
                   "PROGRAM.md"):
        check(f"the body mentions {needle}", needle in one["body"], one["body"][:160])


def test_the_body_names_the_technique_it_is_about():
    for issue in built()[:5]:
        tid = issue["title"].split(" ", 1)[1].split(":", 1)[0]
        check(f"{tid} appears in its own body", f"`{tid}`" in issue["body"])


def test_no_em_dashes_anywhere():
    bad = [i["title"] for i in built() if "—" in i["title"] or "—" in i["body"]]
    check("no em dashes in any issue", not bad, str(bad[:3]))


def test_nothing_here_talks_to_github():
    """The builder must stay offline so it can be reviewed and tested freely.

    Checked by parsing the imports rather than searching the text, because the issue
    bodies legitimately contain words like "pull requests".
    """
    import ast
    path = os.path.join(ROOT, "scripts", "season_one_issues.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for banned in ("subprocess", "urllib", "http", "socket", "requests"):
        check(f"the builder does not import {banned}", banned not in imported, str(sorted(imported)))


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
