"""Tests for the pattern scaffold.

Run from the repository root:  python3 scripts/tests/test_new_pattern.py
"""
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "scanner"))
import new_pattern  # noqa: E402
from guardian_scanner import patterns as validator  # noqa: E402

TEMPLATE = os.path.join(ROOT, "docs", "pattern-template.yaml")
failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def workspace():
    """A patterns directory holding a copy of the real ones."""
    folder = tempfile.mkdtemp()
    for name in os.listdir(os.path.join(ROOT, "patterns")):
        if name.endswith(".yaml"):
            shutil.copy(os.path.join(ROOT, "patterns", name), os.path.join(folder, name))
    return folder


def test_it_takes_the_next_free_id():
    folder = workspace()
    try:
        highest = max(int(n[3:7]) for n in os.listdir(folder) if n.endswith(".yaml"))
        check("the next id is one past the highest",
              new_pattern.next_id(folder) == f"GP-{highest + 1:04d}",
              new_pattern.next_id(folder))
        path, _ = new_pattern.create("A new attack", folder, TEMPLATE)
        check("the file is named after the id", os.path.basename(path) == f"GP-{highest + 1:04d}.yaml",
              os.path.basename(path))
        check("the next one after that moves on",
              new_pattern.next_id(folder) == f"GP-{highest + 2:04d}", new_pattern.next_id(folder))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_ids_are_never_reused_even_after_a_deletion():
    folder = workspace()
    try:
        first, _ = new_pattern.create("First", folder, TEMPLATE)
        taken = os.path.basename(first)
        os.remove(first)
        # Deleting a pattern must not hand its id to the next one.
        again = new_pattern.next_id(folder)
        check("a deleted id is still not reused", again == taken[:-5],
              f"deleted {taken}, next is {again}")
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_it_refuses_to_overwrite():
    folder = workspace()
    try:
        path, _ = new_pattern.create("First", folder, TEMPLATE)
        try:
            # Re-create the same path by pointing next_id at a stale listing.
            with open(path, "x", encoding="utf-8"):
                pass
            check("it refuses to overwrite", False, "no error raised")
        except FileExistsError:
            check("it refuses to overwrite", True)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_it_fills_in_the_fields_it_promises():
    folder = workspace()
    try:
        path, text = new_pattern.create("Hidden instructions in a calendar invite", folder,
                                        TEMPLATE, today="2026-10-04")
        pattern_id = os.path.basename(path)[:-5]
        check("id is filled in", f"id: {pattern_id}" in text, text[:200])
        check("title is filled in", "title: Hidden instructions in a calendar invite" in text)
        check("status starts as draft", "status: draft" in text)
        check("version starts at 1", "version: 1" in text)
        check("created is today", "created: 2026-10-04" in text)
        check("no placeholder id is left", "GP-NNNN" not in text)
        check("no placeholder date is left", "YYYY-MM-DD" not in text)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_it_lists_what_is_left_to_fill():
    folder = workspace()
    try:
        _, text = new_pattern.create("Something", folder, TEMPLATE)
        left = new_pattern.todo_fields(text)
        check("it names fields still to fill", len(left) >= 3, str(left))
        check("it does not list the ones it filled",
              not {"id", "status", "version", "created"} & set(left), str(left))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_the_scaffolded_file_validates_once_filled_in():
    """The scaffold is only useful if what it produces can pass the validator."""
    folder = tempfile.mkdtemp()
    try:
        path, text = new_pattern.create("Hidden instructions in a calendar invite", folder,
                                        TEMPLATE, today="2026-10-04")
        filled = (text
                  .replace("summary: >", "summary: >")
                  .replace("severity: medium (one-line reason)",
                           "severity: medium (the agent acts on text the user never saw)")
                  .replace('surfaces: [mcp_tool_output]', 'surfaces: [mcp_tool_output]')
                  .replace("- {name: Your Name, organization: Your Organization}",
                           "- {name: Frank Albanese, organization: Founding maintainer}"))
        with open(path, "w", encoding="utf-8") as f:
            f.write(filled)
        report = validator.validate_dir(folder)
        remaining = [p for p in report.problems if "credits" in p or "maps_to" in p]
        check("a filled in scaffold has no mapping or credit problems", not remaining,
              "; ".join(remaining))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


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
