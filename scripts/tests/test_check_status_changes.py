"""Tests for the status guard.

Run from the repository root:  python3 scripts/tests/test_check_status_changes.py

The diffs are real: each test builds a throwaway git repository, so the guard is exercised
through the same git plumbing it uses in CI rather than against a mocked diff.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import check_status_changes as guard  # noqa: E402

failures = []

MAINTAINERS_FILE = """# Maintainers

## Maintainers

| Name | GitHub | Affiliation | Areas |
| --- | --- | --- | --- |
| Dana Reed | [@danareed](https://github.com/danareed) | Example | All |

## Reviewers

| Name | GitHub | Affiliation | Areas |
| --- | --- | --- | --- |
| Sam Okafor | [@samokafor](https://github.com/samokafor) | Example | Patterns |
"""

PATTERN = """schema_version: "0.1"
id: GP-0099
title: A test pattern
status: {status}
version: 1
"""


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def git(folder, *args):
    return subprocess.run(["git"] + list(args), cwd=folder, capture_output=True, text=True)


def repo_with(first, second=None, path="patterns/GP-0099.yaml"):
    """A repository with a base commit and a change on top. Returns (folder, base, head)."""
    folder = tempfile.mkdtemp()
    git(folder, "init", "-q", "-b", "main")
    git(folder, "config", "user.name", "Test")
    git(folder, "config", "user.email", "test@example.test")
    os.makedirs(os.path.join(folder, os.path.dirname(path)), exist_ok=True)
    with open(os.path.join(folder, "MAINTAINERS.md"), "w", encoding="utf-8") as f:
        f.write(MAINTAINERS_FILE)
    if first is not None:
        with open(os.path.join(folder, path), "w", encoding="utf-8") as f:
            f.write(first)
    git(folder, "add", "-A")
    git(folder, "commit", "-q", "-m", "base")
    base = git(folder, "rev-parse", "HEAD").stdout.strip()
    if second is not None:
        with open(os.path.join(folder, path), "w", encoding="utf-8") as f:
            f.write(second)
        git(folder, "add", "-A")
        git(folder, "commit", "-q", "-m", "change")
    head = git(folder, "rev-parse", "HEAD").stdout.strip()
    return folder, base, head


def run_guard(folder, base, head, author):
    """Point the guard at the throwaway repository and run it."""
    old_root, old_maint = guard.ROOT, guard.MAINTAINERS
    guard.ROOT = folder
    guard.MAINTAINERS = os.path.join(folder, "MAINTAINERS.md")
    try:
        return guard.main(["check_status_changes.py", base, head, author])
    finally:
        guard.ROOT, guard.MAINTAINERS = old_root, old_maint


# ---------- parsing MAINTAINERS.md ----------

def test_it_reads_only_the_maintainers_table():
    folder = tempfile.mkdtemp()
    try:
        path = os.path.join(folder, "MAINTAINERS.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(MAINTAINERS_FILE)
        found = guard.maintainers(path)
        check("the maintainer is found", "danareed" in found, str(found))
        check("a reviewer is not treated as a maintainer", "samokafor" not in found, str(found))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_the_real_maintainers_file_parses():
    found = guard.maintainers(os.path.join(ROOT, "MAINTAINERS.md"))
    check("the repository's own MAINTAINERS.md parses", "faalbane" in found, str(found))


# ---------- what counts as a status change ----------

def test_adding_a_draft_pattern_is_fine_for_anyone():
    folder, base, head = repo_with(None, PATTERN.format(status="draft"))
    try:
        check("a contributor may add a draft pattern",
              run_guard(folder, base, head, "outsider") == 0)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_adding_a_verified_pattern_is_refused():
    folder, base, head = repo_with(None, PATTERN.format(status="verified"))
    try:
        check("a contributor may not add a verified pattern",
              run_guard(folder, base, head, "outsider") == 1)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_promoting_an_existing_pattern_is_refused():
    folder, base, head = repo_with(PATTERN.format(status="draft"),
                                   PATTERN.format(status="enforced"))
    try:
        check("a contributor may not promote a pattern",
              run_guard(folder, base, head, "outsider") == 1)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_maintainer_may_promote():
    folder, base, head = repo_with(PATTERN.format(status="draft"),
                                   PATTERN.format(status="verified"))
    try:
        check("a maintainer may promote", run_guard(folder, base, head, "danareed") == 0)
        check("the handle is matched without case or @ mattering",
              run_guard(folder, base, head, "@DanaReed") == 0)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_reviewer_may_not_promote():
    folder, base, head = repo_with(PATTERN.format(status="draft"),
                                   PATTERN.format(status="verified"))
    try:
        check("a reviewer may not promote", run_guard(folder, base, head, "samokafor") == 1)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_editing_a_pattern_without_touching_status_is_fine():
    folder, base, head = repo_with(PATTERN.format(status="draft"),
                                   PATTERN.format(status="draft").replace("A test pattern",
                                                                          "A better title"))
    try:
        check("editing a pattern without changing status is fine",
              run_guard(folder, base, head, "outsider") == 0)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_editing_a_file_outside_patterns_is_ignored():
    folder, base, head = repo_with(PATTERN.format(status="draft"),
                                   PATTERN.format(status="verified"), path="docs/notes.md")
    try:
        check("a file outside patterns is not checked",
              run_guard(folder, base, head, "outsider") == 0)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_the_author_cannot_be_forged_through_the_maintainers_file():
    """The author comes from the pull request event, so adding yourself does not help.

    The guard reads MAINTAINERS.md at the merge result, which is the point of attack: a
    contributor could add their own handle in the same pull request. That is why the real
    defence is that MAINTAINERS.md is owned in CODEOWNERS and the file change is visible in
    review. What is tested here is the other half: the author string never comes from the
    pull request's files.
    """
    folder, base, head = repo_with(PATTERN.format(status="draft"),
                                   PATTERN.format(status="verified"))
    try:
        check("an author not in the file is refused no matter what the files say",
              run_guard(folder, base, head, "outsider") == 1)
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
