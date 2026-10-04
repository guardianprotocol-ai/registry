"""Tests for the meeting summary.

Run from the repository root:  python3 scripts/tests/test_shipped.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import shipped  # noqa: E402

failures = []


ISOLATED_GIT = {
    # A contributor with commit.gpgsign = true globally would otherwise see these tests
    # fail with no sign of why. The throwaway repositories take no config from the user.
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.test",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.test",
}


def git_env(extra=None):
    return {**os.environ, **ISOLATED_GIT, **(extra or {})}


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def test_a_bare_date_is_pinned_to_the_start_of_the_day():
    """git log --since=<today> returns nothing, which would report an empty week."""
    check("a bare date gains a time", shipped.normalise("2026-10-04") == "2026-10-04 00:00:00",
          shipped.normalise("2026-10-04"))
    check("a date with a time is left alone",
          shipped.normalise("2026-10-04 09:30") == "2026-10-04 09:30",
          shipped.normalise("2026-10-04 09:30"))
    check("a relative date is left alone",
          shipped.normalise("2 weeks ago") == "2 weeks ago", shipped.normalise("2 weeks ago"))


def build_repo():
    folder = tempfile.mkdtemp()

    def git(*args):
        return subprocess.run(["git"] + list(args), cwd=folder, capture_output=True, text=True, env=git_env())

    git("init", "-q", "-b", "main")
    git("config", "user.name", "Dana Reed")
    git("config", "user.email", "dana@example.test")
    os.makedirs(os.path.join(folder, "patterns"))

    def commit(path, text, message, when, author=None):
        with open(os.path.join(folder, path), "w", encoding="utf-8") as f:
            f.write(text)
        git("add", "-A")
        env = ["-c", f"user.name={author}"] if author else []
        signer = author or "Dana Reed"
        subprocess.run(["git"] + env + ["commit", "-q", f"--date={when}", "-m",
                        f"{message}\n\nSigned-off-by: {signer} <x@example.test>"],
                       cwd=folder, capture_output=True, text=True,
                       env=git_env({"GIT_COMMITTER_DATE": when}))

    commit("patterns/GP-0001.yaml", "id: GP-0001\n", "Add the first pattern",
           "2026-01-01T10:00:00")
    commit("patterns/GP-0001.yaml", "id: GP-0001\nversion: 2\n", "Improve the first pattern",
           "2026-06-01T10:00:00")
    commit("patterns/GP-0002.yaml", "id: GP-0002\n", "Add the second pattern",
           "2026-06-02T10:00:00", author="Sam Okafor")
    return folder


def test_only_patterns_added_in_the_window_count_as_added():
    folder = build_repo()
    old_root = shipped.ROOT
    shipped.ROOT = folder
    try:
        entries = shipped.commits("2026-05-01")
        added, changed = shipped.patterns_touched(entries, "2026-05-01")
        check("a pattern added inside the window is new", added == ["GP-0002"], str(added))
        check("one added before it is only changed", changed == ["GP-0001", "GP-0002"],
              str(changed))
        text = shipped.markdown(entries, "2026-05-01")
        check("the report separates added from changed",
              "**Patterns added:** GP-0002" in text and "**Patterns changed:** GP-0001" in text,
              text)
    finally:
        shipped.ROOT = old_root
        shutil.rmtree(folder, ignore_errors=True)


def test_it_groups_by_the_person_who_signed_off():
    folder = build_repo()
    old_root = shipped.ROOT
    shipped.ROOT = folder
    try:
        text = shipped.markdown(shipped.commits("2026-05-01"), "2026-05-01")
        check("both people are named", "**Dana Reed**" in text and "**Sam Okafor**" in text, text)
        check("it counts the people", "from 2 people" in text, text)
        check("it says who demos", "Those people demo." in text, text)
    finally:
        shipped.ROOT = old_root
        shutil.rmtree(folder, ignore_errors=True)


def test_an_empty_window_says_so():
    folder = build_repo()
    old_root = shipped.ROOT
    shipped.ROOT = folder
    try:
        text = shipped.markdown(shipped.commits("2026-12-01"), "2026-12-01")
        check("an empty window is stated plainly", "Nothing has landed" in text, text)
    finally:
        shipped.ROOT = old_root
        shutil.rmtree(folder, ignore_errors=True)


def test_the_real_repository_reports_something():
    text = shipped.markdown(shipped.commits("2026-09-01"), "2026-09-01")
    check("the real repository has shipped something", "Shipped since" in text, text[:80])
    check("the founding maintainer appears", "Frank Albanese" in text, text[:200])


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
