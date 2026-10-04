"""Tests for the generated credit data.

Run from the repository root:  python3 scripts/tests/test_build_contributors.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import build_contributors as builder  # noqa: E402

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


def write(folder, name, text):
    path = os.path.join(folder, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


# ---------- the opt-in table ----------

def test_the_table_is_read_as_the_opt_in():
    folder = tempfile.mkdtemp()
    try:
        path = write(folder, "CONTRIBUTORS.md", """# Contributors

| Name | GitHub | Organization | Contributions |
| --- | --- | --- | --- |
| Dana Reed | [@danareed](https://github.com/danareed) | Example Corp | Patterns |
| Sam Okafor | | Individual | Docs |
| Lee Park | [@leepark](https://github.com/leepark) | | Scanner |
""")
        rows = builder.from_contributors_file(path)
        check("a handle is read", rows["dana reed"]["github"] == "danareed", str(rows.get("dana reed")))
        check("an organization is read", rows["dana reed"]["organization"] == "Example Corp")
        check("Individual means no organization", rows["sam okafor"]["organization"] is None,
              str(rows["sam okafor"]))
        check("a blank organization means none", rows["lee park"]["organization"] is None,
              str(rows["lee park"]))
        check("a missing handle is allowed", rows["sam okafor"]["github"] is None,
              str(rows["sam okafor"]))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_role_is_not_treated_as_an_organization():
    """Credits say "Founding maintainer" until the company name is cleared. That is a role."""
    folder = tempfile.mkdtemp()
    try:
        path = write(folder, "CONTRIBUTORS.md", """| Name | GitHub | Organization | Contributions |
| --- | --- | --- | --- |
| Frank Albanese | [@faalbane](https://github.com/faalbane) | Founding maintainer | All |
""")
        rows = builder.from_contributors_file(path)
        check("a role is not listed as an organization",
              rows["frank albanese"]["organization"] is None, str(rows["frank albanese"]))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


# ---------- git history ----------

def test_history_gives_each_signer_their_first_date():
    folder = tempfile.mkdtemp()
    try:
        def git(*args):
            return subprocess.run(["git"] + list(args), cwd=folder,
                                  capture_output=True, text=True, env=git_env())
        git("init", "-q", "-b", "main")
        git("config", "user.name", "Dana Reed")
        git("config", "user.email", "dana@example.test")
        write(folder, "a.txt", "one")
        git("add", "-A")
        git("commit", "-q", "--date=2026-01-02T00:00:00", "-m",
            "first\n\nSigned-off-by: Dana Reed <dana@example.test>")
        write(folder, "b.txt", "two")
        git("add", "-A")
        git("commit", "-q", "-m",
            "second\n\nSigned-off-by: Dana Reed <dana@example.test>\n"
            "Signed-off-by: Sam Okafor <sam@example.test>")

        old_root = builder.ROOT
        builder.ROOT = folder
        try:
            people = builder.from_history("HEAD")
        finally:
            builder.ROOT = old_root
        check("both signers are found", set(people) == {"dana@example.test", "sam@example.test"},
              str(sorted(people)))
        check("the first date is the earlier commit",
              people["dana@example.test"]["first"] <= people["sam@example.test"]["first"],
              str(people))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


# ---------- the whole thing, against the real repository ----------

def repo_with_history():
    """A repository with two signers, so the test owns its own history.

    The real repository's history is not available in CI: the checks job checks out a
    shallow merge commit, so `git log --no-merges` is empty there. A test that reads it
    passes on a developer's machine and fails on the runner.
    """
    folder = tempfile.mkdtemp()

    def git(*args, **kw):
        kw.setdefault("env", git_env())
        return subprocess.run(["git"] + list(args), cwd=folder, capture_output=True,
                              text=True, **kw)

    git("init", "-q", "-b", "main")
    git("config", "user.name", "Dana Reed")
    git("config", "user.email", "dana@example.test")
    os.makedirs(os.path.join(folder, "patterns"))
    write(folder, "patterns/GP-0001.yaml", "id: GP-0001\n")
    git("add", "-A")
    subprocess.run(["git", "commit", "-q", "-m",
                    "first\n\nSigned-off-by: Dana Reed <dana@example.test>"],
                   cwd=folder, capture_output=True, text=True,
                   env=git_env({"GIT_COMMITTER_DATE": "2026-01-02T10:00:00",
                                "GIT_AUTHOR_DATE": "2026-01-02T10:00:00"}))
    write(folder, "patterns/GP-0002.yaml", "id: GP-0002\n")
    git("add", "-A")
    subprocess.run(["git", "commit", "-q", "-m",
                    "second\n\nSigned-off-by: Sam Okafor <sam@example.test>"],
                   cwd=folder, capture_output=True, text=True,
                   env=git_env({"GIT_COMMITTER_DATE": "2026-03-04T10:00:00",
                                "GIT_AUTHOR_DATE": "2026-03-04T10:00:00"}))
    return folder


def build_in(folder, contributors_md=None):
    """Run the builder against a throwaway repository."""
    if contributors_md is not None:
        write(folder, "CONTRIBUTORS.md", contributors_md)
    old_root, old_file = builder.ROOT, builder.from_contributors_file
    builder.ROOT = folder
    builder.from_contributors_file = lambda p=None: old_file(
        os.path.join(folder, "CONTRIBUTORS.md"))
    old_patterns = builder.from_patterns
    builder.from_patterns = lambda f=None: {}
    try:
        return builder.build("HEAD")
    finally:
        builder.ROOT = old_root
        builder.from_contributors_file = old_file
        builder.from_patterns = old_patterns


def test_people_carry_the_date_of_their_first_contribution():
    folder = repo_with_history()
    try:
        data = build_in(folder, """| Name | GitHub | Organization | Contributions |
| --- | --- | --- | --- |
| Dana Reed | [@danareed](https://github.com/danareed) | Example Corp | Patterns |
""")
        names = [p["name"] for p in data["people"]]
        check("both signers are listed", names == ["Dana Reed", "Sam Okafor"], str(names))
        check("each carries a first contribution date",
              all(p["first_contribution"] for p in data["people"]),
              str([p["first_contribution"] for p in data["people"]]))
        check("ordered by first contribution",
              data["people"][0]["first_contribution"] < data["people"][1]["first_contribution"],
              str([p["first_contribution"] for p in data["people"]]))
        check("the opted in handle is attached", data["people"][0]["github"] == "danareed",
              str(data["people"][0]))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_an_opted_in_organization_appears_and_an_absent_one_does_not():
    folder = repo_with_history()
    try:
        data = build_in(folder, """| Name | GitHub | Organization | Contributions |
| --- | --- | --- | --- |
| Dana Reed | [@danareed](https://github.com/danareed) | Example Corp | Patterns |
| Sam Okafor | | | Docs |
""")
        organizations = [o["name"] for o in data["organizations"]]
        check("an opted in organization is listed", organizations == ["Example Corp"],
              str(organizations))
        check("someone who opted out brings no organization",
              all(p["organization"] is None for p in data["people"] if p["name"] == "Sam Okafor"),
              str(data["people"]))
        check("the organization carries the date of its first contribution",
              data["organizations"][0]["first_contribution"] == "2026-01-02",
              str(data["organizations"]))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_the_real_repository_builds():
    """A smoke test that does not depend on how deeply the repository was cloned."""
    data = builder.build("HEAD")
    check("it produces a people list", isinstance(data["people"], list), str(type(data["people"])))
    check("the founding maintainer is there through the pattern credits",
          any(p["name"] == "Frank Albanese" for p in data["people"]),
          str([p["name"] for p in data["people"]]))
    check("no organization is listed without an opt-in", data["organizations"] == [],
          str(data["organizations"]))
    check("the note says contributing organizations, not partners",
          "not partners" in data["note"], data["note"])


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
