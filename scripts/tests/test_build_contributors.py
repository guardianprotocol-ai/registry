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
                                  capture_output=True, text=True)
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

def test_the_real_repository_builds():
    data = builder.build("HEAD")
    check("there is at least one person", len(data["people"]) >= 1, str(data["people"])[:120])
    names = [p["name"] for p in data["people"]]
    check("the founding maintainer is listed", "Frank Albanese" in names, str(names))
    first = data["people"][0]
    check("people carry a first contribution date", bool(first["first_contribution"]), str(first))
    check("pattern credits are attached", len(first["patterns"]) >= 12, str(first["patterns"]))
    check("ordered by first contribution",
          [p["first_contribution"] or "9999" for p in data["people"]]
          == sorted(p["first_contribution"] or "9999" for p in data["people"]),
          str([p["first_contribution"] for p in data["people"]]))
    check("no organization is listed without an opt-in", data["organizations"] == [],
          str(data["organizations"]))
    check("the note says contributing organizations, not partners",
          "not partners" in data["note"] or "never \"partners\"" in data["note"], data["note"])


def test_an_opted_in_organization_appears():
    folder = tempfile.mkdtemp()
    try:
        path = write(folder, "CONTRIBUTORS.md", """| Name | GitHub | Organization | Contributions |
| --- | --- | --- | --- |
| Frank Albanese | [@faalbane](https://github.com/faalbane) | Example Corp | All |
""")
        original = builder.from_contributors_file
        builder.from_contributors_file = lambda p=None: original(path)
        try:
            data = builder.build("HEAD")
        finally:
            builder.from_contributors_file = original
        check("an opted in organization is listed",
              any(o["name"] == "Example Corp" for o in data["organizations"]),
              str(data["organizations"]))
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
