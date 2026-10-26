"""Tests for the sign-off gate.

The Developer Certificate of Origin is the mechanism that lets this project accept
contributions and hand them to a foundation later, so the gate that enforces it is worth
testing. It had none.

Each test builds its own repository. Reading the real one would make the result depend on
whoever committed last.

Run from the repository root:  python3 scripts/tests/test_check_signoff.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import check_signoff  # noqa: E402

failures = []

ISOLATED = {
    # A contributor with commit.gpgsign set globally would otherwise see these fail with
    # no sign of why.
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + str(detail)}")
    if not condition:
        failures.append(name)


def build(commits):
    """A repository with one commit per (name, email, signed_off_by) given."""
    folder = tempfile.mkdtemp()

    def git(*args, **env):
        return subprocess.run(["git"] + list(args), cwd=folder, capture_output=True,
                              text=True, env={**os.environ, **ISOLATED, **env})

    git("init", "-q", "-b", "main")
    open(os.path.join(folder, "base.txt"), "w").write("base\n")
    git("add", "-A")
    git("commit", "-q", "-m", "base\n\nSigned-off-by: Base <base@example.test>",
        GIT_AUTHOR_NAME="Base", GIT_AUTHOR_EMAIL="base@example.test",
        GIT_COMMITTER_NAME="Base", GIT_COMMITTER_EMAIL="base@example.test")
    for i, (name, email, signer) in enumerate(commits):
        open(os.path.join(folder, f"f{i}.txt"), "w").write("x\n")
        git("add", "-A")
        message = f"change {i}"
        if signer:
            message += f"\n\nSigned-off-by: {name} <{signer}>"
        git("commit", "-q", "-m", message,
            GIT_AUTHOR_NAME=name, GIT_AUTHOR_EMAIL=email,
            GIT_COMMITTER_NAME=name, GIT_COMMITTER_EMAIL=email)
    return folder


def run(folder, base="HEAD~1", head="HEAD"):
    here = os.getcwd()
    os.chdir(folder)
    try:
        return check_signoff.main(["check_signoff.py", base, head])
    finally:
        os.chdir(here)


def test_a_signed_commit_passes():
    folder = build([("Dana Reed", "dana@example.test", "dana@example.test")])
    try:
        check("a commit signed by its author passes", run(folder) == 0)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_an_unsigned_commit_fails():
    folder = build([("Dana Reed", "dana@example.test", None)])
    try:
        check("a commit with no trailer fails", run(folder) == 1)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_one_person_cannot_certify_another():
    """The whole point of matching the author: a sign-off is a statement about your own
    right to contribute, not somebody else's."""
    folder = build([("Dana Reed", "dana@example.test", "sam@example.test")])
    try:
        check("a sign-off naming somebody else fails", run(folder) == 1)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_automation_is_skipped_rather_than_faked():
    """A bot has no person to make the certification.

    Signing on its behalf would be a human certifying work they did not write, which is
    worse than recording that nobody did. Responsibility sits with whoever merges it.
    """
    for email in check_signoff.BOT_AUTHORS:
        folder = build([("a bot", email, None)])
        try:
            check("an unsigned commit by %s passes" % email.split("@")[0],
                  run(folder) == 0, email)
        finally:
            shutil.rmtree(folder, ignore_errors=True)


def test_a_person_is_not_exempt_for_having_bot_in_their_address():
    """The list is exact on purpose. Somebody called Abbot still certifies their work."""
    folder = build([("Pat Abbot", "abbot@example.test", None)])
    try:
        check("a person whose address contains bot still has to sign", run(folder) == 1)
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    folder = build([("Imposter", "dependabot[bot]@evil.test", None)])
    try:
        check("an address merely resembling the bot still has to sign", run(folder) == 1)
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
