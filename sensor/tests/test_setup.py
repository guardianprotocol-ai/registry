"""Tests for the guided setup.

Taking part was five commands, each needing a flag somebody had to look up. Each of those is
a place to stop, and a participant who stops at step three has installed nothing and produced
nothing. So this asks instead.

What it must not do is act before showing, or claim to have done something it did not.

Run from the sensor folder:  python3 tests/test_setup.py
"""
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_sensor import drill, enroll, hub, setup_cli  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def test_it_needs_a_terminal_and_says_what_to_do_without_one():
    """Run from cron or a script it would hang on the first question forever."""
    out = io.StringIO()
    code = setup_cli.main([], out=out)
    text = out.getvalue()
    check("it refuses without a terminal", code == 2, str(code))
    check("it says why", "needs a terminal" in text, text)
    check("and gives the two commands that do the same thing",
          "drill --org" in text and "enroll --offline" in text, text)


def test_the_member_id_is_validated_the_same_way_the_format_does():
    """A pseudonym accepted here and refused by report would be a trap."""
    for bad in ("ACME Labs", "acme labs", "a", "Acme", "acme_labs", "-acme"):
        check(f"{bad!r} is refused", setup_cli._bad_org(bad) is not None, bad)
        check(f"{bad!r} is refused by the format too",
              not hub.ORG_RE.match(bad), bad)
    for good in ("acme-labs", "north-river", "node-1"):
        check(f"{good!r} is accepted", setup_cli._bad_org(good) is None, good)
        check(f"{good!r} is accepted by the format too",
              bool(hub.ORG_RE.match(good)), good)


def test_the_refusal_explains_rather_than_just_rejecting():
    problem = setup_cli._bad_org("ACME Labs")
    check("it says the shape", "lowercase" in problem, problem)
    check("and says not a company name", "company name" in problem, problem)


def test_the_drill_can_be_told_not_to_repeat_the_next_steps():
    """Setup says what comes next itself, and a tool that gives directions somebody already
    has is lecturing rather than helping."""
    with tempfile.TemporaryDirectory() as w:
        quiet = io.StringIO()
        drill.main(["--org", "a-lab", "--dir", os.path.join(w, "q"), "--no-next-steps"],
                   out=quiet)
        loud = io.StringIO()
        drill.main(["--org", "a-lab", "--dir", os.path.join(w, "l")], out=loud)

        check("the result is printed either way", "3 of 3" in quiet.getvalue(),
              quiet.getvalue()[-200:])
        check("the claim that nothing was shared is printed either way",
              "Nothing has been shared" in quiet.getvalue(), quiet.getvalue()[-200:])
        check("the navigation is suppressed", "--preview" not in quiet.getvalue(),
              quiet.getvalue()[-200:])
        check("and printed when nobody else is going to",
              "--preview" in loud.getvalue(), loud.getvalue()[-200:])


def test_enrolling_can_summarize_instead_of_dumping_a_unit():
    """Thirty lines of plist followed by a question means nobody reads either."""
    brief, full = io.StringIO(), io.StringIO()
    enroll.main(["--offline", "--org", "a-lab", "--print-only", "--brief"], out=brief,
                platform="darwin")
    enroll.main(["--offline", "--org", "a-lab", "--print-only"], out=full,
                platform="darwin")
    check("brief is shorter than full",
          len(brief.getvalue()) < len(full.getvalue()) / 2,
          f"{len(brief.getvalue())} vs {len(full.getvalue())}")
    check("brief still names the file it writes",
          "LaunchAgents" in brief.getvalue(), brief.getvalue()[:300])
    check("brief says it is owned by you, not the system",
          "not the system" in brief.getvalue(), brief.getvalue()[:400])
    check("brief points at the full version",
          "--print-only" in brief.getvalue(), brief.getvalue()[:400])
    check("full prints the unit itself", "<plist" in full.getvalue(),
          full.getvalue()[:200])


def test_the_removal_hint_is_a_command_that_works():
    """It printed --base None for an offline install, which makes the one line somebody
    copies to undo this look broken."""
    out = io.StringIO()
    enroll.main(["--offline", "--org", "a-lab", "--print-only"], out=out, platform="darwin")
    text = out.getvalue()
    check("no None appears in the removal hint", "--base None" not in text, text[-400:])
    check("the hint is there", "--remove" in text, text[-400:])
    out = io.StringIO()
    enroll.main(["--base", "https://x.test", "--org", "a-lab", "--print-only"], out=out,
                platform="darwin")
    check("a networked install keeps its base in the hint",
          "--remove --base https://x.test" in out.getvalue(), out.getvalue()[-400:])


def test_networked_is_the_default_arm():
    """It is the arm the research needs most, and a default is the answer most people give."""
    body = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "guardian_sensor", "setup_cli.py"), encoding="utf-8").read()
    check("the default is networked", 'default="networked"' in body, "default not networked")
    check("offline is still one word away",
          '"offline", "networked", "neither"' in body, "offline not offered")
    check("and is named as the control arm rather than the lesser option",
          "control arm" in body, "offline framed as lesser")


def test_an_empty_publish_point_sets_expectations_rather_than_refusing():
    """A networked install before anything is published polls into silence, which is correct
    and looks broken."""
    class Nothing:
        def __call__(self, url, timeout=None):
            raise OSError("404")

    class Something:
        def __call__(self, url, timeout=None):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"exercise_id": "x", "run_after": "2026-10-27T14:00:00Z"}'

    check("an unreachable agenda reads as nothing published",
          setup_cli._agenda_reachable("https://x.test", Nothing()) is False)
    check("a published agenda reads as something",
          setup_cli._agenda_reachable("https://x.test", Something()) is True)


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
