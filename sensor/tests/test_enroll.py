"""Tests for enrolling a machine in scheduled exercises.

This installs something that runs on somebody's computer for months without them looking at
it, so the failures that matter are the quiet ones: a path that is slightly wrong, data
written somewhere it will be deleted, a service that claims to be running and is not.

Both of those were real. The first version put the working directory inside the git
checkout, so a participant's evidence lived in a repository and `git clean -xfd` would have
taken it. The second resolved a relative default against that working directory and wrote to
`~/.guardian/.guardian/agenda.jsonl`, which nobody would have noticed for weeks.

Run from the sensor folder:  python3 tests/test_enroll.py
"""
import io
import os
import plistlib
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_sensor import enroll  # noqa: E402

failures = []
BASE = "https://guardianprotocol.network/season1"


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


class Runner:
    """Stands in for launchctl and systemctl."""

    def __init__(self, code=0, message=""):
        self.calls, self.code, self.message = [], code, message

    def __call__(self, command):
        self.calls.append(command)
        return self.code, self.message


# ---------- every path the service uses is absolute ----------

def test_the_service_passes_absolute_paths():
    """A relative default resolves against the working directory. Run from ~/.guardian, a
    relative .guardian/agenda.jsonl becomes ~/.guardian/.guardian/agenda.jsonl."""
    args = enroll.agenda_args(BASE, "a-lab", "/home/someone/.guardian")
    pairs = dict(zip(args, args[1:]))
    for flag in ("--log", "--dir"):
        check(f"{flag} is passed", flag in args, str(args))
        check(f"{flag} is absolute", os.path.isabs(pairs[flag]), pairs[flag])
    check("the log is not nested inside another .guardian",
          pairs["--log"].count(".guardian") == 1, pairs["--log"])
    check("the drill directory is not nested either",
          pairs["--dir"].count(".guardian") == 1, pairs["--dir"])
    check("the member id is carried", "a-lab" in args, str(args))
    check("no member id simply omits it", "--org" not in enroll.agenda_args(BASE, None, "/x"))


def test_data_never_lands_in_the_code_directory():
    """The first version did. A participant's records do not belong in a git checkout:
    `git clean -xfd` takes them and updating the code is entangled with their data."""
    work = enroll.data_dir("/home/someone")
    check("the data directory is under the home directory",
          work == "/home/someone/.guardian", work)
    module_dir = os.path.dirname(os.path.dirname(os.path.abspath(enroll.__file__)))
    plist = enroll.launchd_plist("/usr/bin/python3", module_dir, BASE, "a-lab", 60,
                                 work, work)
    check("the working directory is the data directory",
          plist["WorkingDirectory"] == work, plist["WorkingDirectory"])
    check("the working directory is not the module directory",
          plist["WorkingDirectory"] != module_dir, plist["WorkingDirectory"])
    check("the module is still importable, by path not by directory",
          plist["EnvironmentVariables"]["PYTHONPATH"] == module_dir,
          str(plist["EnvironmentVariables"]))


# ---------- the units themselves ----------

def test_the_launchd_agent_is_well_formed():
    plist = enroll.launchd_plist("/usr/bin/python3", "/m", BASE, "a-lab", 60, "/w", "/w")
    check("it round trips as a plist",
          plistlib.loads(plistlib.dumps(plist))["Label"] == enroll.LABEL)
    check("it runs on an interval", plist["StartInterval"] == 60, str(plist))
    check("it runs at load, so enrolling takes effect immediately",
          plist["RunAtLoad"] is True, str(plist))
    check("output is captured somewhere the operator can read",
          plist["StandardOutPath"].endswith(".log"), str(plist))
    check("it names no listening port and no socket",
          "Sockets" not in plist and "inetdCompatibility" not in plist, str(plist))


def test_the_systemd_timer_is_well_formed():
    service, timer = enroll.systemd_units("/usr/bin/python3", "/m", BASE, "a-lab", 60,
                                          "/w", "/w")
    check("the service is oneshot, so nothing lingers", "Type=oneshot" in service, service)
    check("the working directory is set", "WorkingDirectory=/w" in service, service)
    check("the timer repeats", "OnUnitActiveSec=60" in timer, timer)
    check("it survives a reboot", "Persistent=true" in timer, timer)
    check("it is jittered, so participants do not all poll on the same second",
          "RandomizedDelaySec" in timer, timer)
    check("it installs into the user's timers, not the system's",
          "WantedBy=timers.target" in timer, timer)


# ---------- behaviour ----------

def test_it_shows_what_it_will_install_before_installing_it():
    out = io.StringIO()
    runner = Runner()
    code = enroll.main(["--base", BASE, "--org", "a-lab", "--print-only"],
                       out=out, platform="darwin", runner=runner)
    text = out.getvalue()
    check("print only exits clean", code == 0, text[-200:])
    check("it says what will be installed", "This is what will be installed" in text, text[:120])
    check("it shows the file path", "LaunchAgents" in text, text[:400])
    check("it says how often it polls", "every 60 seconds" in text, text)
    check("it says nothing can reach in", "nothing can reach in" in text, text)
    check("it says where data goes", "not in the repository" in text, text)
    check("it says how to stop", "--remove" in text, text)
    check("and it installed nothing", "Nothing was installed" in text, text[-200:])
    check("no service manager was called", runner.calls == [], str(runner.calls))


def test_an_unknown_platform_says_so_and_gives_the_command():
    out = io.StringIO()
    code = enroll.main(["--base", BASE, "--org", "a-lab"], out=out, platform="sunos5",
                       runner=Runner())
    check("it exits non zero", code == 1, str(code))
    check("it names the platform", "sunos5" in out.getvalue(), out.getvalue())
    check("and still tells them how to take part",
          "guardian_sensor agenda --base" in out.getvalue(), out.getvalue())


def test_too_short_an_interval_is_refused():
    out = io.StringIO()
    code = enroll.main(["--base", BASE, "--interval", "5"], out=out, platform="darwin",
                       runner=Runner())
    check("a five second interval is refused", code == 1, out.getvalue())
    check("and sixty is suggested", "Use 60" in out.getvalue(), out.getvalue())


def test_a_service_that_will_not_start_is_reported_rather_than_claimed():
    """A service that says it is running and is not is the worst outcome here, because
    nobody looks again for weeks."""
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as home:
        saved = os.environ.get("HOME")
        os.environ["HOME"] = home
        try:
            code = enroll.main(["--base", BASE, "--org", "a-lab"], out=out,
                               platform="darwin", runner=Runner(1, "Load failed: 5: I/O"))
        finally:
            if saved is not None:
                os.environ["HOME"] = saved
    check("it exits non zero", code == 1, str(code))
    check("it does not claim to be running",
          "You are taking part" not in out.getvalue(), out.getvalue()[-300:])
    check("it says the start failed", "could not start it" in out.getvalue(),
          out.getvalue()[-300:])
    check("and passes on the reason", "Load failed" in out.getvalue(), out.getvalue()[-300:])


def test_removing_when_nothing_is_installed_says_so():
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as home:
        saved = os.environ.get("HOME")
        os.environ["HOME"] = home
        try:
            code = enroll.main(["--base", BASE, "--remove"], out=out, platform="darwin",
                               runner=Runner())
        finally:
            if saved is not None:
                os.environ["HOME"] = saved
    check("removing nothing exits clean", code == 0, out.getvalue())
    check("and says nothing was installed", "Nothing was installed" in out.getvalue(),
          out.getvalue())


def test_the_label_is_namespaced():
    check("the label is a reverse domain under ours",
          enroll.LABEL.startswith("network.guardianprotocol."), enroll.LABEL)


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
