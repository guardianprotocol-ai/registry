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


def test_an_unwritable_home_is_explained_rather_than_raised():
    """The first thing a participant ever runs, so a traceback here is the first thing they
    see of this project. A managed laptop that locks down the home directory is normal in
    exactly the organizations this is built for."""
    with tempfile.TemporaryDirectory() as home:
        locked = os.path.join(home, "locked")
        os.makedirs(locked)
        os.chmod(locked, 0o500)
        saved = os.environ.get("HOME")
        os.environ["HOME"] = locked
        try:
            out = io.StringIO()
            code = enroll.main(["--base", BASE, "--org", "a-lab"], out=out,
                               platform="darwin", runner=Runner())
        finally:
            os.chmod(locked, 0o700)
            if saved is not None:
                os.environ["HOME"] = saved
        text = out.getvalue()
        check("it exits non zero", code == 1, str(code))
        check("it says it cannot write", "Cannot write to" in text, text[:200])
        check("it offers somewhere else", "GUARDIAN_HOME" in text, text[:400])
        check("and installs nothing", "Nothing was installed" in text, text[-200:])
        check("no traceback reaches the participant", "Traceback" not in text, text[:200])


def test_the_data_directory_can_be_moved_for_a_managed_machine():
    saved = os.environ.get("GUARDIAN_HOME")
    os.environ["GUARDIAN_HOME"] = "/somewhere/writable"
    try:
        check("the override is honoured",
              enroll.data_dir() == "/somewhere/writable", enroll.data_dir())
        # An explicit home still wins, so the tests above and any caller passing one are
        # not quietly redirected by an environment variable.
        check("an explicit home still wins",
              enroll.data_dir("/home/someone") == "/home/someone/.guardian",
              enroll.data_dir("/home/someone"))
    finally:
        if saved is None:
            del os.environ["GUARDIAN_HOME"]
        else:
            os.environ["GUARDIAN_HOME"] = saved


def test_the_service_carries_absolute_paths_into_the_override():
    """Otherwise a participant who moved the data directory would have a service writing
    somewhere else entirely, and would not find out."""
    args = enroll.agenda_args(BASE, "a-lab", "/somewhere/writable")
    pairs = dict(zip(args, args[1:]))
    check("the log is inside the override",
          pairs["--log"].startswith("/somewhere/writable"), pairs["--log"])
    check("the drill directory is too",
          pairs["--dir"].startswith("/somewhere/writable"), pairs["--dir"])


def test_the_offline_service_carries_no_url():
    """A participant behind an egress proxy that will not reach an agenda can still take
    part. Until this arm existed they were excluded by a decision nobody made on purpose."""
    args = enroll.agenda_args(None, "a-lab", "/w", offline=True, every_hours=12)
    check("it is offline", "--offline" in args, str(args))
    check("it carries the cadence", "--every-hours" in args and "12" in args, str(args))
    check("there is no base url at all", "--base" not in args, str(args))
    check("no url appears anywhere in the arguments",
          not any("http" in str(x) for x in args), str(args))
    plist = enroll.launchd_plist("/usr/bin/python3", "/m", None, "a-lab", 60, "/w", "/w",
                                 offline=True)
    check("and none in the installed service",
          not any("http" in str(x) for x in plist["ProgramArguments"]),
          str(plist["ProgramArguments"]))


def test_enrolling_offline_says_which_arm_it_is():
    out = io.StringIO()
    code = enroll.main(["--offline", "--org", "a-lab", "--print-only"], out=out,
                       platform="darwin", runner=Runner())
    text = out.getvalue()
    check("it enrols", code == 0, text[-200:])
    check("it says it reaches out to nothing", "reaches out to nothing" in text, text)
    check("and names it as the control arm", "control arm" in text, text)


def test_a_base_or_offline_is_required_to_enrol():
    out = io.StringIO()
    code = enroll.main(["--org", "a-lab"], out=out, platform="darwin", runner=Runner())
    check("neither is refused", code == 2, str(code))
    check("and both are offered", "--offline" in out.getvalue(), out.getvalue())


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
