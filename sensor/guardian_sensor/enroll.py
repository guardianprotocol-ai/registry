"""One command to take part, and one to stop.

A participant should install once and then do nothing, forever. Editing a crontab is a second
step, an easy one to get wrong, and an easy one to forget doing. So this writes the service
for the platform it is on, starts it, and confirms it is running.

What it installs polls. Their machine reaches out; nothing reaches in. From the participant's
side that distinction is invisible, which is the point: they take no action after this, and
an operator can still run an exercise by publishing a file.

The unit it writes is printed before it is written, because installing something that runs
forever on somebody's machine without showing them what it is would be a poor way to ask for
their trust.

Python 3.9+ standard library only.
"""
import argparse
import os
import plistlib
import subprocess
import sys

LABEL = "network.guardianprotocol.agenda"
DEFAULT_INTERVAL = 60

# Where the service runs, and therefore where evidence, pins, canaries and the agenda log
# land. Deliberately not the module directory: that is a git checkout, and a participant's
# own records do not belong inside one. `git clean -xfd` would destroy them, updating the
# repository would be entangled with their data, and an operator asking somebody to "just
# pull" would be asking them to risk it.
def data_dir(home=None):
    # GUARDIAN_HOME exists for a participant whose home directory is managed and locked
    # down, which is normal on a corporate machine and is the audience this is for.
    override = os.environ.get("GUARDIAN_HOME")
    if override and home is None:
        return os.path.abspath(override)
    return os.path.join(home or os.path.expanduser("~"), ".guardian")


def agenda_args(base, org, work_dir, offline=False, every_hours=24):
    """The poll, with every path absolute.

    Relative defaults are resolved against the working directory, so a relative
    `.guardian/agenda.jsonl` run from inside `~/.guardian` becomes
    `~/.guardian/.guardian/agenda.jsonl`. A service runs unattended for months, so a path it
    gets slightly wrong is a path nobody notices is wrong.
    """
    where = (["--offline", "--every-hours", str(every_hours)] if offline
             else ["--base", base])
    return (["-m", "guardian_sensor", "agenda"] + where
            + ["--log", os.path.join(work_dir, "agenda.jsonl"),
               "--dir", os.path.join(work_dir, "drill")]
            + (["--org", org] if org else []))


def launchd_plist(python, module_dir, base, org, interval, log_dir, work_dir,
                  offline=False, every_hours=24):
    """A launchd agent that runs the poll on an interval and keeps running."""
    return {
        "Label": LABEL,
        "ProgramArguments": [python] + agenda_args(base, org, work_dir, offline,
                                                  every_hours),
        "WorkingDirectory": work_dir,
        "EnvironmentVariables": {"PYTHONPATH": module_dir},
        "StartInterval": interval,
        "RunAtLoad": True,
        "StandardOutPath": os.path.join(log_dir, "guardian-agenda.log"),
        "StandardErrorPath": os.path.join(log_dir, "guardian-agenda.log"),
    }


def systemd_units(python, module_dir, base, org, interval, log_dir, work_dir,
                  offline=False, every_hours=24):
    """A systemd timer and service. Returns (service_text, timer_text)."""
    args = " ".join(agenda_args(base, org, work_dir, offline, every_hours))
    service = (
        "[Unit]\n"
        "Description=Guardian Protocol exercise agenda\n"
        "Documentation=https://github.com/guardianprotocol-ai/registry\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"WorkingDirectory={work_dir}\n"
        f"Environment=PYTHONPATH={module_dir}\n"
        f"ExecStart={python} {args}\n")
    timer = (
        "[Unit]\n"
        "Description=Poll the Guardian Protocol agenda\n\n"
        "[Timer]\n"
        f"OnUnitActiveSec={interval}\n"
        "OnBootSec=60\n"
        "Persistent=true\n"
        "RandomizedDelaySec=30\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n")
    return service, timer


def paths(platform=None):
    """Where the unit goes, per platform. User scope, never system scope."""
    platform = platform or sys.platform
    home = os.path.expanduser("~")
    if platform == "darwin":
        return ("launchd", os.path.join(home, "Library", "LaunchAgents",
                                        LABEL + ".plist"))
    if platform.startswith("linux"):
        return ("systemd", os.path.join(home, ".config", "systemd", "user",
                                        "guardian-agenda.timer"))
    return (None, None)


def _run(command):
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return done.returncode, (done.stderr or done.stdout or "").strip()
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)


def main(argv=None, out=sys.stdout, platform=None, runner=None):
    ap = argparse.ArgumentParser(
        prog="guardian_sensor enroll",
        description="Take part in scheduled exercises. Installs once, then does nothing.")
    ap.add_argument("--base", default=None,
                    help="where the agenda is published. Omit with --offline")
    ap.add_argument("--offline", action="store_true",
                    help="take part without reaching out to anything. Runs the exercise on a "
                         "local schedule, fetches nothing, shares nothing")
    ap.add_argument("--every-hours", type=int, default=24,
                    help="with --offline, how often to run. Default 24")
    ap.add_argument("--org", default=os.environ.get("GUARDIAN_ORG"),
                    help="your pseudonymous member id, never a company name")
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                    help="seconds between polls. Default %d" % DEFAULT_INTERVAL)
    ap.add_argument("--print-only", action="store_true",
                    help="print the service that would be installed and install nothing")
    ap.add_argument("--brief", action="store_true",
                    help="summarize the service rather than printing all of it")
    ap.add_argument("--remove", action="store_true", help="stop taking part")
    a = ap.parse_args([] if argv is None else argv)
    run = runner or _run
    if not a.offline and not a.base and not a.remove:
        out.write("Give --base, or --offline to take part without reaching out to "
                  "anything.\n")
        return 2

    kind, path = paths(platform)
    if kind is None:
        out.write("No service manager known for this platform (%s).\n" % (platform or sys.platform))
        out.write("Run the poll from whatever scheduler you use:\n\n")
        out.write("  python3 -m guardian_sensor agenda --base %s --org %s\n"
                  % (a.base, a.org or "<your-member-id>"))
        return 1

    if a.remove:
        if kind == "launchd":
            run(["launchctl", "unload", path])
        else:
            run(["systemctl", "--user", "disable", "--now", "guardian-agenda.timer"])
        removed = False
        for p in ([path] if kind == "launchd"
                  else [path, path.replace(".timer", ".service")]):
            try:
                os.remove(p)
                removed = True
            except OSError:
                pass
        out.write("Stopped taking part.%s\n"
                  % ("" if removed else " Nothing was installed."))
        return 0

    if a.interval < 30:
        out.write("An interval under 30 seconds polls harder than anything here needs. "
                  "Use 60.\n")
        return 1

    python = sys.executable
    module_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    work_dir = data_dir()
    log_dir = work_dir
    # The first thing a participant ever runs, so a traceback here is the first thing they
    # see of this project. A managed laptop may not allow writing here at all, which is a
    # common arrangement in exactly the organizations this is built for.
    try:
        os.makedirs(work_dir, exist_ok=True)
        probe = os.path.join(work_dir, ".writable")
        with open(probe, "w") as f:
            f.write("")
        os.remove(probe)
    except OSError as e:
        out.write("Cannot write to %s (%s).\n\n" % (work_dir, e))
        out.write("This needs somewhere to keep its own records, and that is the usual "
                  "place. If your machine\nkeeps that directory locked down, say where "
                  "instead:\n\n")
        out.write("  GUARDIAN_HOME=/path/you/can/write python3 -m guardian_sensor enroll "
                  "--base %s --org %s\n\n" % (a.base, a.org or "<your-member-id>"))
        out.write("Nothing was installed.\n")
        return 1

    if kind == "launchd":
        body = plistlib.dumps(launchd_plist(python, module_dir, a.base, a.org,
                                            a.interval, log_dir, work_dir,
                                            a.offline, a.every_hours)).decode("utf-8")
        files = [(path, body)]
    else:
        service, timer = systemd_units(python, module_dir, a.base, a.org,
                                       a.interval, log_dir, work_dir,
                                       a.offline, a.every_hours)
        files = [(path.replace(".timer", ".service"), service), (path, timer)]

    # Shown before it is written. Installing something that runs forever on somebody's
    # machine without showing them what it is would be a poor way to ask for their trust.
    # Printed in full by default, because installing something that runs forever on
    # somebody's machine without showing them what it is would be a poor way to ask for
    # their trust. Summarized when asked, because thirty lines of plist in the middle of a
    # question means nobody reads either.
    if a.brief:
        out.write("This is what will be installed:\n\n")
        for where, _ in files:
            out.write("  %s\n" % where)
        out.write("\n  it runs   %s -m guardian_sensor agenda ...\n" % python)
        out.write("  as        a %s job owned by you, not the system\n"
                  % ("launchd" if kind == "launchd" else "systemd user"))
        out.write("\nSee all of it with --print-only.\n\n")
    else:
        out.write("This is what will be installed, and nothing else:\n\n")
        for where, body in files:
            out.write("  %s\n" % where)
            for line in body.strip().splitlines():
                out.write("    %s\n" % line)
            out.write("\n")
    if a.offline:
        out.write("It reaches out to nothing at all. It runs the exercise locally every %d "
                  "hours and shares\nnothing. This is the control arm: what the sensor is "
                  "worth on its own.\n" % a.every_hours)
    else:
        out.write("It polls %s every %d seconds. It never listens, and nothing can reach "
                  "in.\n" % (a.base.rstrip("/") + "/agenda.json", a.interval))
    out.write("Everything it writes stays in %s, not in the repository, so updating the "
              "code\nnever touches your records.\n" % work_dir)
    # The service points at this checkout. Moving it is the one thing a participant can do
    # that breaks participation silently, since the failure lands in a log nobody reads.
    out.write("\nIt runs the code in %s. If you move or delete that, this stops working and\n"
              "will not tell you, so run enroll again afterwards.\n" % module_dir)
    # --base is meaningless offline and printing "--base None" in the one line somebody
    # copies to undo this makes the escape hatch look broken.
    out.write("Stop at any time with: python3 -m guardian_sensor enroll --remove%s\n\n"
              % ("" if a.offline else " --base %s" % a.base))

    if a.print_only:
        out.write("Nothing was installed.\n")
        return 0

    for where, body in files:
        os.makedirs(os.path.dirname(where), exist_ok=True)
        with open(where, "w", encoding="utf-8") as f:
            f.write(body)
    os.makedirs(log_dir, exist_ok=True)

    if kind == "launchd":
        run(["launchctl", "unload", path])
        code, message = run(["launchctl", "load", path])
    else:
        run(["systemctl", "--user", "daemon-reload"])
        code, message = run(["systemctl", "--user", "enable", "--now",
                             "guardian-agenda.timer"])

    if code != 0:
        out.write("Installed the service but could not start it: %s\n" % message[:300])
        out.write("The files are in place, so starting it by hand or logging in again "
                  "should pick it up.\n")
        return 1

    out.write("Running. You are taking part, and there is nothing else to do.\n")
    if not a.org:
        out.write("\nNo member id was given, so reports will need one later. It is a "
                  "pseudonym you choose,\nnever a company name.\n")
    return 0
