"""Take part in a scheduled exercise without anyone having to be available for it.

Coordinating twenty busy people to act in the same hour does not work, and the obvious fix
is worse than the problem: a channel that lets somebody invoke actions on participants'
machines is a botnet, however well intentioned its operator. It would be the most attractive
target in the system, and it would have to be removed before production, so whatever it
proved would not be what shipped.

So the machine polls instead. A published agenda says *when*, never *what*. The action is
fixed in the installed code and is the same local, harmless drill the operator already ran by
hand. Compromising the publishing point would let an attacker make a machine run an exercise
its owner already consented to, which is the whole blast radius.

    push                      pull
    central command           published agenda
    says what to do           says when
    inbound channel           outbound fetch only
    cannot ship it            identical in production

Run from cron or launchd, hourly. Python 3.9+ standard library only.
"""
import argparse
import datetime
import json
import os
import sys
import urllib.request

from . import drill, hub

AGENDA_NAME = "agenda.json"
DEFAULT_LOG = os.path.join(".guardian", "agenda.jsonl")
DEFAULT_DIR = os.path.join(".guardian", "drill")

# The only keys an agenda may carry. A key nobody recognises is a refusal rather than
# something to ignore, because ignoring one means a later version that understands it would
# obey what an earlier one dropped.
ALLOWED_KEYS = ("exercise_id", "run_after", "respond", "note", "settings")

# The parameter space an agenda may move through, and the only values each may take.
#
# This is what makes a controlled experiment possible: the operator can schedule as many
# permutations as the study needs, in any order, without anyone being available for them.
# What it cannot do is introduce behaviour. Every value below selects among things the
# participant installed and can read in this file, so the set of possible outcomes is fixed
# at install time and auditable by the person whose machine it is.
#
# An agenda that could carry a command, a path, a URL or a script would be arbitrary
# execution on other people's machines, which is a different thing however it is labelled.
# Adding a setting here is a deliberate act with a test, not a configuration change.
SETTINGS = {
    # Whether the sensor blocks or only records. The headline comparison in any write up.
    "mode": ("block", "monitor"),
    # Whether the response half runs: the same attack before and after a rule update.
    "respond": (True, False),
    # Whether the sensor is in front at all. The control arm.
    "protected": (True, False),
}
SETTING_NAMES = tuple(sorted(SETTINGS))


def _fetch(url, opener=None):
    opener = opener or urllib.request.urlopen
    with opener(url, timeout=30) as response:
        return response.read()


def parse_settings(raw):
    """Check the settings an agenda asks for against the installed parameter space.

    Every value is compared against a fixed list. An unknown setting, or a known setting with
    an unexpected value, is refused and named, because a setting silently dropped is a
    permutation the operator believes they ran and did not.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise hub.HubError("settings must be an object")
    unknown = sorted(set(raw) - set(SETTINGS))
    if unknown:
        raise hub.HubError(
            "settings carries %s, which this sensor does not offer. It understands %s. A "
            "setting it does not know is refused rather than ignored, because a dropped "
            "setting is a permutation you would believe you had run."
            % (", ".join(unknown), ", ".join(SETTING_NAMES)))
    out = {}
    for name, value in sorted(raw.items()):
        if value not in SETTINGS[name]:
            raise hub.HubError(
                "settings.%s is %r, and may only be one of %s"
                % (name, value, ", ".join(repr(v) for v in SETTINGS[name])))
        out[name] = value
    return out


def parse(document):
    """Check an agenda. Returns (exercise_id, run_after, settings, note) or raises."""
    if not isinstance(document, dict):
        raise hub.HubError("the agenda is not an object")
    extra = sorted(set(document) - set(ALLOWED_KEYS))
    if extra:
        raise hub.HubError(
            "the agenda carries %s, which this sensor does not understand. An agenda may say "
            "when to run a local exercise and nothing else, so an unknown key is refused "
            "rather than ignored." % ", ".join(extra))
    missing = sorted({"exercise_id", "run_after"} - set(document))
    if missing:
        raise hub.HubError("the agenda is missing %s" % ", ".join(missing))

    exercise_id = document["exercise_id"]
    if not isinstance(exercise_id, str) or not exercise_id.strip():
        raise hub.HubError("exercise_id must be a non empty string")
    if len(exercise_id) > 64 or not exercise_id.replace("-", "").replace("_", "").isalnum():
        raise hub.HubError(
            "exercise_id %r must be at most 64 characters of letters, digits, hyphens and "
            "underscores. It names a file on disk, so it may not be free text." % exercise_id)

    try:
        run_after = datetime.datetime.strptime(document["run_after"], "%Y-%m-%dT%H:%M:%SZ")
        run_after = run_after.replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        raise hub.HubError("run_after must look like 2026-10-27T14:00:00Z, in UTC")

    settings = parse_settings(document.get("settings"))
    # `respond` predates `settings` and still works, so an agenda written for an earlier
    # sensor keeps running. The two must not disagree, because an operator who set both and
    # got one silently is running a permutation they did not choose.
    if "respond" in document:
        if not isinstance(document["respond"], bool):
            raise hub.HubError("respond must be true or false")
        if "respond" in settings and settings["respond"] != document["respond"]:
            raise hub.HubError(
                "the agenda sets respond twice, at the top level and in settings, and they "
                "disagree. Use settings.")
        settings.setdefault("respond", document["respond"])

    note = document.get("note", "")
    if not isinstance(note, str) or len(note) > 200:
        raise hub.HubError("note must be a string of at most 200 characters")
    return exercise_id, run_after, settings, note


def already_ran(log_path, exercise_id):
    """Whether this exercise has been run here before.

    An hourly poll would otherwise run the same exercise every hour forever, and a member's
    sightings would fill with the same drill repeated until somebody noticed.
    """
    try:
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("exercise_id") == exercise_id:
                    return True
    except OSError:
        return False
    return False


def record(log_path, exercise_id, outcome, detail="", settings=None):
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"time": _now().isoformat(timespec="seconds"),
                            "exercise_id": exercise_id, "outcome": outcome,
                            "settings": settings or {}, "detail": detail}) + "\n")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def main(argv=None, out=sys.stdout, opener=None, now=None):
    ap = argparse.ArgumentParser(
        prog="guardian_sensor agenda",
        description="Run a published exercise when its time has come. Safe to run hourly.")
    ap.add_argument("--base", required=True,
                    help="base URL holding agenda.json")
    ap.add_argument("--org", default=os.environ.get("GUARDIAN_ORG"))
    ap.add_argument("--dir", default=DEFAULT_DIR)
    ap.add_argument("--log", default=DEFAULT_LOG)
    ap.add_argument("--dry-run", action="store_true",
                    help="say what would happen and run nothing")
    a = ap.parse_args([] if argv is None else argv)
    at = now or _now()

    url = a.base.rstrip("/") + "/" + AGENDA_NAME
    try:
        document = json.loads(_fetch(url, opener).decode("utf-8"))
    except Exception as e:
        # A missing or unreachable agenda is the ordinary case between exercises. Quiet on
        # purpose, because this runs hourly and a cron job that emails on every poll gets
        # turned off within a week.
        out.write("no agenda at %s (%s)\n" % (url, type(e).__name__))
        return 0

    try:
        exercise_id, run_after, settings, note = parse(document)
    except hub.HubError as e:
        out.write("refusing this agenda: %s\n" % e)
        record(a.log, str(document.get("exercise_id", "unparsed"))[:64], "refused", str(e))
        return 1

    if at < run_after:
        out.write("exercise %s is scheduled for %s, which has not come yet.\n"
                  % (exercise_id, run_after.isoformat(timespec="seconds")))
        return 0
    if already_ran(a.log, exercise_id):
        out.write("exercise %s has already run here. Nothing to do.\n" % exercise_id)
        return 0

    described = ", ".join("%s=%s" % (k, v) for k, v in sorted(settings.items())) or "defaults"

    if a.dry_run:
        out.write("exercise %s is due and would run now, with %s.\n"
                  % (exercise_id, described))
        if note:
            out.write("note from the agenda: %s\n" % note[:200])
        return 0

    out.write("Running exercise %s, published for %s.\n"
              % (exercise_id, run_after.isoformat(timespec="seconds")))
    # Printed every run. An operator should be able to see which permutation their machine
    # took part in without reading a log, and a participant should be able to see what was
    # asked of their machine without reading our source.
    out.write("Settings for this exercise: %s\n" % described)
    if note:
        out.write("Note from the agenda: %s\n" % note[:200])

    argv_for_drill = ["--dir", a.dir] + (["--org", a.org] if a.org else [])
    if settings.get("respond"):
        argv_for_drill.append("--respond")
    if "mode" in settings:
        argv_for_drill += ["--mode", settings["mode"]]
    if settings.get("protected") is False:
        argv_for_drill.append("--unprotected")
    code = drill.main(argv_for_drill, out=out)
    record(a.log, exercise_id, "ran" if code == 0 else "failed", "drill exit %d" % code,
           settings=settings)

    out.write("\nRecorded in %s. Nothing has been shared: build and read a report when you "
              "are ready.\n" % a.log)
    return code
