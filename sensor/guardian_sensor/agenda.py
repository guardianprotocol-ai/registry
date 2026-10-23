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
import email.utils
import json
import os
import sys
import urllib.request

from . import called
from . import drill, hub

AGENDA_NAME = "agenda.json"
LOCK_NAME = ".agenda.lock"
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


class Unwritable(Exception):
    """Where we were told to keep state cannot be written to."""

    def __init__(self, path, cause):
        self.path = path
        self.cause = cause
        super().__init__("%s: %s" % (path, cause))


class _OnlyOne:
    """An exclusive lock, so two polls cannot run the same exercise twice.

    A service manager starts the next poll on a timer whether or not the last one finished.
    Normally a poll takes under a second, but a slow publisher can hold the fetch for its
    full timeout and a hanging exercise holds it longer, and then two polls overlap. Both see
    an exercise that has not run, and both run it.

    That is not a crash. It is worse: the participant's sightings carry the same exercise two
    or three times, so one organization appears in an aggregate to have seen something
    repeatedly, and the counts a study reports are quietly wrong.

    Held for the whole poll and released on exit, including on a crash, because the operating
    system drops the lock with the file handle.
    """

    def __init__(self, path):
        self.path = path
        self.handle = None

    def __enter__(self):
        try:
            import fcntl
        except ImportError:
            # No advisory locking here. Say nothing and carry on: a missing lock is a risk of
            # double counting, while refusing to run at all is a certainty of no data.
            return True
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            self.handle = open(self.path, "w")
        except OSError as e:
            # A managed laptop may not let anything write where we expected, which is a
            # common enough arrangement in the organizations this is built for. Raised as
            # something the caller can explain, rather than a traceback a participant has to
            # interpret.
            raise Unwritable(self.path, e)
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            self.handle = None
            return False
        return True

    def __exit__(self, *exc):
        if self.handle is not None:
            self.handle.close()
            self.handle = None
        return False


def _fetch(url, opener=None):
    """Fetch the agenda, and the publishing point's own clock if it offers one.

    Returns (body, skew_seconds_or_None). A sighting's hour comes from the participant's
    clock, so a machine that has been asleep and drifted puts its detections in the wrong
    hour bucket. Nothing here can correct somebody's clock, but a study measuring time across
    machines has to know when a reading is unreliable, and the server it just spoke to
    reports its own time for free.
    """
    opener = opener or urllib.request.urlopen
    with opener(url, timeout=30) as response:
        body = response.read()
        skew = None
        try:
            served = response.headers.get("Date")
            if served:
                when = email.utils.parsedate_to_datetime(served)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=datetime.timezone.utc)
                skew = (datetime.datetime.now(datetime.timezone.utc) - when).total_seconds()
        except (AttributeError, TypeError, ValueError):
            skew = None
        return body, skew


# How far a clock may drift before an hour bucket stops meaning anything. An hour is the
# finest granularity a sighting carries, so half of one is where a reading starts landing in
# the wrong bucket.
SKEW_LIMIT_SECONDS = 1800


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
            "the agenda carries %s, which this sensor does not understand. Either this sensor "
            "is older than the agenda, in which case update it and the exercise will run on "
            "the next poll, or the agenda is asking for something this sensor does not offer. "
            "An unknown key is refused rather than ignored, because ignoring one means a "
            "later version would obey what this one dropped." % ", ".join(extra))
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
    # The note is attacker controlled text printed to a participant's terminal. Escape
    # sequences there can clear their screen, rewrite the title bar, or in some terminals do
    # considerably worse, so a control character is a refusal rather than something to strip.
    # Stripping would let a hostile publisher decide what a human reads and get away with it
    # quietly; refusing makes the attempt visible.
    bad = sorted({c for c in note if ord(c) < 0x20 or ord(c) == 0x7f})
    if bad:
        raise hub.HubError(
            "note contains control characters (%s), which can rewrite a terminal. A note is "
            "read by a person, so it may only contain printable text."
            % ", ".join("0x%02x" % ord(c) for c in bad))
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
                if (record.get("exercise_id") == exercise_id
                        and record.get("outcome") in ("ran", "failed")):
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


# How often a quiet poll leaves any trace. Polling every sixty seconds for a month is about
# forty three thousand polls, and a line each would be two megabytes of "nothing happened"
# per participant, with the one line that matters buried in it. So a quiet poll is silent,
# and a heartbeat is recorded once a day instead: enough to prove the machine is alive,
# little enough that the log stays readable.
HEARTBEAT_HOURS = 24


def last_record(log_path):
    """The most recent record in the log, or None."""
    found = None
    try:
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    found = json.loads(line)
                except ValueError:
                    continue
    except OSError:
        return None
    return found


def heartbeat_due(log_path, at):
    """Whether it is time to leave a sign of life."""
    previous = last_record(log_path)
    if previous is None:
        return True
    try:
        when = datetime.datetime.fromisoformat(previous["time"])
    except (KeyError, TypeError, ValueError):
        return True
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return (at - when) >= datetime.timedelta(hours=HEARTBEAT_HOURS)


def module_is_present():
    """Whether the code this service points at is still where it was installed from.

    A participant who moves or deletes their clone after enrolling would otherwise have a
    service that fails every minute forever while they believe they are taking part. The
    import having worked is the check: this function only exists to be called from a place
    that can say so usefully.
    """
    return os.path.isdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main(argv=None, out=sys.stdout, opener=None, now=None):
    ap = argparse.ArgumentParser(
        prog="guardian_sensor agenda",
        description="Run a published exercise when its time has come. Safe to run hourly.")
    ap.add_argument("--base", default=None,
                    help="base URL holding agenda.json. Omit with --offline")
    ap.add_argument("--offline", action="store_true",
                    help="run on a local schedule and fetch nothing. The control arm for the "
                         "network: what a sensor is worth on its own")
    ap.add_argument("--every-hours", type=int, default=24,
                    help="with --offline, how often to run the exercise. Default 24")
    ap.add_argument("--org", default=os.environ.get("GUARDIAN_ORG"))
    ap.add_argument("--dir", default=DEFAULT_DIR)
    ap.add_argument("--log", default=DEFAULT_LOG)
    ap.add_argument("--dry-run", action="store_true",
                    help="say what would happen and run nothing")
    a = ap.parse_args([] if argv is None else argv)
    at = now or _now()

    if not a.offline and not a.base:
        out.write("Give --base, or --offline to run on a local schedule and fetch nothing.\n")
        return 2

    lock_path = os.path.join(os.path.dirname(os.path.abspath(a.log)) or ".", LOCK_NAME)
    try:
        with _OnlyOne(lock_path) as acquired:
            if not acquired:
                # Another poll is already working. Saying nothing is right: this happens on
                # a timer, so a message here would be noise on a machine that is behaving.
                return 0
            return _poll(a, at, out, opener)
    except Unwritable as e:
        # Running without being able to record would mean no way to tell an exercise has
        # already run, so the same one would repeat on every poll and a member's sightings
        # would fill with it. Refusing is the safe direction, and saying where to point it
        # instead is the useful part.
        out.write("Cannot keep state in %s (%s).\n" % (os.path.dirname(e.path), e.cause))
        out.write("Nothing ran, because without a record there is no way to tell an "
                  "exercise from a repeat of it.\n")
        out.write("Point it somewhere writable with --log and --dir, then enrol again:\n\n")
        out.write("  %s agenda --base %s --log <path> --dir <path>\n"
                  % (called.invocation(), a.base))
        return 1


def _offline(a, at, out):
    """Run the exercise on a local cadence, reaching out to nothing.

    This is the control arm for the whole network claim. The thesis is that value grows as
    more organizations take part, and that cannot be argued without measuring what a sensor
    is worth alone. Without this arm, "sharing helps" is unfalsifiable and a reviewer will
    say so.

    It also widens who can take part. Somebody behind an egress proxy that will not reach an
    agenda URL can still run the sensor and hand over a file, and until now that person was
    excluded by a design decision nobody made on purpose.
    """
    previous = last_record(a.log)
    if previous is not None:
        try:
            when = datetime.datetime.fromisoformat(previous["time"])
            if when.tzinfo is None:
                when = when.replace(tzinfo=datetime.timezone.utc)
            if (at - when) < datetime.timedelta(hours=a.every_hours):
                return 0
        except (KeyError, TypeError, ValueError):
            pass

    exercise_id = "offline-%s" % at.strftime("%Y-%m-%dT%H")
    out.write("Running the local exercise %s. Nothing was fetched and nothing is shared.\n"
              % exercise_id)
    argv_for_drill = ["--dir", a.dir] + (["--org", a.org] if a.org else [])
    code = drill.main(argv_for_drill, out=out)
    record(a.log, exercise_id, "ran" if code == 0 else "failed",
           "offline, drill exit %d" % code, settings={"offline": True})
    return code


def _poll(a, at, out, opener):
    if a.offline:
        return _offline(a, at, out)
    url = a.base.rstrip("/") + "/" + AGENDA_NAME
    skew = None
    try:
        body, skew = _fetch(url, opener)
        document = json.loads(body.decode("utf-8"))
    except Exception as e:
        # A missing or unreachable agenda is the ordinary case between exercises, so a quiet
        # poll says nothing at all. A service that narrates every minute buries the one line
        # that matters and fills a participant's disk with it.
        if heartbeat_due(a.log, at):
            record(a.log, "", "waiting", "no agenda at %s (%s)" % (url, type(e).__name__))
            out.write("no agenda at %s (%s). Waiting.\n" % (url, type(e).__name__))
        return 0

    try:
        exercise_id, run_after, settings, note = parse(document)
    except hub.HubError as e:
        out.write("refusing this agenda: %s\n" % e)
        # The document is hostile input and may not be an object at all, so nothing here may
        # assume its shape. An earlier version called .get on it while recording the refusal
        # and crashed on a JSON array, which stopped the poller: the machine would have left
        # the exercise silently and nobody would have noticed for a month. A refusal path
        # that can itself fail is not a refusal path.
        named = "unparsed"
        if isinstance(document, dict):
            candidate = document.get("exercise_id")
            if isinstance(candidate, str) and candidate.strip():
                named = candidate[:64]
        record(a.log, named, "refused", str(e)[:300])
        return 1

    if at < run_after:
        if heartbeat_due(a.log, at):
            record(a.log, exercise_id, "waiting",
                   "scheduled for %s" % run_after.isoformat(timespec="seconds"))
            out.write("exercise %s is scheduled for %s, which has not come yet.\n"
                      % (exercise_id, run_after.isoformat(timespec="seconds")))
        return 0
    if already_ran(a.log, exercise_id):
        if heartbeat_due(a.log, at):
            record(a.log, exercise_id, "waiting", "already run here")
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
    # Said out loud, because a participant can fix their clock and nobody else can, and
    # because a reading from a drifted machine should not be quietly averaged with the rest.
    if skew is not None and abs(skew) > SKEW_LIMIT_SECONDS:
        out.write("This machine's clock is %d minutes %s the publishing point. An hour is "
                  "the finest\ntime a sighting carries, so this run will land in the wrong "
                  "hour. Worth fixing.\n"
                  % (abs(skew) / 60, "ahead of" if skew > 0 else "behind"))
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
    if skew is not None:
        settings = dict(settings)
    record(a.log, exercise_id, "ran" if code == 0 else "failed",
           "drill exit %d%s" % (code, "" if skew is None else ", clock skew %ds" % round(skew)),
           settings=settings)

    out.write("\nRecorded in %s. Nothing has been shared: build and read a report when you "
              "are ready.\n" % a.log)
    return code
