"""Tests for status, colour, and the packaging that gives the command a short name.

Status answers the question somebody has a week after installing something and forgetting
it. Its one hard requirement is that it reads and never reports: a status command that told
anyone else about a machine's health would be the thing this protocol refuses to be.

Run from the sensor folder:  python3 tests/test_status.py
"""
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_sensor import canaries, credit, paint, status  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def populated(root, with_credit=False, armed=False):
    os.makedirs(os.path.join(root, "drill"), exist_ok=True)
    with open(os.path.join(root, "agenda.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"time": "2026-10-23T18:00:00+00:00", "exercise_id": "offline-x",
                            "outcome": "ran", "settings": {"offline": True},
                            "detail": "ok"}) + "\n")
    with open(os.path.join(root, "drill", "evidence.jsonl"), "w", encoding="utf-8") as f:
        for pattern in ("GP-0001", "GP-0003"):
            f.write(json.dumps({"time": "2026-10-23T18:00:00+00:00",
                                "patterns": [pattern], "action": "blocked",
                                "detail": {}}) + "\n")
    store = canaries.load(os.path.join(root, "absent.json"))
    canaries.add(store, "sk-live-StatusCheck9x", "staging key",
                 canaries.ARMED if armed else canaries.BASELINE)
    canaries.save(store, os.path.join(root, "canaries.json"))
    if with_credit:
        credit.save(credit.build("Ada Lovelace", "ada"), os.path.join(root, "credit.json"))


# ---------- it reads, and never reports ----------

def test_status_fetches_nothing():
    """A status command that phoned home about a machine's health would be the thing this
    protocol refuses to be."""
    body = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "guardian_sensor", "status.py"), encoding="utf-8").read()
    for forbidden in ("urllib", "requests", "socket", "http", "urlopen", "post("):
        check(f"status does not import or call {forbidden}", forbidden not in body,
              f"found {forbidden}")


def test_it_says_so_when_nothing_is_installed():
    with tempfile.TemporaryDirectory() as w:
        out = io.StringIO()
        code = status.main(["--home", os.path.join(w, "absent")], out=out)
        check("it exits non zero", code == 1, str(code))
        check("it says not taking part", "Not taking part" in out.getvalue(), out.getvalue())
        check("and offers the drill", " drill" in out.getvalue(), out.getvalue())


def test_it_reports_what_the_machine_has_done():
    with tempfile.TemporaryDirectory() as w:
        populated(w)
        out = io.StringIO()
        code = status.main(["--home", w], out=out)
        text = out.getvalue()
        check("it exits clean", code == 0, text[-200:])
        check("it counts exercises", "exercises run" in text and " 1" in text, text)
        check("it names the most recent", "offline-x" in text, text)
        check("it says which arm", "offline" in text, text)
        check("it counts detections", "detections recorded" in text, text)
        check("it lists patterns", "GP-0001, GP-0003" in text, text)
        check("it counts canaries", "1 registered, 0 armed" in text, text)


def test_it_says_what_to_do_next():
    """A status that lists facts and leaves the reader to work out the implication has done
    half the job."""
    with tempfile.TemporaryDirectory() as w:
        populated(w)
        out = io.StringIO()
        status.main(["--home", w], out=out)
        check("an uncredited participant is told how to be credited",
              "credit --name" in out.getvalue(), out.getvalue()[-300:])

    with tempfile.TemporaryDirectory() as w:
        populated(w, with_credit=True)
        out = io.StringIO()
        status.main(["--home", w], out=out)
        check("a credited participant is told nothing needs doing",
              "Nothing needs doing" in out.getvalue(), out.getvalue()[-200:])
        check("and is named", "Ada Lovelace" in out.getvalue(), out.getvalue())

    with tempfile.TemporaryDirectory() as w:
        os.makedirs(os.path.join(w, "drill"))
        out = io.StringIO()
        status.main(["--home", w], out=out)
        check("a machine that has run nothing is told so",
              "Nothing has run yet" in out.getvalue(), out.getvalue()[-200:])


def test_a_broken_canary_file_is_surfaced_not_hidden():
    with tempfile.TemporaryDirectory() as w:
        populated(w)
        with open(os.path.join(w, "canaries.json"), "w", encoding="utf-8") as f:
            json.dump({"schema_version": 99, "salt": "ab" * 16, "canaries": []}, f)
        out = io.StringIO()
        status.main(["--home", w], out=out)
        check("an unusable canary file is reported",
              "not being watched" in out.getvalue(), out.getvalue())


def test_json_output_omits_the_name():
    """Status is read-only, but its JSON could end up pasted somewhere."""
    with tempfile.TemporaryDirectory() as w:
        populated(w, with_credit=True)
        out = io.StringIO()
        status.main(["--home", w, "--json"], out=out)
        payload = json.loads(out.getvalue())
        check("it says whether credit is recorded", payload["credited"] is True,
              str(payload.get("credited")))
        check("but not the name itself", "Ada Lovelace" not in out.getvalue(),
              out.getvalue()[:200])


# ---------- colour ----------

def test_colour_is_off_unless_somebody_is_watching():
    """Each case set from a clean slate. An earlier version mutated the environment in
    sequence and the failure it produced was the test confusing itself, not the code."""
    keys = ("NO_COLOR", "FORCE_COLOR", "TERM")
    saved = {k: os.environ.get(k) for k in keys}

    def with_env(**env):
        for k in keys:
            os.environ.pop(k, None)
        for k, v in env.items():
            os.environ[k] = v
        return paint.paint("caught", "good", io.StringIO())

    try:
        check("a pipe gets no escape codes", with_env() == "caught")
        check("forcing it works", "\033[32m" in with_env(FORCE_COLOR="1"))
        check("NO_COLOR wins over forcing, because somebody who set it meant it",
              with_env(NO_COLOR="1", FORCE_COLOR="1") == "caught")
        check("a dumb terminal gets none", with_env(TERM="dumb") == "caught")
        check("forcing beats a dumb terminal, since forcing is explicit",
              "\033[32m" in with_env(FORCE_COLOR="1", TERM="dumb"))
        for k in keys:
            os.environ.pop(k, None)
        check("an unknown kind is returned untouched",
              paint.paint("caught", "nonsense", io.StringIO()) == "caught")
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ---------- packaging ----------

def test_packaging_adds_no_dependency():
    """The core is standard library only, which decision OSPS-QA-02.01 asserts. Packaging
    exists to shorten the command, not to open a door."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    body = open(os.path.join(root, "pyproject.toml"), encoding="utf-8").read()
    check("dependencies are empty", "dependencies = []" in body, body[:200])
    check("the entry point is guardian",
          'guardian = "guardian_sensor.sensor:cli"' in body, body[:400])
    check("the oldest supported Python is declared",
          'requires-python = ">=3.9"' in body, body[:300])
    check("signatures ship with the package", "signatures.json" in body, body[:600])


def test_printed_commands_match_how_the_tool_was_invoked():
    """Printing a form somebody did not type is a small way of telling them the tool was
    written for a different person, and these messages exist to be copied."""
    from guardian_sensor import called
    saved = os.environ.get("GUARDIAN_INVOCATION")
    try:
        os.environ["GUARDIAN_INVOCATION"] = "./guardian"
        check("the wrapper's name is honoured", called.invocation() == "./guardian",
              called.invocation())
        with tempfile.TemporaryDirectory() as w:
            populated(w)
            out = io.StringIO()
            status.main(["--home", w], out=out)
            check("and reaches the advice it prints",
                  "./guardian credit" in out.getvalue(), out.getvalue()[-300:])
            check("with no trace of the other form",
                  "python3 -m guardian_sensor" not in out.getvalue(),
                  out.getvalue()[-300:])
        os.environ.pop("GUARDIAN_INVOCATION")
        check("and falls back to the module form",
              called.invocation() == "python3 -m guardian_sensor", called.invocation())
    finally:
        if saved is None:
            os.environ.pop("GUARDIAN_INVOCATION", None)
        else:
            os.environ["GUARDIAN_INVOCATION"] = saved


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
