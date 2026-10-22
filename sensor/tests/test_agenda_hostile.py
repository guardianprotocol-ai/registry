"""What a hostile publishing point can do to a participant, tried rather than argued.

The agenda is the only thing on a participant's machine that takes input from outside it.
Everything else reads local files the operator put there. So this is the whole remote attack
surface, and it is worth attacking on purpose.

The claim being tested is narrow and should stay that way: a document from a hostile
publisher cannot crash the poller, hang it, make it write outside its own directory, or make
it do anything other than run a local exercise the participant already installed. It is not a
claim that the participant is safe from everything, and it is not a claim about the transport.

Run from the sensor folder:  python3 tests/test_agenda_hostile.py
"""
import io
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_sensor import agenda, hub  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


class Hostile:
    """Serves whatever bytes a hostile publisher would serve."""

    def __init__(self, payload):
        self.payload = payload

    def __call__(self, url, timeout=None):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        if isinstance(self.payload, bytes):
            return self.payload
        return json.dumps(self.payload).encode("utf-8")


HOSTILE_DOCUMENTS = [
    ("a command", {"exercise_id": "a", "run_after": "2020-01-01T00:00:00Z",
                   "command": "rm -rf ~"}),
    ("a shell flag", {"exercise_id": "a", "run_after": "2020-01-01T00:00:00Z",
                      "shell": True}),
    ("a python payload", {"exercise_id": "a", "run_after": "2020-01-01T00:00:00Z",
                          "script": "__import__('os').system('id')"}),
    ("a path traversal in the id", {"exercise_id": "../../../../etc/cron.d/x",
                                    "run_after": "2020-01-01T00:00:00Z"}),
    ("a null byte in the id", {"exercise_id": "a\x00b",
                               "run_after": "2020-01-01T00:00:00Z"}),
    ("a newline in the id", {"exercise_id": "a\nrun_after: now",
                             "run_after": "2020-01-01T00:00:00Z"}),
    ("an absolute path as the id", {"exercise_id": "/etc/passwd",
                                    "run_after": "2020-01-01T00:00:00Z"}),
    ("a very long id", {"exercise_id": "a" * 100000,
                        "run_after": "2020-01-01T00:00:00Z"}),
    ("a very long note", {"exercise_id": "a", "run_after": "2020-01-01T00:00:00Z",
                          "note": "x" * 1000000}),
    ("terminal escapes in the note", {"exercise_id": "a", "run_after": "2020-01-01T00:00:00Z",
                                      "note": "\x1b]0;owned\x07\x1b[2J"}),
    ("a url to fetch", {"exercise_id": "a", "run_after": "2020-01-01T00:00:00Z",
                        "url": "http://evil.test/x"}),
    ("an env override", {"exercise_id": "a", "run_after": "2020-01-01T00:00:00Z",
                         "env": {"PATH": "/tmp/evil"}}),
    ("a settings command", {"exercise_id": "a", "run_after": "2020-01-01T00:00:00Z",
                            "settings": {"command": "id"}}),
    ("a settings path", {"exercise_id": "a", "run_after": "2020-01-01T00:00:00Z",
                         "settings": {"mode": "/tmp/evil"}}),
    ("an array instead of an object", ["exercise_id", "a"]),
    ("a string instead of an object", "exercise_id"),
    ("a number instead of an object", 12345),
    ("null", None),
    ("deeply nested json", {"exercise_id": "a", "run_after": "2020-01-01T00:00:00Z",
                            "note": [[[[[[[[[["deep"]]]]]]]]]]}),
    ("a non UTC time", {"exercise_id": "a", "run_after": "2020-01-01T00:00:00+05:00"}),
    ("a negative year", {"exercise_id": "a", "run_after": "-001-01-01T00:00:00Z"}),
]


def test_no_hostile_document_is_accepted_or_crashes_the_parser():
    for name, document in HOSTILE_DOCUMENTS:
        try:
            agenda.parse(document)
            accepted = True
        except hub.HubError:
            accepted = False
        except Exception as e:  # noqa: BLE001
            check(f"{name} is refused cleanly", False,
                  f"raised {type(e).__name__} instead of HubError: {e}")
            continue
        check(f"{name} is refused cleanly", not accepted, "it was accepted")


def test_a_time_in_the_past_is_accepted_because_that_is_the_normal_case():
    """Not every odd looking document is hostile. An agenda published yesterday for an
    exercise due yesterday is how a participant who was offline catches up."""
    _, run_after, _, _ = agenda.parse({"exercise_id": "a",
                                       "run_after": "0001-01-01T00:00:00Z"})
    check("a date far in the past parses", run_after.year == 1, str(run_after))


def test_malformed_bytes_do_not_crash_the_poller():
    """A hostile publisher controls the bytes, not just the structure."""
    payloads = [b"", b"{", b"not json", b"\x00\x01\x02", b"[" * 10000,
                b'{"exercise_id":' + b"9" * 100000 + b"}",
                "null".encode("utf-16"), b'{"exercise_id": "a", "run_after": }']
    for payload in payloads:
        with tempfile.TemporaryDirectory() as w:
            out = io.StringIO()
            try:
                code = agenda.main(["--base", "https://x.test",
                                    "--log", os.path.join(w, "a.jsonl")],
                                   out=out, opener=Hostile(payload))
            except Exception as e:  # noqa: BLE001
                check(f"{payload[:14]!r} does not crash the poller", False,
                      f"raised {type(e).__name__}: {e}")
                continue
            check(f"{payload[:14]!r} does not crash the poller", code in (0, 1), str(code))


def test_a_hostile_document_cannot_write_outside_the_log_it_was_given():
    """exercise_id names a file, so a traversal in it would be a traversal on disk."""
    with tempfile.TemporaryDirectory() as w:
        log = os.path.join(w, "inner", "a.jsonl")
        os.makedirs(os.path.dirname(log))
        before = set()
        for root, _, names in os.walk(w):
            before.update(os.path.join(root, n) for n in names)
        for name, document in HOSTILE_DOCUMENTS:
            try:
                agenda.main(["--base", "https://x.test", "--log", log],
                            out=io.StringIO(), opener=Hostile(document))
            except Exception:  # noqa: BLE001
                pass
        after = set()
        for root, _, names in os.walk(w):
            after.update(os.path.join(root, n) for n in names)
        created = sorted(p for p in after - before)
        check("only the log it was told to write was created",
              created in ([], [log]), str(created))
        check("nothing was written above the directory it was given",
              all(p.startswith(w) for p in after), str(sorted(after)))


def test_a_refused_document_runs_no_exercise():
    """The point of refusing. A refusal that still ran something would be no refusal."""
    with tempfile.TemporaryDirectory() as w:
        drill_dir = os.path.join(w, "d")
        for name, document in HOSTILE_DOCUMENTS:
            agenda.main(["--base", "https://x.test", "--log", os.path.join(w, "a.jsonl"),
                         "--dir", drill_dir], out=io.StringIO(), opener=Hostile(document))
        check("no drill directory was ever created", not os.path.exists(drill_dir),
              str(os.path.exists(drill_dir)))


def test_a_hostile_document_cannot_make_the_poll_take_long():
    """A poller that hangs stops participating, and nobody notices for a month."""
    slowest, which = 0.0, None
    for name, document in HOSTILE_DOCUMENTS:
        with tempfile.TemporaryDirectory() as w:
            started = time.time()
            agenda.main(["--base", "https://x.test", "--log", os.path.join(w, "a.jsonl")],
                        out=io.StringIO(), opener=Hostile(document))
            taken = time.time() - started
            if taken > slowest:
                slowest, which = taken, name
    check("every hostile document is handled in well under a second",
          slowest < 1.0, f"{which} took {slowest:.2f}s")


def test_nothing_in_the_remote_path_opens_a_socket():
    """The structural claim. There is nothing to penetrate because nothing listens.

    Checked by reading the source rather than by trusting the design, because a server
    imported later would be an easy thing to add without noticing what it changes.
    """
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    package = os.path.join(here, "guardian_sensor")
    banned = ("socketserver", "http.server", "BaseHTTPRequestHandler", "socket.bind",
              ".listen(", "asyncio.start_server", "flask", "fastapi")
    for name in sorted(os.listdir(package)):
        if not name.endswith(".py"):
            continue
        body = open(os.path.join(package, name), encoding="utf-8").read()
        for needle in banned:
            check(f"{name} does not bring in {needle}", needle not in body,
                  f"{name} contains {needle}")


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
