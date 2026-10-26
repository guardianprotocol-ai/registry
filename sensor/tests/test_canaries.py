"""Tests for canaries the operator registers.

Three properties carry this feature, and every one of them is a way to lose a secret rather
than a way to be wrong about one:

the value is never stored, the value is never emitted, and a canary does not block until the
operator says it may.

Most of what follows checks those. The rest checks the shape of what gets refused, because a
feature that accepts a five character canary will be switched off within a day by the false
alarms it causes, and a feature switched off protects nobody.

Run from the sensor folder:  python3 tests/test_canaries.py
"""
import io
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_sensor import canaries, canary_cli  # noqa: E402

failures = []
SECRET = "sk-live-9f2bAcD7xK3mQ"
OTHER = "ghp-ZZ18qWe4RtY7uIo9"


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def fresh():
    return canaries.load(os.path.join(tempfile.mkdtemp(), "none.json"))


# ---------- the value is never stored ----------

def test_the_value_is_not_in_the_file():
    with tempfile.TemporaryDirectory() as w:
        path = os.path.join(w, "canaries.json")
        store = fresh()
        canaries.add(store, SECRET, "staging payment key")
        canaries.save(store, path)
        raw = open(path, encoding="utf-8").read()
        check("the value is absent from the file", SECRET not in raw)
        check("the label is present, so a human can recognise it",
              "staging payment key" in raw)
        check("a digest is present", len(json.loads(raw)["canaries"][0]["hash"]) == 64)


def test_the_digest_is_salted():
    """An unsalted digest of an API key is the key, to anyone with the vendor's key space."""
    a, b = fresh(), fresh()
    check("two stores get different salts", a["salt"] != b["salt"])
    canaries.add(a, SECRET, "k")
    canaries.add(b, SECRET, "k")
    check("the same value digests differently under different salts",
          a["canaries"][0]["hash"] != b["canaries"][0]["hash"])


def test_the_file_is_not_world_readable():
    with tempfile.TemporaryDirectory() as w:
        path = canaries.save(fresh(), os.path.join(w, "c.json"))
        mode = os.stat(path).st_mode & 0o777
        check("the file is owner only", mode == 0o600, oct(mode))


# ---------- matching ----------

def test_a_registered_value_is_found_inside_a_larger_body():
    """A whole-body hash cannot do this, which is why candidate tokens are hashed."""
    store = fresh()
    canaries.add(store, SECRET, "staging payment key")
    hits = canaries.matches(store, f"here is the deploy key {SECRET} for the runner")
    check("the canary is found in a sentence", [h["label"] for h in hits] == ["staging payment key"],
          str(hits))
    check("nothing is found when it is absent",
          canaries.matches(store, "an ordinary message about shipping") == [])
    check("a near miss is not a hit",
          canaries.matches(store, "sk-live-9f2bAcD7xK3mZ") == [])


def test_several_canaries_are_each_reported_once():
    store = fresh()
    canaries.add(store, SECRET, "one")
    canaries.add(store, OTHER, "two")
    hits = canaries.matches(store, f"{SECRET} and {OTHER} and {SECRET} again")
    check("both are found", sorted(h["label"] for h in hits) == ["one", "two"], str(hits))
    check("a repeated value is reported once", len(hits) == 2, str(hits))


def test_matching_is_case_sensitive():
    """Credentials are case sensitive, so folding case would invent false alarms."""
    store = fresh()
    canaries.add(store, SECRET, "k")
    check("an upper case variant is not a hit",
          canaries.matches(store, SECRET.upper()) == [])


def test_an_empty_store_matches_nothing():
    check("an empty store is quiet", canaries.matches(fresh(), SECRET) == [])
    check("empty text is quiet", canaries.matches(fresh(), "") == [])
    check("missing text is quiet", canaries.matches(fresh(), None) == [])


# ---------- what is refused ----------

def test_a_short_value_is_refused():
    store = fresh()
    for bad in ("admin", "hunter2", "short12345"):
        try:
            canaries.add(store, bad, "k")
            check(f"a {len(bad)} character value is refused", False, "it was accepted")
        except canaries.CanaryError as e:
            check(f"a {len(bad)} character value is refused", "at least" in str(e), str(e))


def test_a_value_with_spaces_is_refused():
    """It would never be found as a token, so registering it is a false sense of cover."""
    try:
        canaries.add(fresh(), "this is a long passphrase", "k")
        check("a value with spaces is refused", False, "it was accepted")
    except canaries.CanaryError as e:
        check("a value with spaces is refused", "not matched as a token" in str(e), str(e))


def test_a_label_containing_the_value_is_refused():
    """The label is stored in the clear and travels into evidence."""
    try:
        canaries.add(fresh(), SECRET, f"the key {SECRET}")
        check("a label containing the value is refused", False, "it was accepted")
    except canaries.CanaryError as e:
        check("a label containing the value is refused", "must not be the secret" in str(e),
              str(e))


def test_a_duplicate_is_refused_and_names_the_existing_label():
    store = fresh()
    canaries.add(store, SECRET, "staging payment key")
    try:
        canaries.add(store, SECRET, "a different label")
        check("a duplicate value is refused", False, "it was accepted")
    except canaries.CanaryError as e:
        check("a duplicate value is refused", "already registered" in str(e), str(e))
        check("and the error does not contain the value", SECRET not in str(e), str(e))


def test_a_file_from_another_schema_version_is_refused():
    with tempfile.TemporaryDirectory() as w:
        path = os.path.join(w, "c.json")
        json.dump({"schema_version": 99, "salt": "ab" * 16, "canaries": []}, open(path, "w"))
        try:
            canaries.load(path)
            check("a future schema version is refused", False, "it was accepted")
        except canaries.CanaryError as e:
            check("a future schema version is refused", "schema_version" in str(e), str(e))


def test_a_file_with_no_salt_is_refused():
    """Without the salt the digests cannot be checked, so quietly continuing would mean
    watching for nothing while appearing to watch."""
    with tempfile.TemporaryDirectory() as w:
        path = os.path.join(w, "c.json")
        json.dump({"schema_version": 1, "canaries": [{"label": "k", "hash": "x"}]},
                  open(path, "w"))
        try:
            canaries.load(path)
            check("a file with no salt is refused", False, "it was accepted")
        except canaries.CanaryError as e:
            check("a file with no salt is refused", "salt" in str(e), str(e))


# ---------- what may be said about a hit ----------

def test_a_hit_reports_the_label_and_never_the_value():
    store = fresh()
    entry = canaries.add(store, SECRET, "staging payment key")
    said = canaries.redacted(entry)
    check("the label is reported", said["canary"] == "staging payment key", str(said))
    check("the state is reported", said["state"] == canaries.BASELINE, str(said))
    check("nothing else is reported", sorted(said) == ["canary", "state"], str(said))
    check("the digest is not reported", "hash" not in said, str(said))
    check("the value is nowhere in it", SECRET not in json.dumps(said))


# ---------- the command line ----------

def test_the_value_is_read_from_a_pipe_not_an_argument():
    """An argument lands in shell history and the process table."""
    with tempfile.TemporaryDirectory() as w:
        path = os.path.join(w, "c.json")
        out = io.StringIO()
        code = canary_cli.main(["add", "--label", "staging", "--file", path],
                               out=out, stream=io.StringIO(SECRET + "\n"))
        check("it registers from standard input", code == 0, out.getvalue())
        check("it says the value was not stored",
              "was not stored" in out.getvalue(), out.getvalue())
        check("the value is not in the output", SECRET not in out.getvalue())
        check("the value is not in the file", SECRET not in open(path).read())
        check("it tells the operator how to arm it",
              "canary arm --label" in out.getvalue(), out.getvalue())


def test_the_command_line_refuses_and_explains():
    with tempfile.TemporaryDirectory() as w:
        path = os.path.join(w, "c.json")
        out = io.StringIO()
        code = canary_cli.main(["add", "--label", "k", "--file", path],
                               out=out, stream=io.StringIO("short\n"))
        check("a short value is refused at the command line", code == 1, out.getvalue())
        check("and the reason is given", "at least" in out.getvalue(), out.getvalue())
        out = io.StringIO()
        code = canary_cli.main(["add", "--label", "k", "--file", path],
                               out=out, stream=io.StringIO("\n"))
        check("an empty value is refused", code == 2, out.getvalue())


def test_list_arm_and_remove():
    with tempfile.TemporaryDirectory() as w:
        path = os.path.join(w, "c.json")
        out = io.StringIO()
        canary_cli.main(["list", "--file", path], out=out)
        check("an empty list says the sensor watches nothing of yours",
              "not for" in out.getvalue(), out.getvalue())

        canary_cli.main(["add", "--label", "staging", "--file", path],
                        out=io.StringIO(), stream=io.StringIO(SECRET + "\n"))
        out = io.StringIO()
        canary_cli.main(["list", "--file", path], out=out)
        check("the canary is listed by label", "staging" in out.getvalue(), out.getvalue())
        check("the list shows its state", "baseline" in out.getvalue(), out.getvalue())
        check("the list does not show the value", SECRET not in out.getvalue())

        out = io.StringIO()
        check("arming works", canary_cli.main(["arm", "--label", "staging", "--file", path],
                                              out=out) == 0, out.getvalue())
        check("and it says a hit will now block", "will now block" in out.getvalue(),
              out.getvalue())
        check("the state is persisted",
              canaries.load(path)["canaries"][0]["state"] == canaries.ARMED)

        out = io.StringIO()
        check("arming an unknown label fails",
              canary_cli.main(["arm", "--label", "nope", "--file", path], out=out) == 1)
        out = io.StringIO()
        check("removing works",
              canary_cli.main(["remove", "--label", "staging", "--file", path], out=out) == 0)
        check("the store is empty afterwards", canaries.load(path)["canaries"] == [])


def test_hit_counts_come_from_the_evidence_log():
    """A counter that always reads zero would have an operator arm a canary that had been
    firing all week, which is the opposite of what the baseline period is for."""
    with tempfile.TemporaryDirectory() as w:
        path = os.path.join(w, "evidence.jsonl")
        check("a missing evidence log counts nothing", canaries.hits_by_label(path) == {})
        with open(path, "w", encoding="utf-8") as f:
            for label in ("staging payment key", "staging payment key", "unused row"):
                f.write(json.dumps({"patterns": ["GP-0020"], "action": "flagged",
                                    "detail": {"canary": label}}) + "\n")
            f.write(json.dumps({"patterns": ["GP-0002"], "action": "blocked",
                                "detail": {"canary": "not a canary record"}}) + "\n")
            f.write("\n")
            f.write("not json at all\n")
        counts = canaries.hits_by_label(path)
        check("hits are counted per label",
              counts == {"staging payment key": 2, "unused row": 1}, str(counts))
        check("records for other patterns are not counted",
              "not a canary record" not in counts, str(counts))


def test_no_hit_counter_is_stored_in_the_canary_file():
    """It would give the component holding the digests a write path on a hot code path."""
    entry = canaries.add(fresh(), SECRET, "k")
    check("the entry carries no counter", "hits" not in entry, str(entry))
    check("it carries what a human needs", sorted(entry) == ["hash", "label", "state"],
          str(sorted(entry)))


def test_the_list_warns_when_a_baseline_canary_is_already_firing():
    with tempfile.TemporaryDirectory() as w:
        path, ev = os.path.join(w, "c.json"), os.path.join(w, "evidence.jsonl")
        canary_cli.main(["add", "--label", "noisy", "--file", path],
                        out=io.StringIO(), stream=io.StringIO(SECRET + "\n"))
        canary_cli.main(["add", "--label", "quiet", "--file", path],
                        out=io.StringIO(), stream=io.StringIO(OTHER + "\n"))
        with open(ev, "w", encoding="utf-8") as f:
            f.write(json.dumps({"patterns": ["GP-0020"], "action": "flagged",
                                "detail": {"canary": "noisy"}}) + "\n")
        out = io.StringIO()
        canary_cli.main(["list", "--file", path, "--evidence", ev], out=out)
        text = out.getvalue()
        check("the firing canary shows a real count", "noisy" in text and " 1" in text, text)
        check("it is named as already firing", "already firing: noisy" in text, text)
        check("and the operator is told to move it rather than arm it",
              "Move the canary rather than arming it" in text, text)
        check("the quiet one is named as ready to consider arming",
              "quiet so far: quiet" in text, text)


def test_a_canary_is_found_in_the_shapes_a_secret_travels_in():
    """Three of the six commonest shapes were missed, including a query string.

    The token class keeps "=" because base64 ends with it and a path keeps "/", but that
    meant "token=SECRET" arrived as a single token and never matched a secret stored on
    its own. A credential leaving in a URL is the likeliest way one leaves at all, so
    this was a hole in the rule that matters most.
    """
    folder = tempfile.mkdtemp()
    try:
        store = canaries.load(os.path.join(folder, "c.json"))
        canaries.add(store, "GP9999-CANARY-prod", "prod", canaries.ARMED)
        for text in ["GP9999-CANARY-prod",
                     "token=GP9999-CANARY-prod",
                     "Authorization: Bearer GP9999-CANARY-prod",
                     "https://somewhere.test/?k=GP9999-CANARY-prod",
                     '{"api_key":"GP9999-CANARY-prod"}',
                     "API_KEY=GP9999-CANARY-prod",
                     "a=1&k=GP9999-CANARY-prod&b=2"]:
            check("found in %s" % text[:34],
                  len(canaries.matches(store, text)) == 1, text)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_splitting_does_not_lose_a_base64_value():
    """A base64 value ends in "=". Splitting on separators without trying the whole
    token first would be the way to miss that one instead."""
    folder = tempfile.mkdtemp()
    try:
        store = canaries.load(os.path.join(folder, "c.json"))
        canaries.add(store, "dGhpcyBpcyBhIHRlc3Q=", "encoded", canaries.ARMED)
        check("a padded value is still found",
              len(canaries.matches(store, "value dGhpcyBpcyBhIHRlc3Q= here")) == 1)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_an_unrelated_value_is_not_a_match():
    """Splitting creates more candidates, so it is worth showing it did not start
    matching things it should not."""
    folder = tempfile.mkdtemp()
    try:
        store = canaries.load(os.path.join(folder, "c.json"))
        canaries.add(store, "GP9999-CANARY-prod", "prod", canaries.ARMED)
        for text in ["token=GP9999-CANARY-staging", "API_KEY=something-else-entirely",
                     "https://somewhere.test/?k=nothing-to-see", "k=short"]:
            check("not matched: %s" % text[:34], canaries.matches(store, text) == [],
                  text)
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
