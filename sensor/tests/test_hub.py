"""Tests for the sharing hub.

Run from the sensor/ folder:  python3 tests/test_hub.py

The important tests here are the ones that try to get content out. The hub's promise is
that a sightings file contains no tool names, arguments, URLs, paths or message text, and
that promise is only worth anything if something actively attacks it.
"""
import io
import json
import os
import random
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from guardian_sensor import hub, hub_cli  # noqa: E402

failures = []

# Things that must never reach a sightings file. Each is planted somewhere in the evidence.
SECRETS = [
    "GP0002-CANARY-7f3a",
    "canary@registry.test",
    "https://files.unknown.test/drop",
    "/Users/someone/.aws/credentials",
    "ACME Financial Group",
    "sk-live-abcdef0123456789",
    "notes about the Q3 acquisition",
]


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def loaded_record(**extra):
    """An evidence record with secrets in every field that normally holds content."""
    record = {
        "time": "2026-10-04T11:22:33+00:00",
        "patterns": ["GP-0002"],
        "action": "blocked",
        "reasons": ["sent " + SECRETS[0] + " to " + SECRETS[1]],
        "detail": {"tool": "send_message", "to": SECRETS[1], "body": SECRETS[0],
                   "url": SECRETS[2], "path": SECRETS[3], "org": SECRETS[4],
                   "key": SECRETS[5], "note": SECRETS[6]},
        "sensor": "guardian-sensor v0 (prototype)",
    }
    record.update(extra)
    return record


def blob_of(document):
    return json.dumps(document)


# ---------- the allow-list ----------

def test_an_entry_has_exactly_the_allowed_fields():
    doc = hub.build_sightings([loaded_record()], "acme-labs", "r2026.10.04")
    entry = doc["sightings"][0]
    check("an entry has exactly the allowed fields",
          tuple(entry) == hub.ALLOWED_FIELDS, str(tuple(entry)))


def test_no_planted_secret_reaches_the_output():
    doc = hub.build_sightings([loaded_record()], "acme-labs", "r2026.10.04")
    blob = blob_of(doc)
    leaked = [s for s in SECRETS if s in blob]
    check("no planted secret appears in the sightings", not leaked, str(leaked))
    check("the preview leaks nothing either",
          not [s for s in SECRETS if s in hub.preview_text(doc)], str(leaked))


def test_secrets_hidden_in_unexpected_fields_still_do_not_escape():
    """Someone could write anything into an evidence log. It still cannot get out."""
    record = loaded_record()
    record["surprise"] = SECRETS[2]
    record["sensor"] = SECRETS[4]
    record["time_zone"] = SECRETS[3]
    record["detail"] = SECRETS[0]
    doc = hub.build_sightings([record], "acme-labs", "r2026.10.04")
    leaked = [s for s in SECRETS if s in blob_of(doc)]
    check("unknown fields are never read", not leaked, str(leaked))


def test_a_secret_smuggled_into_a_pattern_id_is_dropped():
    for bad in ["GP-0002; " + SECRETS[2], SECRETS[1], "../../etc/passwd", "GP-2", "gp-0002"]:
        doc = hub.build_sightings([loaded_record(patterns=[bad])], "acme-labs", "r1")
        check(f"pattern id {bad[:24]!r} is refused", doc["sightings"] == [], str(doc["sightings"]))
    good = hub.build_sightings([loaded_record(patterns=["GP-0002", SECRETS[1]])], "acme-labs", "r1")
    check("a real id beside a bad one keeps only the real one",
          [e["pattern"] for e in good["sightings"]] == ["GP-0002"], str(good["sightings"]))


def test_a_secret_smuggled_into_the_action_is_dropped():
    doc = hub.build_sightings([loaded_record(action="blocked " + SECRETS[2])], "acme-labs", "r1")
    check("an unknown action is refused", doc["sightings"] == [], str(doc["sightings"]))


def test_fuzzing_the_evidence_never_produces_a_leak():
    """Secrets scattered through random fields, many times over."""
    rng = random.Random(20261004)
    bad = []
    for _ in range(300):
        record = loaded_record()
        for _ in range(rng.randint(1, 4)):
            record[f"f{rng.randint(0, 50)}"] = rng.choice(SECRETS)
        if rng.random() < 0.3:
            record["patterns"] = [rng.choice(SECRETS)]
        if rng.random() < 0.3:
            record["action"] = rng.choice(SECRETS)
        doc = hub.build_sightings([record], "acme-labs", "r1")
        bad += [s for s in SECRETS if s in blob_of(doc)]
    check("300 fuzzed records leak nothing", not bad, str(bad[:3]))


# ---------- what does get shared ----------

def test_the_timestamp_is_rounded_down_to_the_hour():
    doc = hub.build_sightings([loaded_record()], "acme-labs", "r1")
    hour = doc["sightings"][0]["hour"]
    check("the hour is kept", hour == "2026-10-04T11", hour)
    check("minutes and seconds are gone", "22" not in hour and "33" not in hour, hour)


def test_identical_hours_are_counted_not_listed():
    records = [loaded_record(time=f"2026-10-04T11:{m:02d}:00+00:00") for m in range(5)]
    doc = hub.build_sightings(records, "acme-labs", "r1")
    check("five events in one hour become one entry with a count of five",
          len(doc["sightings"]) == 1 and doc["sightings"][0]["count"] == 5,
          str(doc["sightings"]))


def test_the_member_id_has_to_look_like_a_pseudonym():
    for bad in ["", "ACME Financial Group", "a", "x" * 40, "acme labs", "Acme-Labs"]:
        try:
            hub.build_sightings([], bad, "r1")
            ok = False
        except hub.HubError:
            ok = True
        check(f"member id {bad[:20]!r} is refused", ok)
    try:
        hub.build_sightings([], "acme-labs", "r1")
        ok = True
    except hub.HubError:
        ok = False
    check("a pseudonym is accepted", ok)


def test_since_filters_by_date():
    folder = tempfile.mkdtemp()
    try:
        path = os.path.join(folder, "evidence.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps(loaded_record(time="2026-09-01T10:00:00+00:00")) + "\n")
            f.write(json.dumps(loaded_record(time="2026-10-04T10:00:00+00:00")) + "\n")
        check("all records without --since", len(hub.read_evidence([path])) == 2)
        check("--since drops the older one",
              len(hub.read_evidence([path], since="2026-10-01")) == 1)
        try:
            hub.read_evidence([path], since="last tuesday")
            ok = False
        except hub.HubError:
            ok = True
        check("a bad --since is refused", ok)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_broken_evidence_line_is_skipped_not_raised():
    folder = tempfile.mkdtemp()
    try:
        path = os.path.join(folder, "evidence.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json\n\n")
            f.write(json.dumps(loaded_record()) + "\n")
        check("a corrupt line does not stop the report", len(hub.read_evidence([path])) == 1)
        check("a missing log is not an error", hub.read_evidence(["/nope/none.jsonl"]) == [])
    finally:
        shutil.rmtree(folder, ignore_errors=True)


# ---------- rule updates ----------

def manifest_for(files, version="r2026.10.04"):
    return {"schema_version": "0.1", "rules_version": version,
            "files": {n: hub.sha256_of_bytes(d) for n, d in files.items()}}


def test_a_matching_release_verifies():
    files = {"signatures.json": b'{"a":1}', "pattern-status.json": b'{"GP-0001":"draft"}'}
    check("a matching release returns its rules version",
          hub.verify_against_manifest(manifest_for(files), files) == "r2026.10.04")


def test_a_tampered_file_is_refused():
    files = {"signatures.json": b'{"a":1}'}
    manifest = manifest_for(files)
    tampered = {"signatures.json": b'{"a":2}'}
    try:
        hub.verify_against_manifest(manifest, tampered)
        ok = False
        why = "accepted"
    except hub.HubError as e:
        ok = "does not match the manifest" in str(e)
        why = str(e)
    check("a file that does not match its hash is refused", ok, why)


def test_a_missing_or_extra_file_is_refused():
    files = {"signatures.json": b"a", "pattern-status.json": b"b"}
    manifest = manifest_for(files)
    try:
        hub.verify_against_manifest(manifest, {"signatures.json": b"a"})
        ok = False
    except hub.HubError as e:
        ok = "missing" in str(e)
    check("a release missing a file is refused", ok)
    try:
        hub.verify_against_manifest(manifest, {**files, "surprise.json": b"c"})
        ok = False
    except hub.HubError as e:
        ok = "does not cover" in str(e)
    check("a release with an uncovered file is refused", ok)


def test_a_manifest_without_a_version_is_refused():
    for manifest in [{}, {"files": {}}, {"files": {}, "rules_version": ""}, "nonsense"]:
        try:
            hub.verify_against_manifest(manifest, {})
            ok = False
        except hub.HubError:
            ok = True
        check(f"manifest {str(manifest)[:28]!r} is refused", ok)


def test_updates_are_recorded_and_read_back():
    folder = tempfile.mkdtemp()
    try:
        path = os.path.join(folder, "updates.jsonl")
        check("no updates yet means no version", hub.current_rules_version(path) is None)
        hub.record_update(path, "r2026.10.01", "https://example.test/a")
        hub.record_update(path, "r2026.10.04", "https://example.test/b")
        check("the latest version is read back",
              hub.current_rules_version(path) == "r2026.10.04", str(hub.current_rules_version(path)))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


# ---------- the command line ----------

def test_preview_writes_nothing():
    folder = tempfile.mkdtemp()
    try:
        evidence = os.path.join(folder, "evidence.jsonl")
        out = os.path.join(folder, "sightings.json")
        with open(evidence, "w", encoding="utf-8") as f:
            f.write(json.dumps(loaded_record()) + "\n")
        buf = io.StringIO()
        code = hub_cli.report(["--org", "acme-labs", "--evidence", evidence, "--out", out,
                               "--preview", "--rules-version", "r1"], out=buf)
        check("preview exits cleanly", code == 0)
        check("preview writes no file", not os.path.exists(out))
        check("preview shows the entry", "GP-0002" in buf.getvalue(), buf.getvalue()[:200])
        check("preview leaks nothing",
              not [s for s in SECRETS if s in buf.getvalue()])
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_the_written_file_contains_no_secret():
    folder = tempfile.mkdtemp()
    try:
        evidence = os.path.join(folder, "evidence.jsonl")
        out = os.path.join(folder, "sightings.json")
        with open(evidence, "w", encoding="utf-8") as f:
            for _ in range(20):
                f.write(json.dumps(loaded_record()) + "\n")
        hub_cli.report(["--org", "acme-labs", "--evidence", evidence, "--out", out,
                        "--rules-version", "r1"], out=io.StringIO())
        written = open(out, encoding="utf-8").read()
        check("the file was written", os.path.exists(out))
        check("the written bytes contain no secret",
              not [s for s in SECRETS if s in written], written[:200])
        check("it does contain the pattern and a count",
              "GP-0002" in written and '"count": 20' in written, written[:300])
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_update_verifies_before_writing_anything():
    folder = tempfile.mkdtemp()
    try:
        files = {"signatures.json": b'{"rules":1}'}
        manifest = manifest_for(files)
        served = {"manifest.json": json.dumps(manifest).encode()}
        served.update(files)

        class Fake:
            def __init__(self, data):
                self.data = data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return self.data

        def opener(url, timeout=None):
            name = url.rsplit("/", 1)[-1]
            if name not in served:
                raise OSError(f"404 {name}")
            return Fake(served[name])

        dest = os.path.join(folder, "rules")
        updates = os.path.join(folder, "updates.jsonl")
        buf = io.StringIO()
        code = hub_cli.update(["--base", "https://example.test/r", "--dest", dest,
                               "--updates", updates], opener=opener, out=buf)
        check("a good update succeeds", code == 0, buf.getvalue())
        check("the verified file is written", os.path.exists(os.path.join(dest, "signatures.json")))
        check("the update is recorded",
              hub.current_rules_version(updates) == "r2026.10.04",
              str(hub.current_rules_version(updates)))

        # Now serve a tampered file under the same manifest.
        served["signatures.json"] = b'{"rules":999}'
        dest2 = os.path.join(folder, "rules2")
        updates2 = os.path.join(folder, "updates2.jsonl")
        code = hub_cli.update(["--base", "https://example.test/r", "--dest", dest2,
                               "--updates", updates2], opener=opener, out=io.StringIO())
        check("a tampered update is refused", code == 1)
        check("nothing is written when it is refused", not os.path.exists(dest2))
        check("a refused update is not recorded", not os.path.exists(updates2))
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
