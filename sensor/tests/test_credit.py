"""Tests for how a participant records their credit.

The one property that carries this file: a real name and a pseudonym must never end up in
the same place. The pseudonym goes into sightings, which are shared. The name goes into a
separate file, which the participant sends separately and only if they want to be named.

Keeping them together would have been more convenient and would have quietly undone the
privacy argument the whole format rests on, so most of what follows checks they are apart.

Run from the sensor folder:  python3 tests/test_credit.py
"""
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_sensor import canaries, credit, hub  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def test_a_name_never_reaches_a_sighting():
    """The property. A sighting is built from an allow-list, and a name is not on it."""
    check("no credit field is in the sightings allow-list",
          not ({"name", "github", "organization", "credit"} & set(hub.ALLOWED_FIELDS)),
          str(hub.ALLOWED_FIELDS))
    records = [{"time": "2026-10-23T09:00:00+00:00", "patterns": ["GP-0001"],
                "action": "blocked", "detail": {"tool": "send_message"}}]
    document = hub.build_sightings(records, "a-lab", "r2026.10.08")
    blob = json.dumps(document)
    for personal in ("Spandana", "Govindgari", "team652", "Frank", "Albanese"):
        check(f"{personal!r} cannot appear in a sighting", personal not in blob)


def test_the_two_files_are_separate():
    with tempfile.TemporaryDirectory() as w:
        credit_path = os.path.join(w, "credit.json")
        canary_path = os.path.join(w, "canaries.json")
        credit.save(credit.build("Ada Lovelace", "ada"), credit_path)
        store = canaries.load(os.path.join(w, "absent.json"))
        canaries.add(store, "sk-live-AbCdEf123456", "a key")
        canaries.save(store, canary_path)
        check("the credit file holds the name",
              "Ada Lovelace" in open(credit_path).read())
        check("the canary file does not", "Ada" not in open(canary_path).read())
        check("and they are different files", credit_path != canary_path)


def test_a_record_holds_only_what_was_given():
    record = credit.build("Ada Lovelace", "@ada", "Analytical Engines")
    check("the at sign is stripped", record["github"] == "ada", str(record))
    check("the name is kept", record["name"] == "Ada Lovelace", str(record))
    check("the organization is kept", record["organization"] == "Analytical Engines",
          str(record))
    check("nothing else is invented",
          sorted(record) == ["acknowledge_only", "github", "name", "organization",
                             "schema_version"], str(sorted(record)))
    check("authorship is not assumed on anyone's behalf",
          record["acknowledge_only"] is False, str(record))
    check("and can be declined",
          credit.build("Ada", acknowledge_only=True)["acknowledge_only"] is True)


def test_what_is_refused():
    for bad, expect in ((("", None), "a name is required"),
                        (("   ", None), "a name is required"),
                        (("x" * 81, None), "at most 80"),
                        (("Ada", "not a handle!"), "not a GitHub handle"),
                        (("Ada", "-leading"), "not a GitHub handle"),
                        (("Ada", "a" * 40), "not a GitHub handle")):
        try:
            credit.build(*bad)
            check(f"refused: {expect}", False, f"accepted {bad}")
        except credit.CreditError as e:
            check(f"refused: {expect}", expect in str(e), str(e))
    check("a handle may contain a single hyphen",
          credit.build("Ada", "ada-lovelace")["github"] == "ada-lovelace")
    check("no handle at all is fine, since it is optional",
          credit.build("Ada")["github"] == "")


def test_the_command_says_where_it_went_and_that_it_goes_nowhere():
    with tempfile.TemporaryDirectory() as w:
        path = os.path.join(w, "credit.json")
        out = io.StringIO()
        code = credit.main(["--name", "Ada Lovelace", "--github", "ada", "--file", path],
                           out=out)
        text = out.getvalue()
        check("it records", code == 0 and os.path.exists(path), text[-200:])
        check("it prints the whole record", '"name": "Ada Lovelace"' in text, text)
        check("it says it goes nowhere on its own", "goes nowhere on its own" in text, text)
        check("it says sightings never carry the name",
              "never your name" in text, text)
        check("it explains what authorship requires",
              "substantive contribution" in text, text)


def test_showing_and_removing():
    with tempfile.TemporaryDirectory() as w:
        path = os.path.join(w, "credit.json")
        out = io.StringIO()
        code = credit.main(["--show", "--file", path], out=out)
        check("nothing recorded says so", code == 0 and "Nothing recorded" in out.getvalue(),
              out.getvalue())
        check("and says it is optional", "optional" in out.getvalue(), out.getvalue())

        credit.main(["--name", "Ada", "--github", "ada", "--file", path], out=io.StringIO())
        out = io.StringIO()
        credit.main(["--show", "--file", path], out=out)
        check("showing prints what is there", "Ada" in out.getvalue(), out.getvalue())
        check("and says it is only shared if sent", "only if you send it" in out.getvalue(),
              out.getvalue())

        out = io.StringIO()
        credit.main(["--remove", "--file", path], out=out)
        check("removing works", not os.path.exists(path))
        check("and says nothing is recorded now",
              "Nothing about you is recorded" in out.getvalue(), out.getvalue())


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
