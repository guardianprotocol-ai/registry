"""Tests for what a receiver accepts.

The receiver is the last place the allow-list is applied, and the first one that is not
running on the sender's machine. Most of these tests are attacks: a document that tries to
carry a path, a member filing sightings under somebody else's name, a count that is a
boolean. Accepting any of them would put something in the aggregate that the protocol
promised was not there.

Run from the receiver folder:  python3 tests/test_validate.py
"""
import json
import os
import shutil
import tempfile
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import validate  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + str(detail)}")
    if not condition:
        failures.append(name)


def entry(**over):
    base = {"org": "a-lab", "sensor_version": "guardian-sensor v0",
            "rules_version": "b34d9a7a88daa", "pattern": "GP-0003", "action": "blocked",
            "hour": "2026-10-22T13", "count": 1, "source": "drill"}
    base.update(over)
    return base


def doc(entries=None, **over):
    base = {"schema_version": "0.2", "org": "a-lab",
            "sightings": [entry()] if entries is None else entries}
    base.update(over)
    return base


def refuses(name, document, expect=None):
    try:
        validate.check_document(document)
    except validate.Refused as e:
        check(name, expect is None or expect in str(e), e)
        return
    check(name, False, "it was accepted")


def test_a_good_document_is_accepted():
    check("a plain document is accepted", len(validate.check_document(doc())) == 1)


def test_nothing_outside_the_allow_list_gets_in():
    for field, value in [("path", "/etc/passwd"), ("url", "https://example.test"),
                         ("tool", "send_message"), ("body", "hello"),
                         ("arguments", {"to": "a@b.test"}), ("time", "2026-10-22T13:04:11")]:
        refuses("a smuggled %s is refused" % field, doc([entry(**{field: value})]),
                "allow-list")


def test_a_document_cannot_file_under_another_member():
    """The k-threshold counts distinct organizations. If one sender can name others, it
    can reach the threshold alone and manufacture an alert."""
    refuses("an entry naming another member is refused",
            doc([entry(org="somebody-else")]), "but the document is from")


def test_the_shape_is_checked():
    refuses("a list is not a document", [entry()])
    refuses("an extra top level field is refused", dict(doc(), extra=1), "expected")
    refuses("an unknown schema is refused", doc(schema_version="9.9"), "schema_version")
    refuses("sightings must be a list", dict(doc(), sightings={"a": 1}), "not a list")
    refuses("an entry must be an object", doc(["not an object"]), "not an object")
    refuses("a missing field is refused",
            doc([{k: v for k, v in entry().items() if k != "hour"}]), "missing")


def test_the_values_are_checked():
    refuses("a bad member id is refused", doc(org="Not An Id"), "member id")
    refuses("a pattern that is a path is refused",
            doc([entry(pattern="../../etc/passwd")]), "pattern")
    refuses("an unknown action is refused", doc([entry(action="allowed")]), "action")
    refuses("an unknown source is refused", doc([entry(source="production")]), "source")
    refuses("an hour with minutes is refused", doc([entry(hour="2026-10-22T13:04")]), "hour")
    refuses("a count of zero is refused", doc([entry(count=0)]), "count")
    refuses("a negative count is refused", doc([entry(count=-5)]), "count")
    # bool is a subclass of int, so True would otherwise be stored as a count of one.
    refuses("a boolean count is refused", doc([entry(count=True)]), "count")
    refuses("a count that is text is refused", doc([entry(count="many")]), "count")


def test_too_much_is_refused():
    refuses("more entries than one request may carry is refused",
            doc([entry() for _ in range(validate.MAX_ENTRIES + 1)]), "single request")


def test_the_same_sighting_has_the_same_identity():
    """Re-sending must correct a count, never add to it.

    A member who was offline sends their whole history on the next poll. If identity
    included the count, each correction would land as a new row and the totals the
    research reports would drift upwards every time somebody reconnected.
    """
    a = entry(count=1)
    check("the count is not part of the identity",
          validate.key_for(a) == validate.key_for(entry(count=7)), validate.key_for(a))
    for field in ("org", "pattern", "action", "hour", "source", "rules_version",
                  "sensor_version"):
        check("a different %s is a different sighting" % field,
              validate.key_for(a) != validate.key_for(entry(**{field: "zzzz"})), field)


def test_the_identity_cannot_contain_a_path_separator():
    """The identity is used as a storage key. A slash in it would change where it lands."""
    key = validate.key_for(entry())
    check("no slash in the identity", "/" not in key, key)


def test_what_the_sensor_builds_is_what_the_receiver_accepts():
    """The two halves are written in different files and could drift apart silently.

    If the sensor adds a field the receiver has not been told about, the receiver refuses
    the whole document and the member sees their sightings stop arriving for a reason
    nobody is looking at. This fails here instead, at the moment the field is added.
    """
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, os.path.join(root, "sensor"))
    try:
        from guardian_sensor import hub
    except ImportError as e:
        check("the sensor package is importable", False, e)
        return
    check("both sides name the same fields",
          tuple(validate.ALLOWED_FIELDS) == tuple(hub.ALLOWED_FIELDS),
          f"receiver {validate.ALLOWED_FIELDS} vs sensor {hub.ALLOWED_FIELDS}")
    check("both sides allow the same actions",
          tuple(validate.ACTIONS) == tuple(hub.ACTIONS),
          f"receiver {validate.ACTIONS} vs sensor {hub.ACTIONS}")
    check("both sides allow the same sources",
          tuple(validate.SOURCES) == tuple(hub.SOURCES),
          f"receiver {validate.SOURCES} vs sensor {hub.SOURCES}")
    check("both sides read the same schema versions",
          tuple(validate.SCHEMA_VERSIONS) == tuple(hub.READABLE_SCHEMA_VERSIONS),
          f"receiver {validate.SCHEMA_VERSIONS} vs sensor {hub.READABLE_SCHEMA_VERSIONS}")

    # Built the way the sensor builds it, rather than the way this file builds fixtures.
    records = [{"time": "2026-10-22T13:04:11+00:00", "patterns": ["GP-0003"],
                "action": "blocked", "drill": True, "detail": {}}]
    built = hub.build_sightings(records, "a-lab", "b34d9a7a88daa")
    try:
        accepted = validate.check_document(built)
        check("a document the sensor built is accepted", len(accepted) == 1, str(built))
    except validate.Refused as e:
        check("a document the sensor built is accepted", False, e)


class _FakeDoc:
    def __init__(self, data=None):
        self._data, self.exists = data, data is not None

    def to_dict(self):
        return dict(self._data or {})


class _FakeRef:
    def __init__(self, store, key):
        self.store, self.key = store, key

    def get(self):
        return _FakeDoc(self.store.get(self.key))

    def set(self, value, merge=False):
        if merge and self.key in self.store:
            self.store[self.key].update(value)
        else:
            self.store[self.key] = dict(value)


class _FakeCollection:
    def __init__(self, store):
        self.store = store

    def document(self, key):
        return _FakeRef(self.store, key)

    def stream(self):
        return [_FakeDoc(v) for v in self.store.values()]


class _FakeDb:
    def __init__(self):
        self.data = {}

    def collection(self, name):
        return _FakeCollection(self.data.setdefault(name, {}))

    def batch(self):
        raise AssertionError("not needed for these tests")


def test_a_member_who_saw_nothing_is_still_counted():
    """The denominator. Before this they were invisible.

    A member who installs, agrees to report and catches nothing sends a document with no
    entries. Storing only sightings stored nothing for them, so there was no way to tell
    a quiet machine from one nobody installed, and "twenty organizations saw this" had no
    denominator to sit over.
    """
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import participation as receiver

    db = _FakeDb()
    quiet = {"schema_version": "0.2", "org": "quiet-co", "sightings": []}
    record = receiver.record_for("quiet-co", quiet)
    check("a member with nothing to report is recorded", record["org"] == "quiet-co",
          str(record))
    check("and it says they had nothing", record["last_entries"] == 0, str(record))
    check("and when they were first seen", "first_seen" in record, str(record))

    busy = {"schema_version": "0.2", "org": "busy-co",
            "sightings": [entry(org="busy-co")]}
    other = receiver.record_for("busy-co", busy)
    check("a member with something to report is recorded too",
          other["last_entries"] == 1, str(other))
    check("and the sensor version travels with them",
          other.get("sensor_version") == "guardian-sensor v0", str(other))


def test_reporting_twice_does_not_make_two_members():
    """Otherwise the denominator grows every hour and every rate shrinks."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import participation as receiver

    document = {"schema_version": "0.2", "org": "same-co", "sightings": []}
    first = receiver.record_for("same-co", document)
    again = receiver.record_for("same-co", document, existing=first)
    check("the first sighting of them is kept",
          again["first_seen"] == first["first_seen"], f"{first} then {again}")
    check("and last seen moves forward", "last_seen" in again, str(again))


def test_the_report_says_zero_plainly():
    """A report of nothing that reads like a report of something is the failure this
    project keeps finding in its own checks."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import participation

    empty = participation.text({}, {})
    check("an empty network says so", "No organization has reported yet" in empty, empty)
    both = participation.text(
        {"a": {"org": "a", "first_seen": "x", "last_seen": "y"},
         "b": {"org": "b", "first_seen": "x", "last_seen": "y"}}, {"a": 4})
    check("a quiet member is counted and named", "none yet" in both, both)
    check("the total is stated", "2 organizations reporting" in both, both)


def test_a_member_id_in_use_cannot_be_taken():
    """The k-threshold counts organizations. Counting means nothing if a name can be taken.

    Trust on first use: whoever reports first holds the name, and every report after that
    must be signed with the same key. Without this, anybody who knew a member id could
    file sightings in their name, which both poisons that organization's numbers and
    inflates the count of organizations the research rests on.
    """
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import membership

    key = "a" * 64
    body = b'{"org":"acme","schema_version":"0.2","sightings":[]}'
    good = membership.sign(key, body)

    keep, note = membership.decide("acme", None, body, good, offered_key=key)
    check("first contact records the key", keep == key, note)

    _, note = membership.decide("acme", key, body, good)
    check("the real member is accepted again", note == "known member", note)

    for label, signature, offered in [
            ("no signature at all", None, None),
            ("somebody else's signature", membership.sign("b" * 64, body), None),
            ("their own new key", membership.sign("b" * 64, body), "b" * 64)]:
        try:
            membership.decide("acme", key, body, signature, offered_key=offered)
            check("an impostor with %s is refused" % label, False, "it was accepted")
        except membership.Refused:
            check("an impostor with %s is refused" % label, True)


def test_a_changed_body_breaks_the_signature():
    """Signed over the bytes sent, so nothing can be edited in flight."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import membership

    key = "a" * 64
    body = b'{"count":1}'
    signature = membership.sign(key, body)
    check("the original verifies", membership.check(key, body, signature))
    check("one changed digit does not",
          not membership.check(key, b'{"count":9}', signature))


def test_an_unsigned_first_contact_is_allowed_and_said_so():
    """A member who has no key yet can still take part, and it is recorded as unsigned
    rather than quietly treated as proven."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import membership

    keep, note = membership.decide("newcomer", None, b"{}", None)
    check("they are let in", keep is None, note)
    check("and it says the report was not signed", "unsigned" in note, note)


def test_identified_rows_expire_and_counts_do_not():
    """Collecting little in transit and keeping everything at rest is half a promise.

    A member id is in a sighting because the threshold has to count distinct
    organizations. Once the window is aggregated it has done its work, and keeping it
    after that is keeping a record of who was attacked rather than what was seen.
    """
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import datetime
    import retention

    e = entry()
    cell = retention.aggregate_key(e)
    check("the surviving cell holds no member id", e["org"] not in cell, cell)
    for field in ("pattern", "action", "hour"):
        check("but it still answers about %s" % field, str(e[field]) in cell, cell)

    now = datetime.datetime(2026, 10, 26, tzinfo=datetime.timezone.utc)
    when = retention.expires_at(now)
    check("an identified row expires", when > now, str(when))
    check("and not so soon a late report misses its window",
          (when - now).days >= 14, (when - now).days)
    check("the promise is stated in words a member reads",
          "deleted after" in retention.describe(), retention.describe())


def test_a_sensor_that_goes_silent_is_visible():
    """The honest answer to whether an agent can disable its own sensor.

    It can. A sensor runs at the same privilege as the agent on the same machine, so
    anything with shell access can edit the client config, kill the process, or delete
    the state. No design at equal privilege prevents that.

    What it cannot do is keep reporting while disabled. A sign of life goes once a day
    even with nothing to report, so absence is visible from outside the machine, and
    visible to a network rather than only to its owner. Tamper evident rather than tamper
    proof, which is the achievable property.
    """
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import datetime
    import participation

    now = datetime.datetime(2026, 10, 26, 15, tzinfo=datetime.timezone.utc)
    seen = {"alive": {"org": "alive", "last_seen": "2026-10-26T14:00:00"},
            "went-dark": {"org": "went-dark", "last_seen": "2026-10-22T09:00:00"}}
    gone = participation.silent(seen, now=now)
    check("the silent member is named", [o for o, _ in gone] == ["went-dark"], str(gone))
    check("with how long it has been", round(gone[0][1]) == 102, str(gone))

    text = participation.text(seen, {"alive": 12}, now=now)
    check("silence is separated from having nothing to report",
          "stopped reporting altogether" in text, text[:400])
    check("and it is not overclaimed as proof",
          "not proof of anything on its own" in text, text[-400:])


def test_quiet_is_not_the_same_as_gone():
    """A member reporting daily with nothing to report is a result. Conflating the two
    would make the denominator wrong and hide the tampering signal in it."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import datetime
    import participation

    now = datetime.datetime(2026, 10, 26, 15, tzinfo=datetime.timezone.utc)
    quiet = {"q": {"org": "q", "last_seen": "2026-10-26T14:00:00"}}
    check("a member heard from an hour ago is not silent",
          participation.silent(quiet, now=now) == [],
          str(participation.silent(quiet, now=now)))
    text = participation.text(quiet, {}, now=now)
    check("they are counted as having seen nothing",
          "1 have seen nothing" in text, text[:300])
    check("and not reported as gone",
          "stopped reporting" not in text, text[:300])


def test_the_export_carries_only_the_eight_fields():
    """A stored row has more in it than a sighting does.

    The receiver keeps an expiry on every row, which is what drives retention. That is
    its own bookkeeping and not something a member reported, and handing it to the
    validator refused the entire export. Correct of the validator; the export's mistake.

    Found the first time four organizations were on the network and the aggregate was
    run for real, which is the worst moment to find it and the only moment it could have
    been found: nothing had exercised the path since retention was added.
    """
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import export

    stored = dict(entry())
    stored["expires_at"] = "2026-11-25T00:00:00+00:00"
    stored["key_fingerprint"] = "should not travel either"

    folder = tempfile.mkdtemp()
    try:
        export.write({"a-lab": [stored]}, folder)
        with open(os.path.join(folder, "a-lab", "sightings.json"),
                  encoding="utf-8") as f:
            written = json.load(f)
        for name in ("expires_at", "key_fingerprint"):
            check("%s does not reach the export" % name,
                  name not in written["sightings"][0], str(written["sightings"][0]))
        check("and the eight fields all do",
              sorted(written["sightings"][0]) == sorted(validate.ALLOWED_FIELDS),
              str(sorted(written["sightings"][0])))
        # The point of projecting rather than deleting known extras.
        check("a field nobody has thought of yet is also left behind",
              "key_fingerprint" not in json.dumps(written), json.dumps(written)[:200])
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
