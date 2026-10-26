"""Tests for what a receiver accepts.

The receiver is the last place the allow-list is applied, and the first one that is not
running on the sender's machine. Most of these tests are attacks: a document that tries to
carry a path, a member filing sightings under somebody else's name, a count that is a
boolean. Accepting any of them would put something in the aggregate that the protocol
promised was not there.

Run from the receiver folder:  python3 tests/test_validate.py
"""
import os
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
