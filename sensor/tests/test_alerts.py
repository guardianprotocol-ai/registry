"""Tests for alerts and for sending sightings.

Two things that together close the loop, and two things that could each undo the privacy the
rest of the project rests on.

Sending must only happen after consent, and must send only what the allow-list permits.
Alerts must say what was seen and never what to do, because an alert that could carry an
instruction is a command channel with a friendlier name.

Run from the sensor folder:  python3 tests/test_alerts.py
"""
import datetime
import io
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_sensor import alerts, hub, share  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def document(patterns=("GP-0001", "GP-0003")):
    return {"schema_version": "1", "published": "2026-10-23T19:00:00+00:00",
            "source": "drill", "note": "counts only",
            "alerts": [{"pattern": p, "organizations": 3, "total": 3} for p in patterns]}


def sightings(org="acme-labs"):
    return hub.build_sightings(
        [{"time": "2026-10-23T19:00:00+00:00", "patterns": ["GP-0001"], "action": "blocked",
          "detail": {"tool": "send_message", "url": "https://x.test"}}],
        org, "r2026.10.08")


# ---------- an alert cannot carry an instruction ----------

def test_an_alert_that_tells_a_machine_what_to_do_is_refused():
    """The defining property. Refused, not ignored: ignoring an unknown key means a later
    version that understands it would obey what this one dropped."""
    for key in ("run", "command", "exec", "script", "url", "action", "block"):
        bad = document()
        bad[key] = "anything"
        try:
            alerts.parse(bad)
            check(f"a document carrying {key!r} is refused", False, "accepted")
        except alerts.AlertError as e:
            check(f"a document carrying {key!r} is refused",
                  "does not understand" in str(e), str(e))
    for key in ("action", "run", "severity"):
        bad = document()
        bad["alerts"][0][key] = "block"
        try:
            alerts.parse(bad)
            check(f"an alert carrying {key!r} is refused", False, "accepted")
        except alerts.AlertError as e:
            check(f"an alert carrying {key!r} is refused",
                  "not part of the format" in str(e), str(e))


def test_the_shape_is_checked_not_trusted():
    cases = [("not an object", "not an object"),
             ({"schema_version": "9", "alerts": []}, "is not one this sensor reads"),
             ({"schema_version": "1", "alerts": "lots"}, "should be a list")]
    for bad, expect in cases:
        try:
            alerts.parse(bad)
            check(f"refused: {expect}", False, "accepted")
        except alerts.AlertError as e:
            check(f"refused: {expect}", expect in str(e), str(e))
    bad = document()
    bad["alerts"][0]["pattern"] = "../../etc/passwd"
    try:
        alerts.parse(bad)
        check("a pattern that is a path is refused", False, "accepted")
    except alerts.AlertError as e:
        check("a pattern that is a path is refused", "not a pattern" in str(e), str(e))
    bad = document()
    bad["alerts"][0]["organizations"] = 0
    try:
        alerts.parse(bad)
        check("a count below one is refused", False, "accepted")
    except alerts.AlertError as e:
        check("a count below one is refused", "not a count" in str(e), str(e))


def test_an_alert_is_announced_once():
    """A poll runs every sixty seconds. Repeating the same alert would train a member to
    ignore the one line that matters."""
    with tempfile.TemporaryDirectory() as w:
        published = alerts.parse(document())
        check("all of it is new at first", len(alerts.unseen(w, published)) == 2)
        alerts.remember(w, published, "2026-10-23T19:00:00+00:00")
        check("none of it is new afterwards", alerts.unseen(w, published) == [])
        more = alerts.parse(document(("GP-0001", "GP-0003", "GP-0019")))
        fresh = alerts.unseen(w, more)
        check("only the new one is new", [a["pattern"] for a in fresh] == ["GP-0019"],
              str(fresh))


# ---------- sending ----------

def test_nothing_is_sent_without_recorded_consent():
    with tempfile.TemporaryDirectory() as w:
        check("no consent by default", share.consent(w) is None)
        share.record_consent(w, "acme-labs", "https://x.test/s", agreed=False)
        check("consent that says no counts as no", share.consent(w) is None)
        share.record_consent(w, "acme-labs", "https://x.test/s")
        agreed = share.consent(w)
        check("consent that says yes is read", agreed is not None)
        check("it records the member id", agreed["org"] == "acme-labs", str(agreed))
        check("and says what is sent, in words",
              "counts only" in agreed["what_is_sent"], str(agreed))
        check("and how to revoke it", "share --stop" in agreed["revoke_with"]
              or "share off" in agreed["revoke_with"] or "--stop" in agreed["revoke_with"],
              str(agreed))


def test_the_allow_list_is_applied_again_at_the_door():
    """The document was built from the allow-list, so this should never fail. It is here
    because the cost of being wrong is somebody's data."""
    good = sightings()
    check("a clean document passes", share.check_before_sending(good) is True)
    for field, value in (("tool", "send_message"), ("url", "https://x.test"),
                         ("path", "/etc/passwd"), ("body", "secret")):
        bad = json.loads(json.dumps(good))
        bad["sightings"][0][field] = value
        try:
            share.check_before_sending(bad)
            check(f"a smuggled {field} is refused", False, "accepted")
        except share.ShareError as e:
            check(f"a smuggled {field} is refused",
                  "not in the allow-list" in str(e) and "Nothing was sent" in str(e), str(e))


def test_an_entry_naming_another_member_is_refused():
    bad = sightings()
    bad["sightings"][0]["org"] = "someone-else"
    try:
        share.check_before_sending(bad)
        check("an entry naming another member is refused", False, "accepted")
    except share.ShareError as e:
        check("an entry naming another member is refused",
              "different member" in str(e), str(e))


def test_a_receiver_that_is_down_loses_nothing():
    """A receiver being unreachable must be a delay, not a loss, and must never raise into a
    member's poll."""
    class Dead:
        def __call__(self, request, timeout=None):
            raise OSError("connection refused")

    ok, message = share.send(sightings(), "https://nowhere.invalid/s", opener=Dead())
    check("it does not raise", ok is False, str(ok))
    check("and says why", "OSError" in message or "refused" in message, message)

    class Refusing:
        def __call__(self, request, timeout=None):
            import urllib.error
            raise urllib.error.HTTPError("u", 503, "busy", {}, None)

    ok, message = share.send(sightings(), "https://x.test/s", opener=Refusing())
    check("a 503 is reported, not raised", ok is False and "503" in message, message)


def test_a_send_is_recorded_in_counts_only():
    """A log of what was shared should not be more revealing than the thing it describes."""
    with tempfile.TemporaryDirectory() as w:
        share.note_sent(w, sightings(), True, "accepted (200)")
        body = open(os.path.join(w, share.SENT_NAME), encoding="utf-8").read()
        record = json.loads(body.strip())
        check("it records how many entries", record["entries"] == 1, body)
        check("it records whether it worked", record["ok"] is True, body)
        check("it records when", record["time"].startswith("20"), body)
        for leak in ("send_message", "GP-0001", "acme-labs", "x.test"):
            check(f"{leak!r} is not in the send log", leak not in body, body)


def _doc(entries):
    return {"schema_version": "0.2", "org": "a-lab", "sightings": entries}


def _entry(pattern="GP-0003", count=1):
    return {"org": "a-lab", "sensor_version": "guardian-sensor v0",
            "rules_version": "b34d9a7a88daa", "pattern": pattern, "action": "blocked",
            "hour": "2026-10-22T13", "count": count, "source": "drill"}


def test_sending_is_not_attempted_every_poll():
    """The poll runs every sixty seconds. Sending every poll says nothing new.

    The format buckets by the hour, so a second send inside the same hour cannot carry
    information the first one did not. Thirty members polling every minute for a month is
    about 1.3 million requests, each re-sending the member's entire history.
    """
    folder = tempfile.mkdtemp()
    try:
        document = _doc([_entry()])
        now = datetime.datetime(2026, 10, 22, 14, 0, tzinfo=datetime.timezone.utc)

        due, why = share.should_send(folder, document, at=now)
        check("the first send always happens", due, why)

        share.note_sent(folder, document, True, "ok", at=now)
        due, why = share.should_send(folder, document, at=now)
        check("an unchanged document is not sent again", not due, why)

        minutes_later = now + datetime.timedelta(minutes=5)
        due, why = share.should_send(folder, _doc([_entry(), _entry("GP-0001")]),
                                     at=minutes_later)
        check("something new still waits for the hour", not due, why)

        an_hour_later = now + datetime.timedelta(hours=1, minutes=1)
        due, why = share.should_send(folder, _doc([_entry(), _entry("GP-0001")]),
                                     at=an_hour_later)
        check("something new goes once the hour is up", due, why)

        a_day_later = now + datetime.timedelta(hours=24, minutes=1)
        due, why = share.should_send(folder, document, at=a_day_later)
        check("an unchanged document still goes once a day", due, why)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_failed_send_does_not_start_the_clock():
    """A receiver that was down must not cost the member an hour of silence.

    If a refused attempt counted as a send, a member whose first attempt failed would wait
    out an interval that never carried anything, and the evidence would sit on their disk
    while the aggregate showed them as reporting nothing.
    """
    folder = tempfile.mkdtemp()
    try:
        document = _doc([_entry()])
        now = datetime.datetime(2026, 10, 22, 14, 0, tzinfo=datetime.timezone.utc)
        share.note_sent(folder, document, False, "connection refused", at=now)
        due, why = share.should_send(folder, document, at=now)
        check("a refused send is retried at once", due, why)
        check("the reason says nothing has landed yet",
              "nothing has been sent yet" in why, why)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_the_digest_follows_the_sightings_only():
    """Two documents with the same sightings must look the same, or nothing throttles."""
    a = _doc([_entry()])
    b = _doc([_entry()])
    b["org"] = "a-lab"
    check("the same sightings give the same digest",
          share.document_digest(a) == share.document_digest(b),
          f"{share.document_digest(a)} vs {share.document_digest(b)}")
    changed = _doc([_entry(count=2)])
    check("a changed count is a changed document",
          share.document_digest(a) != share.document_digest(changed),
          share.document_digest(changed))


def _alert_doc(**over):
    alert = {"pattern": "GP-0003", "organizations": 3, "total": 9}
    alert.update(over)
    return {"schema_version": "1", "published": "2026-10-26T03:00:00+00:00",
            "source": "drill", "alerts": [alert]}


def test_a_reader_checks_the_guarantee_it_repeats():
    """The published note says at least three independent organizations saw this.

    A reader that prints that sentence and accepts an alert claiming one organization has
    not checked the thing it is telling its operator. The publisher enforces the floor,
    and so does this, because the publisher runs on somebody else's machine.
    """
    try:
        alerts.parse(_alert_doc())
        check("three organizations is accepted", True)
    except alerts.AlertError as e:
        check("three organizations is accepted", False, e)

    for count in (1, 2):
        try:
            alerts.parse(_alert_doc(organizations=count, total=count))
            check("an alert claiming %d organizations is refused" % count, False,
                  "it was accepted")
        except alerts.AlertError as e:
            check("an alert claiming %d organizations is refused" % count, True, e)


def test_an_alert_that_cannot_be_true_is_refused():
    """Every contributing organization supplies at least one sighting."""
    try:
        alerts.parse(_alert_doc(organizations=5, total=1))
        check("more organizations than sightings is refused", False, "it was accepted")
    except alerts.AlertError as e:
        check("more organizations than sightings is refused", True, e)


def test_a_clock_moving_backwards_does_not_silence_a_node():
    """NTP corrections, suspended virtual machines and fixed timezones all do this.

    Treating a negative interval as "too soon" left a node holding new detections silent
    for the length of the jump, while telling its operator the last send was under an hour
    ago. Time to protection is the measurement this project reports, so a silent node is a
    wrong number and not only a late one.
    """
    folder = tempfile.mkdtemp()
    try:
        first = _doc([_entry()])
        now = datetime.datetime(2026, 10, 22, 14, 0, tzinfo=datetime.timezone.utc)
        share.note_sent(folder, first, True, "ok", at=now)
        more = _doc([_entry(), _entry("GP-0001")])
        due, why = share.should_send(folder, more, at=now - datetime.timedelta(hours=5))
        check("a backwards clock sends rather than waits", due, why)
        check("and says why", "backwards" in why, why)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_node_notices_when_something_is_spreading():
    """The early warning, without naming anybody.

    A pattern going from six organizations to forty is the thing worth interrupting
    somebody about, and a node cannot see it from a list of pattern names. Noticed on
    the node rather than published, because a published trend would be one operator
    deciding what counts as an emergency for everybody.
    """
    folder = tempfile.mkdtemp()
    try:
        alerts.remember(folder, [{"pattern": "GP-0003", "organizations": 6, "total": 9}],
                        "2026-10-26T09:00")
        spike = alerts.rising(folder, [{"pattern": "GP-0003", "organizations": 40,
                                        "total": 120}])
        check("a sharp rise is noticed", [a["pattern"] for a in spike] == ["GP-0003"],
              str(spike))
        check("and it says what it rose from",
              spike[0]["before"] == 6 and spike[0]["now"] == 40, str(spike))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_ordinary_growth_is_not_an_alarm():
    """An alarm that fires on noise is an alarm somebody turns off."""
    folder = tempfile.mkdtemp()
    try:
        alerts.remember(folder, [{"pattern": "GP-0001", "organizations": 10, "total": 10}],
                        "2026-10-26T09:00")
        check("ten to eleven is not a spike",
              alerts.rising(folder, [{"pattern": "GP-0001", "organizations": 11,
                                      "total": 11}]) == [])
        # Doubling is required, and so is a floor, or every new pattern alarms twice.
        check("one to two is not a spike",
              alerts.rising(folder, [{"pattern": "GP-0001", "organizations": 2,
                                      "total": 2}]) == [])
        check("a pattern never seen before is not a spike",
              alerts.rising(folder, [{"pattern": "GP-9999", "organizations": 99,
                                      "total": 99}]) == [])
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_an_older_alerts_file_still_works():
    """Machines that have been running carry the previous format, a bare timestamp."""
    folder = tempfile.mkdtemp()
    try:
        with open(os.path.join(folder, alerts.SEEN_NAME), "w", encoding="utf-8") as f:
            json.dump({"GP-0003": "2026-10-20T09:00"}, f)
        check("no count to compare means no false alarm",
              alerts.rising(folder, [{"pattern": "GP-0003", "organizations": 40,
                                      "total": 99}]) == [])
        check("and the file is still readable",
              "GP-0003" in alerts.seen(folder), str(alerts.seen(folder)))
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
