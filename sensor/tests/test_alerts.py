"""Tests for alerts and for sending sightings.

Two things that together close the loop, and two things that could each undo the privacy the
rest of the project rests on.

Sending must only happen after consent, and must send only what the allow-list permits.
Alerts must say what was seen and never what to do, because an alert that could carry an
instruction is a command channel with a friendlier name.

Run from the sensor folder:  python3 tests/test_alerts.py
"""
import io
import json
import os
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
