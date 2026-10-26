"""Sending a sightings document, once the member has agreed to.

Waiting for somebody to remember to send a file is a bottleneck, and a protocol whose data
only moves when a human remembers is not a network. So this sends.

What makes that acceptable is not that the sending is convenient. It is that the document
being sent is anonymous by construction: eight fields, counts only, no tool names, no
arguments, no paths, no message text, nothing finer than an hour. Sending it automatically
leaks nothing that sending it by hand would not. The question is consent, and consent is
given once, explicitly, and recorded where the member can see and revoke it.

Three rules this file exists to hold.

**Consent is recorded, not assumed.** Nothing sends unless a file on the member's disk says
they agreed, and that file says what they agreed to.

**The document is checked before it leaves, every time.** Not trusted because the code that
built it is ours. Checked against the allow-list again at the door, because the cost of being
wrong is somebody's data and the cost of checking is nothing.

**Failure is quiet and harmless.** A receiver that is down, slow or gone must never block a
member's work or lose their evidence. The evidence stays on their disk and the next attempt
sends it.

Python 3.9+ standard library only.
"""
import datetime
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

from . import called, hub, identity

CONSENT_NAME = "sharing.json"
SCHEMA_VERSION = 1
SENT_NAME = "sent.jsonl"

# How often sending is even considered. The poll runs every sixty seconds, but the format
# buckets detections by the hour, so sending more than once an hour cannot carry
# information the previous send did not already have. Thirty members polling every minute
# would otherwise be about 1.3 million requests a month, every one of them re-sending the
# member's whole history, to say the same thing the last one said.
SEND_MIN_HOURS = 1
# An unchanged document still goes once a day. Without it a quiet machine and a dead
# machine look identical from the outside, and "nothing was caught" is a result the
# experiment needs to be able to tell apart from "nobody is running it".
HEARTBEAT_HOURS = 24


class ShareError(Exception):
    pass


def consent_path(root):
    return os.path.join(root, CONSENT_NAME)


def record_consent(root, org, endpoint, agreed=True):
    """Write down what was agreed, in words the member can read back."""
    record = {
        "schema_version": SCHEMA_VERSION,
        "agreed": bool(agreed),
        "org": org,
        "endpoint": endpoint,
        "what_is_sent": ("counts only: pattern, action, hour, source, and the pseudonym "
                         "above. No tool names, arguments, URLs, paths or message text, and "
                         "no time finer than the hour."),
        # The command as the member would actually type it. This said "share --stop",
        # which is not a command the CLI has: the one line telling somebody how to
        # withdraw consent named something that fails. Taken from called.invocation() so
        # it matches how they started the tool rather than assuming a name on PATH.
        "revoke_with": "%s share off" % called.invocation(),
    }
    os.makedirs(root, exist_ok=True)
    path = consent_path(root)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, sort_keys=True)
        f.write("\n")
    return record


def consent(root):
    """What the member agreed to, or None."""
    try:
        with open(consent_path(root), encoding="utf-8") as f:
            record = json.load(f)
    except (OSError, ValueError):
        return None
    if record.get("schema_version") != SCHEMA_VERSION or not record.get("agreed"):
        return None
    if not record.get("endpoint") or not record.get("org"):
        return None
    return record


def check_before_sending(document):
    """The allow-list, applied again at the door.

    The document was built from the allow-list, so this should never fail. It is here because
    the cost of being wrong is somebody's data and the cost of checking is nothing, and
    because a future change upstream should break here rather than at a receiver.
    """
    if not isinstance(document, dict):
        raise ShareError("the document is not an object")
    if sorted(document) != ["org", "schema_version", "sightings"]:
        raise ShareError("the document has fields %s, expected org, schema_version, "
                         "sightings" % sorted(document))
    if document.get("schema_version") not in hub.READABLE_SCHEMA_VERSIONS:
        raise ShareError("schema_version %r is not one this version sends"
                         % document.get("schema_version"))
    if not hub.ORG_RE.match(document.get("org") or ""):
        raise ShareError("org %r is not a member id" % document.get("org"))
    for entry in document.get("sightings", []):
        extra = set(entry) - set(hub.ALLOWED_FIELDS)
        if extra:
            raise ShareError("an entry carries %s, which is not in the allow-list. Nothing "
                             "was sent." % ", ".join(sorted(extra)))
        if entry.get("org") != document["org"]:
            raise ShareError("an entry names a different member than the document")
    return True


def send(document, endpoint, opener=None, timeout=30, key=None,
         first_contact=False):
    """POST the document. Returns (ok, message). Never raises on a network problem.

    A receiver that is down, slow or gone must not block a member's work or lose their
    evidence. The evidence stays on their disk and the next attempt sends it, so a failure
    here is a delay rather than a loss.
    """
    check_before_sending(document)
    body = json.dumps(document, sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json",
               "User-Agent": "guardian-sensor/%s" % hub.SENSOR_VERSION}
    if key:
        # Signed over the bytes actually being sent. A receiver that has seen this member
        # before refuses anything that does not match, so a member id cannot be taken by
        # somebody else once it is in use.
        headers["X-Guardian-Signature"] = identity.sign(key, body)
        if first_contact:
            # The key itself travels exactly once, to establish the name. After that only
            # signatures travel, so reading a later request tells an eavesdropper nothing
            # that lets them report as this member.
            headers["X-Guardian-Key"] = key
    request = urllib.request.Request(
        endpoint, data=body, method="POST", headers=headers)
    opener = opener or urllib.request.urlopen
    try:
        with opener(request, timeout=timeout) as response:
            code = getattr(response, "status", None) or response.getcode()
            if 200 <= code < 300:
                return True, "accepted (%d)" % code
            return False, "the receiver answered %d" % code
    except urllib.error.HTTPError as e:
        return False, "the receiver answered %d" % e.code
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, e)


def document_digest(document):
    """A short digest of what would be sent.

    Only the sightings are hashed. The envelope carries the member id and the schema
    version, which do not change, so including them would make every document look new.
    """
    body = json.dumps(document.get("sightings", []), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


def last_success(root):
    """The most recent send that the receiver accepted, or None."""
    found = None
    try:
        with open(os.path.join(root, SENT_NAME), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("ok"):
                    found = record
    except OSError:
        return None
    return found


def should_send(root, document, at=None):
    """Whether to send now, and the reason either way. Returns (bool, reason).

    Three cases, in order. Nothing has ever been sent, so send. The document has changed
    and the last send was at least an hour ago, so send. The document has not changed but
    a day has passed, so send anyway as a sign of life.

    A failed send does not count as a send: last_success only reads accepted ones, so a
    receiver that was down for six hours is caught up on the next poll rather than waiting
    out an interval that never started.
    """
    at = at or datetime.datetime.now(datetime.timezone.utc)
    previous = last_success(root)
    if previous is None:
        return True, "nothing has been sent yet"
    try:
        when = datetime.datetime.fromisoformat(previous["time"])
    except (KeyError, TypeError, ValueError):
        # An unreadable timestamp must not wedge sending forever.
        return True, "the last send has no readable time"
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    hours = (at - when).total_seconds() / 3600.0
    # A clock that moved backwards makes the interval meaningless, and the safe direction
    # is to send. NTP corrections, a suspended virtual machine and a fixed timezone all do
    # this. Treating it as "too soon" left a node silent for the length of the jump while
    # it held new detections, and said "under an hour ago" about a send five hours ahead
    # of it. Time to protection is the measurement this project reports, so a silent node
    # is a wrong number rather than only a late one.
    if hours < 0:
        return True, "the clock moved backwards since the last send"
    changed = previous.get("digest") != document_digest(document)
    if changed and hours >= SEND_MIN_HOURS:
        return True, "there is something new"
    if hours >= HEARTBEAT_HOURS:
        return True, "a day has passed, sending a sign of life"
    if changed:
        return False, "something new, but the last send was under an hour ago"
    return False, "nothing has changed since the last send"


def note_sent(root, document, ok, message, at=None):
    """What was sent and when, so a member can see their own history.

    Counts only, the same as the document, because a log of what was shared should not be
    more revealing than the thing it describes.
    """
    path = os.path.join(root, SENT_NAME)
    os.makedirs(root, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "time": (at or datetime.datetime.now(
                datetime.timezone.utc)).isoformat(timespec="seconds"),
            "entries": len(document.get("sightings", [])),
            # So the next poll can tell an unchanged document from a new one without
            # keeping a copy of what was sent.
            "digest": document_digest(document),
            "ok": bool(ok),
            "detail": message[:200],
        }) + "\n")


def forget(endpoint, org, key, opener=None, timeout=30):
    """Ask the receiver to delete everything it holds about this member.

    Signed with the key this member reports with, so only they can ask. Never raises on
    a network problem: a receiver that is down is a reason to try again, not a reason
    for the command to look like it broke something.

    What is deleted is everything that says this member saw anything. The counts their
    reports contributed to stay, because those identify nobody and removing them would
    silently rewrite results other people are relying on. Said here so the promise and
    the behaviour are written in the same place.
    """
    request = urllib.request.Request(
        endpoint, data=b"", method="DELETE",
        headers={"X-Guardian-Org": org,
                 "X-Guardian-Signature": identity.sign(key, b""),
                 "User-Agent": "guardian-sensor/%s" % hub.SENSOR_VERSION})
    opener = opener or urllib.request.urlopen
    try:
        with opener(request, timeout=timeout) as response:
            code = getattr(response, "status", None) or response.getcode()
            if 200 <= code < 300:
                return True, "deleted"
            return False, "the receiver answered %d" % code
    except urllib.error.HTTPError as e:
        return False, "the receiver answered %d" % e.code
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, e)
