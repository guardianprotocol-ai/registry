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
import json
import os
import sys
import urllib.error
import urllib.request

from . import hub

CONSENT_NAME = "sharing.json"
SCHEMA_VERSION = 1
SENT_NAME = "sent.jsonl"


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
        "revoke_with": "guardian share --stop",
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


def send(document, endpoint, opener=None, timeout=30):
    """POST the document. Returns (ok, message). Never raises on a network problem.

    A receiver that is down, slow or gone must not block a member's work or lose their
    evidence. The evidence stays on their disk and the next attempt sends it, so a failure
    here is a delay rather than a loss.
    """
    check_before_sending(document)
    body = json.dumps(document, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        endpoint, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "guardian-sensor/%s" % hub.SENSOR_VERSION})
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


def note_sent(root, document, ok, message):
    """What was sent and when, so a member can see their own history.

    Counts only, the same as the document, because a log of what was shared should not be
    more revealing than the thing it describes.
    """
    path = os.path.join(root, SENT_NAME)
    os.makedirs(root, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(
                timespec="seconds"),
            "entries": len(document.get("sightings", [])),
            "ok": bool(ok),
            "detail": message[:200],
        }) + "\n")
