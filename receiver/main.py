"""The Season 1 sightings receiver.

One endpoint. It accepts a sightings document, checks it against the allow-list in
validate.py, and stores each entry at most once. It reads nothing back out: publishing
alerts is a separate step a person runs, on purpose, so that nothing a stranger posts can
become advice other machines act on without a human having looked at it.

What this is not: the protocol. The protocol is the HTTP contract in README.md, which any
organization can implement. This file is one deployment of it, and the only part of the
exchange that is specific to Google Cloud. Everything that decides what is acceptable
lives in validate.py, which has no cloud dependency at all.

Threat model for Season 1 is written out in README.md. The short version: this endpoint is
unauthenticated, so a stranger can file sightings under invented member ids. Nothing is
published automatically, the k-threshold needs several distinct organizations, and a person
reviews the aggregate before any alert goes out. That is the control. It is a Season 1
answer and it is written down rather than assumed.
"""
import json
import os

import functions_framework
from google.cloud import firestore

import participation
import validate

COLLECTION = os.environ.get("GUARDIAN_COLLECTION", "sightings")
# Who is taking part, as distinct from what they saw. A member who installs, agrees to
# share and catches nothing sends a document with no entries, which stored nothing, so
# they were invisible. That makes the denominator unknowable: "twenty organizations saw
# this" means nothing without knowing how many were running. The research needs both
# numbers and only one of them existed.
PARTICIPANTS = os.environ.get("GUARDIAN_PARTICIPANTS", "participants")
_db = None


def db():
    global _db
    if _db is None:
        _db = firestore.Client()
    return _db


def _json(body, code):
    return (json.dumps(body), code, {"Content-Type": "application/json"})


def note_participant(org, document, store_at=None, now=None):
    """Record that this member reported, whether or not they had anything to report.

    A member who installs, agrees to share and catches nothing sends a document with no
    entries, which stores no sightings and left them invisible. The research needs to
    tell a quiet machine from one nobody installed, because that is the denominator.
    """
    writer = store_at or db()
    ref = writer.collection(PARTICIPANTS).document(org)
    found = ref.get()
    existing = found.to_dict() if found and found.exists else None
    record = participation.record_for(org, document, existing, now)
    ref.set(record, merge=True)
    return record


def store(entries, store_at=None):
    """Write each entry once, keyed by its identity. Returns how many were written.

    A re-send overwrites rather than adds, so a member catching up after a week offline
    corrects the stored counts instead of inflating them.
    """
    writer = store_at or db()
    batch = writer.batch()
    written = 0
    for entry in entries:
        key = validate.key_for(entry)
        # The key is the document id, which is what makes a repeat idempotent. Firestore
        # ids cannot contain a slash, and no field in the allow-list can produce one: the
        # patterns in validate.py admit none.
        batch.set(writer.collection(COLLECTION).document(key), dict(entry))
        written += 1
        if written % 400 == 0:
            batch.commit()
            batch = writer.batch()
    batch.commit()
    return written


@functions_framework.http
def sightings(request):
    if request.method != "POST":
        return _json({"error": "this endpoint accepts POST"}, 405)
    raw = request.get_data(cache=False)
    if len(raw) > validate.MAX_BYTES:
        return _json({"error": "the body is larger than %d bytes" % validate.MAX_BYTES}, 413)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        return _json({"error": "the body is not JSON: %s" % e}, 400)
    try:
        entries = validate.check_document(document)
    except validate.Refused as e:
        # The reason goes back in full. A sender that cannot see why it was refused will
        # keep sending the same thing, and the member will believe they are taking part.
        return _json({"error": str(e)}, 400)
    try:
        # Before the sightings, so a member with nothing to report is still counted. That
        # case is the whole reason this exists.
        note_participant(document["org"], document)
        written = store(entries)
    except Exception as e:  # noqa: BLE001
        # The sender keeps its evidence and retries, so a failure here is a delay. The
        # message stays generic because it describes our infrastructure, not their data.
        print("store failed: %s: %s" % (type(e).__name__, e))
        return _json({"error": "the receiver could not store this, try again later"}, 503)
    return _json({"accepted": len(entries), "stored": written}, 200)
