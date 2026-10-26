"""What a receiver accepts, and what it refuses.

This is the third place the allow-list is applied. The sensor builds a document from it,
checks it again at the door before sending, and a receiver checks it once more on arrival.
That is deliberate. The first two run on a machine the protocol does not control, so a
receiver that trusted them would be trusting whatever the sender chose to run.

Refusing is the whole job. A receiver that quietly dropped unknown fields would accept a
document carrying a file path, store the part it recognised, and leave the sender believing
the protocol had agreed to the rest. So anything not named here is a refusal with a reason,
and nothing is ever partially accepted.

Python 3.9+ standard library only, and no cloud SDK, so this file runs anywhere and is the
part somebody reimplementing the protocol has to match.
"""
import re

SCHEMA_VERSIONS = ("0.1", "0.2")
DOCUMENT_FIELDS = ("org", "schema_version", "sightings")
ALLOWED_FIELDS = ("org", "sensor_version", "rules_version", "pattern", "action", "hour",
                  "count", "source")
ACTIONS = ("flagged", "blocked")
SOURCES = ("live", "drill")

ORG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$")
PATTERN_RE = re.compile(r"^GP-\d{4}$")
HOUR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")

# A document is counts. These bound what one request can be, so a receiver cannot be made
# to hold an unbounded amount of anything by somebody who simply keeps typing.
MAX_BYTES = 256 * 1024
MAX_ENTRIES = 5000


class Refused(Exception):
    """The document was not accepted, and this says why in words a sender can act on."""


def _string(entry, field, pattern, label):
    value = entry.get(field)
    if not isinstance(value, str) or not pattern.match(value):
        raise Refused("%s is %r, which is not %s" % (field, value, label))
    return value


def check_document(document):
    """Return the accepted entries, or raise Refused. Never returns a partial document."""
    if not isinstance(document, dict):
        raise Refused("the body is not a JSON object")
    if sorted(document) != sorted(DOCUMENT_FIELDS):
        raise Refused("the document has fields %s, expected %s"
                      % (sorted(document), sorted(DOCUMENT_FIELDS)))
    if document.get("schema_version") not in SCHEMA_VERSIONS:
        raise Refused("schema_version %r is not one this receiver reads"
                      % document.get("schema_version"))
    org = _string(document, "org", ORG_RE, "a member id")
    entries = document.get("sightings")
    if not isinstance(entries, list):
        raise Refused("sightings is not a list")
    if len(entries) > MAX_ENTRIES:
        raise Refused("%d entries, more than the %d a single request may carry"
                      % (len(entries), MAX_ENTRIES))
    for entry in entries:
        if not isinstance(entry, dict):
            raise Refused("an entry is not an object")
        extra = sorted(set(entry) - set(ALLOWED_FIELDS))
        if extra:
            raise Refused("an entry carries %s, which the allow-list does not include. "
                          "Nothing was stored." % ", ".join(extra))
        missing = sorted(set(ALLOWED_FIELDS) - set(entry))
        if missing:
            raise Refused("an entry is missing %s" % ", ".join(missing))
        # Every entry names the member the document names. Without this one document could
        # file sightings on behalf of somebody else, and the count of distinct
        # organizations, which is what the k-threshold rests on, would mean nothing.
        if entry.get("org") != org:
            raise Refused("an entry names %r but the document is from %r"
                          % (entry.get("org"), org))
        _string(entry, "pattern", PATTERN_RE, "a pattern id such as GP-0003")
        _string(entry, "hour", HOUR_RE, "an hour such as 2026-10-22T13")
        _string(entry, "sensor_version", VERSION_RE, "a version")
        _string(entry, "rules_version", VERSION_RE, "a version")
        if entry.get("action") not in ACTIONS:
            raise Refused("action is %r, expected one of %s"
                          % (entry.get("action"), ", ".join(ACTIONS)))
        if entry.get("source") not in SOURCES:
            raise Refused("source is %r, expected one of %s"
                          % (entry.get("source"), ", ".join(SOURCES)))
        count = entry.get("count")
        # bool is an int in Python, and True would otherwise be stored as a count of one.
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise Refused("count is %r, expected a whole number of at least 1" % count)
    return entries


def key_for(entry):
    """The identity of a sighting, for storing it at most once.

    A sender re-sends what it already sent: it may have been offline, or unsure the last
    attempt landed. Adding those counts would turn one detection into several and inflate
    the only numbers the research reports. So an entry has an identity, and arriving twice
    overwrites rather than accumulates. A member who was offline for a week sends
    everything and the stored total converges on the truth instead of drifting above it.

    `count` is deliberately not part of the key. It is the value being corrected.
    """
    return "|".join(str(entry[f]) for f in ALLOWED_FIELDS if f != "count")
