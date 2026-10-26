"""What the network has seen, read by a member's own machine.

The last link. A sighting reached an aggregate and stopped there: nothing a member's machine
could read told them what anybody else had seen, so "the network told me" was a description
rather than a mechanism.

An alert says a pattern cleared the three organization threshold, how many contributed, and
when it was published. It says nothing about who, because an alert derived from anonymous
reports must not be less anonymous than the reports were.

Read by polling a static file, the same way the agenda is read. Nothing is pushed to a member
and nothing can be: there is no listener here, and an alert can only say what was seen, never
what to do about it.

Python 3.9+ standard library only.
"""
import datetime
import json
import os
import urllib.request

SCHEMA_VERSIONS = ("1",)
ALERTS_NAME = "alerts.json"
SEEN_NAME = "alerts-seen.json"

# The only keys an alert document may carry, and the only keys an alert may. An alert that
# could carry an instruction would be a command channel with a friendlier name, so the shape
# is checked rather than trusted and an unknown key is refused rather than ignored.
DOCUMENT_KEYS = ("schema_version", "published", "source", "alerts", "note")
# The same floor the aggregator publishes under. Stated here as well, rather than
# imported, because the sensor depends on nothing outside its own package and a reader
# must be able to check this without the publisher's code.
MIN_ORGS = 3

ALERT_KEYS = ("pattern", "organizations", "total")


class AlertError(Exception):
    pass


def parse(document):
    """Check an alerts document. Returns its alerts, or raises."""
    if not isinstance(document, dict):
        raise AlertError("the alerts document is not an object")
    extra = sorted(set(document) - set(DOCUMENT_KEYS))
    if extra:
        raise AlertError(
            "the alerts document carries %s, which this sensor does not understand. An "
            "alert says what was seen and never what to do, so an unknown key is refused "
            "rather than ignored." % ", ".join(extra))
    if document.get("schema_version") not in SCHEMA_VERSIONS:
        raise AlertError("alerts schema_version %r is not one this sensor reads"
                         % document.get("schema_version"))
    alerts = document.get("alerts")
    if not isinstance(alerts, list):
        raise AlertError("alerts should be a list")

    out = []
    for alert in alerts:
        if not isinstance(alert, dict):
            raise AlertError("an alert is not an object")
        unknown = sorted(set(alert) - set(ALERT_KEYS))
        if unknown:
            raise AlertError("an alert carries %s, which is not part of the format"
                             % ", ".join(unknown))
        pattern = alert.get("pattern")
        if not isinstance(pattern, str) or not pattern.startswith("GP-"):
            raise AlertError("an alert names %r, which is not a pattern" % pattern)
        for key in ("organizations", "total"):
            if not isinstance(alert.get(key), bool) and isinstance(alert.get(key), int) \
                    and alert[key] >= 1:
                continue
            raise AlertError("an alert's %s is %r, which is not a count"
                             % (key, alert.get(key)))
        # The published note says these are patterns at least three independent
        # organizations saw. A reader that displays that sentence and accepts an alert
        # claiming one has not checked the guarantee it is repeating. The publisher
        # enforces the floor; so does this, because the publisher runs somewhere else.
        if alert["organizations"] < MIN_ORGS:
            raise AlertError("an alert claims %d organizations, below the floor of %d that "
                             "makes a published count safe to repeat"
                             % (alert["organizations"], MIN_ORGS))
        # Every contributing organization supplies at least one sighting, so a total below
        # the number of organizations describes something that cannot have happened.
        if alert["total"] < alert["organizations"]:
            raise AlertError("an alert claims %d organizations but only %d sightings, which "
                             "cannot both be true"
                             % (alert["organizations"], alert["total"]))
        out.append(alert)
    return out


def fetch(base, opener=None, timeout=30):
    """The published alerts, or None if there are none to read."""
    opener = opener or urllib.request.urlopen
    url = base.rstrip("/") + "/" + ALERTS_NAME
    with opener(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def seen(root):
    try:
        with open(os.path.join(root, SEEN_NAME), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


# How much larger a pattern has to get before it is worth interrupting somebody. At
# least doubling, and at least this many more organizations, so a jump from one to two
# is not an alarm and a jump from six to forty is.
SPIKE_FACTOR = 2
SPIKE_FLOOR = 3


def _count(record):
    """Organizations last seen for a pattern, from either file format."""
    if isinstance(record, dict):
        value = record.get("organizations")
        return value if isinstance(value, int) else None
    return None


def rising(root, alerts):
    """Patterns that have grown sharply since this machine last looked.

    This is the early warning. Nobody is named and nothing is attributed: a member sees
    that an attack is spreading across the network far faster than it was, which is
    enough to go and look, and enough to ask the people they know whether they are
    seeing it too.

    Computed here rather than published, because a published trend would be one
    operator deciding what counts as an emergency for everybody, and because the alerts
    format refuses fields it does not know, so it could not carry one without every
    existing reader refusing the whole document.
    """
    known = seen(root)
    out = []
    for alert in alerts:
        now = alert.get("organizations")
        if not isinstance(now, int):
            continue
        before = _count(known.get(alert["pattern"]))
        if before is None:
            continue                     # never seen with a count, so nothing to compare
        if now >= before * SPIKE_FACTOR and now - before >= SPIKE_FLOOR:
            out.append({"pattern": alert["pattern"], "before": before, "now": now})
    return out


def remember(root, alerts, published):
    """Record what has been seen, so the same alert is announced once.

    A poll runs every sixty seconds. Announcing the same alert every time would train a
    member to ignore the one line that matters, which is the opposite of the point.
    """
    os.makedirs(root, exist_ok=True)
    known = seen(root)
    # What was seen, not only that it was seen. A pattern going from six organizations
    # to forty is the thing worth noticing, and a node cannot notice it from a list of
    # names. Older files hold a bare timestamp per pattern and are read as such.
    known.update({a["pattern"]: {"published": published,
                                 "organizations": a.get("organizations"),
                                 "total": a.get("total")} for a in alerts})
    path = os.path.join(root, SEEN_NAME)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(known, f, indent=2, sort_keys=True)
        f.write("\n")
    return known


def unseen(root, alerts):
    """Which alerts this machine has not been told about yet."""
    known = seen(root)
    return [a for a in alerts if a["pattern"] not in known]
