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
            if not isinstance(alert.get(key), int) or alert[key] < 1:
                raise AlertError("an alert's %s is %r, which is not a count"
                                 % (key, alert.get(key)))
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


def remember(root, alerts, published):
    """Record what has been seen, so the same alert is announced once.

    A poll runs every sixty seconds. Announcing the same alert every time would train a
    member to ignore the one line that matters, which is the opposite of the point.
    """
    os.makedirs(root, exist_ok=True)
    known = seen(root)
    known.update({a["pattern"]: published for a in alerts})
    path = os.path.join(root, SEEN_NAME)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(known, f, indent=2, sort_keys=True)
        f.write("\n")
    return known


def unseen(root, alerts):
    """Which alerts this machine has not been told about yet."""
    known = seen(root)
    return [a for a in alerts if a["pattern"] not in known]
