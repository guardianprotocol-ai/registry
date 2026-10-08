"""The minimal sharing hub: anonymized sightings out, verified rule updates in.

Privacy here is by construction, not by redaction. The output is **built** from a fixed
list of fields, and the values that go into it are checked against a fixed shape before
they are used. Nothing is ever copied out of an evidence record and then cleaned up: the
parts of a record that hold content (`detail`, `reasons`) are never read at all.

That distinction matters. A redactor is a filter someone can get past. An allow-list is a
wall: a value that is not a known pattern id or a known action simply has nothing to be
written into.

Python 3.9+ standard library only.
"""
import datetime
import hashlib
import json
import os
import re

SCHEMA_VERSION = "0.1"
SENSOR_VERSION = "guardian-sensor v0"

# The only keys a sightings entry may ever have.
ALLOWED_FIELDS = ("org", "sensor_version", "rules_version", "pattern", "action", "hour", "count")

# The only values those fields may hold, besides the counts and the ones the member sets.
PATTERN_RE = re.compile(r"^GP-\d{4}$")
ACTIONS = ("flagged", "blocked")
ORG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$")
HOUR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}$")
# The two version fields are the only ones a caller hands in rather than the hub deriving
# them, so they get the same treatment as the rest. Without a shape, anything a caller or a
# release manifest puts here rides out in every entry, and 'nothing else leaves this
# machine' stops being true. Releases look like r2026.10.08.
RULES_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
SENSOR_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")

DEFAULT_EVIDENCE = (".guardian/evidence.jsonl",)


class HubError(Exception):
    pass


# --------------------------------------------------------------------------
# Sightings out
# --------------------------------------------------------------------------

def _hour_of(value):
    """The hour a record falls in, or None. Nothing finer than an hour ever leaves."""
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp.strftime("%Y-%m-%dT%H")


def _patterns_of(record):
    """Pattern ids from a record, keeping only ones shaped like a registry id."""
    raw = record.get("patterns")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [p for p in raw if isinstance(p, str) and PATTERN_RE.match(p)]


def _action_of(record):
    action = record.get("action")
    return action if action in ACTIONS else None


def read_evidence(paths, since=None):
    """Every evidence record from the given logs. Malformed lines are skipped, not raised."""
    cutoff = None
    if since:
        try:
            cutoff = datetime.date.fromisoformat(since)
        except ValueError:
            raise HubError(f"--since {since!r} is not a date. Use YYYY-MM-DD.")
    out = []
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(record, dict):
                    continue
                if cutoff:
                    hour = _hour_of(record.get("time"))
                    if not hour or datetime.date.fromisoformat(hour[:10]) < cutoff:
                        continue
                out.append(record)
    return out


def build_sightings(records, org, rules_version, sensor_version=SENSOR_VERSION):
    """Counts by pattern, action and hour. Built from the allow-list, never copied.

    Only three things are read from each record: its pattern ids, its action and its
    timestamp. Each is checked against a fixed shape first. `detail` and `reasons`, which
    are the fields that hold tool names, arguments, URLs, paths and message bodies, are
    never read by this function or anything it calls.
    """
    if not ORG_RE.match(org or ""):
        raise HubError(
            f"org {org!r} must be 3 to 32 characters, lowercase letters, digits and hyphens. "
            "It is a pseudonym you choose, never a company name.")
    if not isinstance(rules_version, str) or not rules_version.strip():
        raise HubError("rules_version is required. Run 'update' first, or pass --rules-version.")
    if not RULES_VERSION_RE.match(rules_version):
        raise HubError(
            f"rules_version {rules_version!r} is not a version. Up to 32 characters, letters, "
            "digits, dots, hyphens and underscores, like r2026.10.08. It is shared with every "
            "entry, so it may not carry free text.")
    if not SENSOR_VERSION_RE.match(sensor_version or ""):
        raise HubError(
            f"sensor_version {sensor_version!r} is not a version. Up to 40 characters, letters, "
            "digits, spaces, dots, hyphens and underscores. It is shared with every entry, so "
            "it may not carry free text.")

    counts = {}
    for record in records:
        action = _action_of(record)
        hour = _hour_of(record.get("time"))
        if not action or not hour:
            continue
        for pattern in _patterns_of(record):
            counts[(pattern, action, hour)] = counts.get((pattern, action, hour), 0) + 1

    entries = []
    for (pattern, action, hour), count in sorted(counts.items()):
        entry = {
            "org": org,
            "sensor_version": sensor_version,
            "rules_version": rules_version,
            "pattern": pattern,
            "action": action,
            "hour": hour,
            "count": count,
        }
        # A last gate, so a future edit cannot widen the output by accident.
        if tuple(entry) != ALLOWED_FIELDS:
            raise HubError(f"sightings entry has fields {tuple(entry)}, expected {ALLOWED_FIELDS}")
        entries.append(entry)

    return {"schema_version": SCHEMA_VERSION, "org": org, "sightings": entries}


def preview_text(document):
    """Exactly what would be shared, as the member will see it before approving."""
    entries = document["sightings"]
    lines = [
        "This is the whole of what would be shared. Nothing else leaves this machine.",
        "",
        f"Member id: {document['org']}",
        f"Entries:   {len(entries)}",
    ]
    # Every field's value has to be on screen, not just its name. The promise above is that
    # this is the whole of what leaves, and a member cannot consent to a value they were
    # never shown. sensor_version is the same for every entry, so it belongs in the header
    # rather than repeated down the table.
    for name in sorted({e["sensor_version"] for e in entries}):
        lines.append(f"Sensor:    {name}")
    lines.append("")
    if not entries:
        lines.append("Nothing to share for that period.")
        return "\n".join(lines)
    lines.append(f"{'pattern':<10} {'action':<9} {'hour':<15} {'rules':<12} count")
    lines.append("-" * 56)
    for e in entries:
        lines.append(f"{e['pattern']:<10} {e['action']:<9} {e['hour']:<15} "
                     f"{e['rules_version']:<12} {e['count']}")
    lines += [
        "",
        "Fields shared: " + ", ".join(ALLOWED_FIELDS) + ".",
        "No tool names, no arguments, no URLs, no paths, no message text, and no timestamp "
        "finer than the hour. Those are not removed from the output; they are never read.",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Rules in
# --------------------------------------------------------------------------

def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_of_bytes(data):
    return hashlib.sha256(data).hexdigest()


def verify_against_manifest(manifest, files):
    """files is {name: bytes}. Returns the rules version, or raises.

    Refusing is the whole point, so every failure mode is explicit: a file the manifest
    does not mention, a file the manifest mentions that did not arrive, or a hash that does
    not match.
    """
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict):
        raise HubError("the manifest is not readable. Refusing to update.")
    expected = manifest["files"]
    rules_version = manifest.get("rules_version")
    if not isinstance(rules_version, str) or not rules_version.strip():
        raise HubError("the manifest names no rules_version. Refusing to update.")
    # Checked here too: this value is written into the update record and later shared with
    # every sightings entry, so a hub must not be able to put free text into a member's
    # outgoing data by way of its own manifest.
    if not RULES_VERSION_RE.match(rules_version):
        raise HubError(f"the manifest's rules_version {rules_version!r} is not a version. "
                       "Refusing to update.")

    missing = sorted(set(expected) - set(files))
    if missing:
        raise HubError("the release is missing " + ", ".join(missing) + ". Refusing to update.")
    extra = sorted(set(files) - set(expected))
    if extra:
        raise HubError("the release has files the manifest does not cover: "
                       + ", ".join(extra) + ". Refusing to update.")
    for name, want in sorted(expected.items()):
        got = sha256_of_bytes(files[name])
        if got != want:
            raise HubError(f"{name} does not match the manifest. Expected {want}, got {got}. "
                           "Refusing to update.")
    return rules_version


def record_update(path, rules_version, source):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    entry = {
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "rules_version": rules_version,
        "source": source,
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def current_rules_version(path):
    """The rules version from the last successful update, or None."""
    if not os.path.exists(path):
        return None
    version = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and isinstance(entry.get("rules_version"), str):
                version = entry["rules_version"]
    return version
