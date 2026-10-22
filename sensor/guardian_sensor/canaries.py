"""Canaries the operator registers, so the sensor watches their secrets and not only ours.

Every detection in this sensor is a pattern somebody wrote down in advance. That works
against attacks we have seen and it is exactly what an adaptive attacker reads and routes
around. A canary is different in kind: it does not describe an attack, it fires because a
specific value moved, whatever moved it.

The sensor already flags its own test canaries. The values that matter to an operator are
theirs, and it had no way to learn them.

Three properties this file exists to hold.

**The value is never stored.** Only a salted digest of it. A file listing the secrets the
sensor watches for, sitting next to the sensor, would be a worse secret store than the one
it is protecting.

**The value is never emitted.** Not in evidence, not in a log line, not in an error. A
canary that leaks through the thing reporting it has been spent.

**A canary earns the right to block.** It arrives in `baseline` and only an operator moves it
to `armed`. Backups, indexers and data loss scanners legitimately touch things nobody should
touch, and a canary that fires during its own baseline is a badly placed canary rather than
an incident.

Python 3.9+ standard library only.
"""
import hashlib
import hmac
import json
import os
import re
import secrets

SCHEMA_VERSION = 1
DEFAULT_PATH = os.path.join(".guardian", "canaries.json")

# Short values collide with ordinary text, and a canary that fires on ordinary text gets
# switched off. Twelve characters is the floor for anything resembling a credential, and
# refusing shorter ones is better than letting an operator register "admin" and lose faith
# in the whole mechanism an hour later.
MIN_LENGTH = 12

BASELINE, ARMED = "baseline", "armed"
STATES = (BASELINE, ARMED)

# What might be a discrete token in outbound text. A credential appears as a token, not
# spliced into the middle of a word, so the text is split on everything a credential does not
# usually contain and each piece is hashed. That keeps the stored form a digest while still
# finding a value inside a larger body, which a whole-body hash cannot do.
TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+./=:]{%d,}" % MIN_LENGTH)


class CanaryError(Exception):
    pass


def _digest(value, salt):
    """Salted so the file cannot be attacked with a list of likely secrets.

    An unsalted digest of an API key is as good as the key to anyone holding a rainbow table
    of the vendor's key space, and vendors publish their key formats.
    """
    return hmac.new(bytes.fromhex(salt), value.encode("utf-8"), hashlib.sha256).hexdigest()


def load(path=DEFAULT_PATH):
    try:
        with open(path, encoding="utf-8") as f:
            store = json.load(f)
    except (OSError, ValueError):
        return {"schema_version": SCHEMA_VERSION, "salt": secrets.token_hex(16),
                "canaries": []}
    if store.get("schema_version") != SCHEMA_VERSION:
        raise CanaryError(
            "canary file is schema_version %r and this sensor understands %r"
            % (store.get("schema_version"), SCHEMA_VERSION))
    if not isinstance(store.get("salt"), str) or len(store["salt"]) < 32:
        raise CanaryError("canary file has no usable salt, so its digests cannot be checked")
    return store


def save(store, path=DEFAULT_PATH):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, sort_keys=True)
        f.write("\n")
    # Replaced rather than truncated and rewritten, so a crash midway cannot leave the
    # sensor with half a canary list and no way to tell.
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def add(store, value, label, state=BASELINE):
    """Register a value. Returns the new entry, which never contains the value.

    `label` is how a human recognises the canary afterwards, since they will never see the
    value again here. It must not be the value, and a label that contains it is refused,
    because an operator pasting the secret into both fields would undo the whole point.
    """
    if not isinstance(value, str) or len(value) < MIN_LENGTH:
        raise CanaryError(
            "a canary must be at least %d characters. Shorter values collide with ordinary "
            "text, and a canary that fires on ordinary text gets turned off." % MIN_LENGTH)
    if not label or not label.strip():
        raise CanaryError("a canary needs a label, because you will not see the value again")
    if value in label:
        raise CanaryError("the label contains the canary value. The label is stored in the "
                          "clear and travels into evidence, so it must not be the secret.")
    if state not in STATES:
        raise CanaryError("state must be one of %s" % ", ".join(STATES))
    if not TOKEN_RE.fullmatch(value):
        raise CanaryError(
            "this value contains characters that are not matched as a token, such as spaces, "
            "so it would never be found in outbound text. Register a credential or a token, "
            "not a sentence.")

    digest = _digest(value, store["salt"])
    for existing in store["canaries"]:
        if hmac.compare_digest(existing["hash"], digest):
            raise CanaryError("that value is already registered as %r" % existing["label"])

    # No hit counter is stored here. A count in this file would have to be written by the
    # sensor on every detection, which means the component holding digests of the
    # operator's secrets gains a write path on a hot code path, for a number that is already
    # recorded in the evidence log. `hits_by_label` derives it from there instead, so there
    # is one source of truth and this file stays something only the operator writes.
    entry = {"label": label.strip(), "hash": digest, "state": state}
    store["canaries"].append(entry)
    return entry


def remove(store, label):
    before = len(store["canaries"])
    store["canaries"] = [c for c in store["canaries"] if c["label"] != label]
    return len(store["canaries"]) < before


def arm(store, label):
    """Move a canary from baseline to armed. Only an operator does this."""
    for c in store["canaries"]:
        if c["label"] == label:
            c["state"] = ARMED
            return c
    return None


def tokens(text):
    """Candidate tokens in outbound text, deduplicated."""
    return set(TOKEN_RE.findall(text or ""))


def matches(store, text):
    """Registered canaries present in `text`, as a list of entries. Never returns a value.

    Each candidate token is hashed and compared, so the stored form stays a digest. A value
    spliced into the middle of a longer run of characters, or re-encoded on the way out, is
    not found. That limitation is real and is documented rather than hidden: this catches a
    credential being passed on, not a credential being smuggled.
    """
    if not store.get("canaries"):
        return []
    by_hash = {c["hash"]: c for c in store["canaries"]}
    found = []
    for token in tokens(text):
        entry = by_hash.get(_digest(token, store["salt"]))
        if entry is not None and entry not in found:
            found.append(entry)
    return found


def hits_by_label(evidence_path):
    """How many times each canary has fired, read from the evidence log.

    This is what the baseline period is for. An operator is told to watch a canary through a
    few days of ordinary work and arm it if it never fires, so the count has to be real: a
    counter that always reads zero would have them arm a canary that had been firing all
    week, which is the opposite of what baseline is for.
    """
    counts = {}
    try:
        with open(evidence_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if "GP-0020" not in record.get("patterns", []):
                    continue
                label = (record.get("detail") or {}).get("canary")
                if label:
                    counts[label] = counts.get(label, 0) + 1
    except OSError:
        return {}
    return counts


def redacted(entry):
    """What may be said about a canary hit. Label and state only, never the value."""
    return {"canary": entry["label"], "state": entry["state"]}
