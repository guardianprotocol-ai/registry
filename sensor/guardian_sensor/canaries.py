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
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import urllib.parse

from . import home

SCHEMA_VERSION = 1
def default_path():
    return home.path("canaries.json")


# Resolved at import for display only. Anything that opens a file calls default_path(),
# so a command run with GUARDIAN_HOME set uses the directory it was given.
DEFAULT_PATH = default_path()

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
    fold = _digest(value.casefold(), store["salt"])
    for existing in store["canaries"]:
        if hmac.compare_digest(existing["hash"], digest):
            raise CanaryError("that value is already registered as %r" % existing["label"])
        existing_fold = existing.get("fold")
        if isinstance(existing_fold, str) and hmac.compare_digest(existing_fold, fold):
            raise CanaryError(
                "that value differs only by case from %r. Registering both would make a "
                "case-only copy ambiguous about which label fired." % existing["label"])

    # No hit counter is stored here. A count in this file would have to be written by the
    # sensor on every detection, which means the component holding digests of the
    # operator's secrets gains a write path on a hot code path, for a number that is already
    # recorded in the evidence log. `hits_by_label` derives it from there instead, so there
    # is one source of truth and this file stays something only the operator writes.
    #
    # `length` is not the secret. It lets a value glued inside a short carrier be found
    # by that exact width, instead of hashing every window of every width.
    # `fold` is the digest of the case-folded value. A copy that differs only by case
    # still matches, and the value is still not stored. Two digests, never the text.
    entry = {"label": label.strip(), "hash": digest, "state": state,
             "length": len(value), "fold": fold}
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


# A run of "=" that is base64 padding, not a name-and-value separator: it sits at the
# end of the token, or immediately before another separator. "KEY=VALUE==" used to
# split into "KEY" and "VALUE", and the padding was eaten, so a registered base64
# value that ends in "==" was invisible the moment it followed an equals sign.
_PADDING = re.compile(r"=(?==*(?:[&?;,:/]|$))")
# Separators a credential is wrapped in. ":" is "key:VALUE". "/" is a URL path
# segment. Both used to stay inside the token, so the hashed string was the wrapper
# plus the value and never the value.
_SEPARATORS = re.compile(r"[=&?;,:/]+")
_B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
# Pieces shorter than a token. A value split across two calls is not a token on
# either side. "part1" in the regression suite is 5 characters and must not be kept,
# or it glues to the half and the join is no longer the value.
FRAGMENT_RE = re.compile(r"[A-Za-z0-9_\-+./=:]{6,80}")
# Sliding a window across a multi-kilobyte blob is what made a large file write
# expensive in measurement, and a value sitting in its own token does not need it.
# 256 is enough for a value glued inside a URL or a short carrier.
MAX_SLIDE = 256
MAX_DECODE = 8192


def _surfaces(text):
    """Strings worth tokenising. JSON is decoded so a newline is a newline.

    Tool arguments arrive as a JSON object. A value on its own line was hashed as
    "nVALUE", because the encoding of the newline is a backslash and an n, and the
    backslash splits the token while the n stays on the value. Decoding the JSON
    strings first is the fix. Percent-decoding is applied to those strings, because
    "%" is not part of a token either.
    """
    raw = text or ""
    found = [raw]
    parsed = None
    stripped = raw.strip()
    if stripped[:1] in "{[":
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            parsed = None
    if parsed is not None:
        _walk_strings(parsed, found)
    extra = []
    for item in found:
        if "%" in item:
            once = urllib.parse.unquote(item)
            extra.append(once)
            if "%" in once:
                extra.append(urllib.parse.unquote(once))
    for item in extra:
        if item not in found:
            found.append(item)
    return found


def _walk_strings(obj, found):
    if isinstance(obj, str):
        if obj and obj not in found:
            found.append(obj)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            _walk_strings(key, found)
            _walk_strings(value, found)
    elif isinstance(obj, list):
        for value in obj:
            _walk_strings(value, found)


def fragments(text):
    """Short pieces of outbound text, so a later call can finish a value this one started.

    The first four and the last four distinct pieces, in order. A long document has
    thousands of ordinary words, and keeping every one would make the next call join
    against a transcript. Membership is a set: scanning a list to drop duplicates is
    quadratic in the number of words, which a large tool argument has.
    """
    first = []
    last = []
    seen = set()
    for surface in _surfaces(text):
        for piece in FRAGMENT_RE.findall(surface):
            if piece in seen:
                continue
            seen.add(piece)
            if len(first) < 4:
                first.append(piece)
            else:
                last.append(piece)
                if len(last) > 4:
                    del last[0]
    return first + last


def _parts(token):
    """The token, then the pieces separators leave, with base64 padding kept."""
    yield token
    bare = token.rstrip(".")
    if bare != token:
        yield bare
    protected = _PADDING.sub("\x01", token)
    if protected == token and not _SEPARATORS.search(token):
        return
    segments = [part.replace("\x01", "=") for part in _SEPARATORS.split(protected)]
    for part in segments:
        if part:
            yield part
            bare = part.rstrip(".")
            if bare != part:
                yield bare
    # A value that itself contains "/" is more than one segment. Put a few neighbouring
    # segments back together. Three is enough for the shapes we register.
    if "/" in token:
        segs = [part for part in token.split("/") if part]
        for start in range(len(segs)):
            acc = segs[start]
            for nxt in range(start + 1, min(start + 3, len(segs))):
                acc = acc + "/" + segs[nxt]
                yield acc


def _decoded(token):
    """One layer of base64, base64url or hex. Not a second layer, and not compression."""
    if not token or len(token) > MAX_DECODE:
        return
    blobs = []
    if len(token) >= 16 and _B64.match(token):
        padded = token + ("=" * ((4 - len(token) % 4) % 4))
        try:
            blobs.append(base64.b64decode(padded))
        except Exception:
            pass
    if len(token) >= 16 and ("-" in token or "_" in token) and _B64URL.match(token):
        padded = token + ("=" * ((4 - len(token) % 4) % 4))
        try:
            blobs.append(base64.urlsafe_b64decode(padded))
        except Exception:
            pass
    if len(token) >= MIN_LENGTH * 2 and len(token) % 2 == 0 and _HEX.match(token):
        try:
            blobs.append(bytes.fromhex(token))
        except ValueError:
            pass
    seen = set()
    for raw in blobs:
        if not raw or len(raw) > MAX_DECODE:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(text) >= MIN_LENGTH and text not in seen:
            seen.add(text)
            yield text


def _windows(token, lengths):
    if len(token) > MAX_SLIDE:
        return
    for length in lengths:
        if length < MIN_LENGTH or len(token) <= length:
            continue
        span = len(token) - length + 1
        for index in range(span):
            yield token[index:index + length]


def _joins(prior, current):
    if not prior or not current:
        return
    for left in prior[-3:]:
        if len(left) < 6:
            continue
        for right in current[:4]:
            if len(right) < 6:
                continue
            yield left + right


def matches(store, text, prior=None, pieces=None):
    """Registered canaries present in `text`, as a list of entries. Never returns a value.

    Candidates are hashed and compared to the salted digest. The forms tried are the
    token, the pieces a separator leaves (with base64 padding kept), a trailing period
    removed, JSON string values, percent-decoding, one layer of base64 or hex, the
    reverse of a token, the case-folded digest, a value glued inside a short carrier,
    and the join of a piece from `prior` with a piece from this text. `prior` is how a
    value split across two calls is put back together, in order.

    Still not tried, on purpose: a second encoding layer, compression, rot13, a change
    that drops part of the value, and a value that never appears in tool text. Those
    are measured as held-out cases rather than quietly added after a score.
    """
    rows = store.get("canaries") or []
    if not rows:
        return []
    by_hash = {}
    by_fold = {}
    lengths = []
    for row in rows:
        by_hash[row["hash"]] = row
        fold = row.get("fold")
        if isinstance(fold, str):
            by_fold[fold] = row
        length = row.get("length")
        if isinstance(length, int) and MIN_LENGTH <= length <= MAX_SLIDE:
            if length not in lengths:
                lengths.append(length)
    found = []
    seen = set()
    salt = store["salt"]

    def hit(value, folded):
        if not isinstance(value, str) or len(value) < MIN_LENGTH or len(value) > 4096:
            return
        table = by_fold if folded else by_hash
        entry = table.get(_digest(value, salt))
        if entry is None or entry["label"] in seen:
            return
        seen.add(entry["label"])
        found.append(entry)

    def consider(value):
        hit(value, False)
        folded = value.casefold()
        hit(folded, True)
        rev = value[::-1]
        if rev != value:
            hit(rev, False)
            hit(rev.casefold(), True)

    for surface in _surfaces(text):
        for token in tokens(surface):
            for candidate in _parts(token):
                if len(candidate) < MIN_LENGTH:
                    continue
                consider(candidate)
                for window in _windows(candidate, lengths):
                    consider(window)
                for decoded in _decoded(candidate):
                    consider(decoded)
                    for inner in tokens(decoded):
                        if inner != decoded and len(inner) >= MIN_LENGTH:
                            consider(inner)
            if len(found) == len(rows):
                return found
    # Nothing to join with on the first call. Computing the pieces anyway is a full
    # scan of the argument, and the caller already does that when it stores them for
    # the next call.
    if prior:
        if pieces is None:
            pieces = fragments(text)
        for joined in _joins(list(prior), pieces):
            consider(joined)
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
