"""Path, file and sentinel canaries. The path is never stored.

A value canary fires when a registered secret shows up in a tool call. A path canary
fires when a registered file is touched, whatever touched it. The store holds a salted
digest of the canonical path, and a second digest of the real path when that differs.
It does not hold the path. The watcher is pointed at a root the operator named, hashes
the paths it finds, and keeps the mapping from digest to path in memory only.

A sentinel is the same idea for a hostname or URL that nothing legitimate calls. The
store holds a digest of that string. A connection to the listener is a separate signal
and does not need the string.

Seeded records are ordinary value canaries planted in a dataset. Their appearance in a
tool call, in egress, or in a second file is evidence the dataset was copied. The values
are written into the dataset and only their digests are kept.

Python 3.9+ standard library only.
"""
import csv
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import sqlite3

from . import canaries
from . import home
from . import rules

SCHEMA_VERSION = 1
BASELINE, ARMED = canaries.BASELINE, canaries.ARMED
KIND_PATH, KIND_SENTINEL = "path", "sentinel"
ROLES = ("decoy", "asset", "seed-home")
DECOY_KINDS = ("env", "ssh", "weights", "dataset", "credentials")
SEED_FORMATS = ("csv", "sqlite")
# A copy larger than this is not read into the matcher. The open is still a path event.
MAX_SCAN_BYTES = 1024 * 1024
MAX_CONTENT_BYTES = 32 * 1024 * 1024
MAX_CANDIDATES = 500

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,512}")


class PathCanaryError(Exception):
    pass


def default_path():
    return home.path("path-canaries.json")


def default_policy_path():
    return home.path("breach-policy.json")


def _digest(value, salt):
    return hmac.new(bytes.fromhex(salt), value.encode("utf-8"), hashlib.sha256).hexdigest()


def load(path=None):
    path = path or default_path()
    try:
        with open(path, encoding="utf-8") as handle:
            store = json.load(handle)
    except (OSError, ValueError):
        return {"schema_version": SCHEMA_VERSION, "salt": secrets.token_hex(16), "paths": []}
    if store.get("schema_version") != SCHEMA_VERSION:
        raise PathCanaryError(
            "path canary file is schema_version %r and this sensor understands %r"
            % (store.get("schema_version"), SCHEMA_VERSION))
    if not isinstance(store.get("salt"), str) or len(store["salt"]) < 32:
        raise PathCanaryError("path canary file has no usable salt")
    if not isinstance(store.get("paths"), list):
        raise PathCanaryError("path canary file has no path list")
    return store


def save(store, path=None):
    path = path or default_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(store, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def _require_label(label, secret):
    if not label or not str(label).strip():
        raise PathCanaryError("a path canary needs a label, because the path is not stored")
    if secret and secret in label:
        raise PathCanaryError(
            "the label contains the path or the sentinel. The label is stored in the clear "
            "and travels into evidence, so it must not be the thing being watched.")
    return label.strip()


def _existing(store, digest, fold_label=None):
    for entry in store["paths"]:
        if hmac.compare_digest(entry["hash"], digest):
            raise PathCanaryError("that path is already registered as %r" % entry["label"])
        other = entry.get("realpath_hash")
        if isinstance(other, str) and hmac.compare_digest(other, digest):
            raise PathCanaryError("that path is already registered as %r" % entry["label"])
        if fold_label and entry["label"] == fold_label:
            raise PathCanaryError("a path canary labelled %r already exists" % fold_label)


def add_path(store, path, label, state=BASELINE, role="decoy", root=None,
             content=False, decoy_hash=None):
    """Register a file by its path. Returns the entry, which does not contain the path."""
    if role not in ROLES:
        raise PathCanaryError("role must be one of %s" % ", ".join(ROLES))
    if state not in canaries.STATES:
        raise PathCanaryError("state must be one of %s" % ", ".join(canaries.STATES))
    if not path or not isinstance(path, str):
        raise PathCanaryError("add-file needs a path")
    if "\x00" in path or len(path) > 4096:
        raise PathCanaryError("that path is not one this sensor will register")
    if not os.path.lexists(path):
        raise PathCanaryError("no such file, so there is nothing to watch")
    absolute = os.path.abspath(path)
    label = _require_label(label, absolute)
    real = os.path.realpath(path)
    if root is not None and not _inside(real, root):
        raise PathCanaryError(
            "refusing to register a path that resolves outside the configured root")
    # A symlink that leaves the root is refused above. Two paths inside the root that
    # share an inode both get a digest, so an open through either name matches.
    digest = _digest(absolute, store["salt"])
    real_digest = _digest(real, store["salt"])
    _existing(store, digest)
    if real_digest != digest:
        _existing(store, real_digest)
    entry = {
        "label": label,
        "hash": digest,
        "realpath_hash": real_digest,
        "state": state,
        "kind": KIND_PATH,
        "role": role,
        "length": len(absolute),
    }
    if decoy_hash is not None:
        if (not isinstance(decoy_hash, str) or len(decoy_hash) != 64
                or any(char not in "0123456789abcdef" for char in decoy_hash)):
            raise PathCanaryError("a decoy digest must be a sha256 hex string")
        # The digest of the bytes `canary decoy` wrote. Not a path, and not a
        # reason to truncate a file that no longer matches it.
        entry["decoy_hash"] = decoy_hash
    if content and os.path.isfile(real) and not os.path.islink(path):
        file_hash, size = hash_file(real)
        if file_hash:
            entry["content_hash"] = file_hash
            entry["content_bytes"] = size
    store["paths"].append(entry)
    return entry


def add_sentinel(store, text, label, state=BASELINE):
    """Register a decoy URL or hostname. The string is not stored."""
    if not isinstance(text, str) or len(text) < 8 or len(text) > 512:
        raise PathCanaryError("a sentinel must be a short URL or hostname")
    if "\x00" in text or "\n" in text:
        raise PathCanaryError("a sentinel must be a single line")
    if state not in canaries.STATES:
        raise PathCanaryError("state must be one of %s" % ", ".join(canaries.STATES))
    label = _require_label(label, text)
    digest = _digest(text, store["salt"])
    _existing(store, digest, fold_label=label)
    entry = {
        "label": label,
        "hash": digest,
        "state": state,
        "kind": KIND_SENTINEL,
        "role": "decoy",
        "length": len(text),
    }
    store["paths"].append(entry)
    return entry


def remove(store, label):
    before = len(store["paths"])
    store["paths"] = [c for c in store["paths"] if c["label"] != label]
    return len(store["paths"]) < before


def arm(store, label):
    for entry in store["paths"]:
        if entry["label"] == label:
            entry["state"] = ARMED
            return entry
    return None


def by_label(store, label):
    for entry in store["paths"]:
        if entry["label"] == label:
            return entry
    return None


def redacted(entry):
    """What may be said about a hit. Never the path, never a sentinel string."""
    return {
        "canary": entry["label"],
        "state": entry["state"],
        "kind": entry.get("kind", KIND_PATH),
        "role": entry.get("role", "decoy"),
    }


def hits_by_label(evidence_path):
    counts = {}
    try:
        with open(evidence_path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if "GP-0041" not in record.get("patterns", []):
                    continue
                label = (record.get("detail") or {}).get("canary")
                if label:
                    counts[label] = counts.get(label, 0) + 1
    except OSError:
        return {}
    return counts


def hash_file(path, limit=MAX_CONTENT_BYTES):
    """SHA-256 of a file, or (None, size) when it is larger than the cap.

    A partial hash must not be stored as if it were the whole file, or a truncated
    copy would look like the asset.
    """
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    return None, size
                digest.update(chunk)
    except OSError:
        return None, 0
    return digest.hexdigest(), size


def _inside(path, root):
    path = os.path.realpath(path)
    root = os.path.realpath(root)
    if path == root:
        return True
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _iter_strings(value, depth=0):
    if depth > 8:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item, depth + 1)


def candidate_strings(args):
    """Path-like and URL-like strings in a tool call. Over-collects on purpose.

    A shell command is split with shlex so quoted paths stay one token. Words are
    still only candidates: a hit requires a digest match, so an ordinary word does
    not fire.
    """
    found = []
    found.extend(rules.paths_in(args))
    for command in rules.commands_in(args):
        try:
            words = shlex.split(command, posix=True)
        except ValueError:
            words = command.split()
        found.extend(words)
        found.extend(URL_RE.findall(command or ""))
    for text in _iter_strings(args):
        if not text or len(text) > 4096:
            continue
        if "/" in text or text.startswith(".") or "://" in text:
            found.append(text)
        found.extend(URL_RE.findall(text))
    # Preserve order, drop empties, cap the work a single call can force.
    out = []
    seen = set()
    for item in found:
        if not item or not isinstance(item, str) or item in seen:
            continue
        if "\x00" in item or len(item) > 4096:
            continue
        seen.add(item)
        out.append(item)
        if len(out) >= MAX_CANDIDATES:
            break
    return out


def _variants(text, roots, cwd):
    """Absolute paths and the raw string, paired with the path a human would recognise."""
    variants = [(text, text)]
    bases = []
    if cwd:
        bases.append(cwd)
    bases.extend(roots or [])
    if os.path.isabs(text):
        absolute = os.path.abspath(text)
        variants.append((absolute, absolute))
        if os.path.exists(absolute):
            variants.append((os.path.realpath(absolute), absolute))
    else:
        for base in bases:
            joined = os.path.abspath(os.path.join(base, text))
            variants.append((joined, joined))
            if os.path.exists(joined):
                variants.append((os.path.realpath(joined), joined))
    return variants


def _lookup(store):
    table = {}
    for entry in store.get("paths") or []:
        digest = entry.get("hash")
        if isinstance(digest, str):
            table.setdefault(digest, entry)
        other = entry.get("realpath_hash")
        if isinstance(other, str):
            table.setdefault(other, entry)
    return table


def match_paths(store, args, roots=None, cwd=None):
    """Entries whose path digest matches a candidate in the tool call.

    `access_path` is the path observed in the call, not a path read back from the store.
    """
    table = _lookup(store)
    salt = store.get("salt") or ""
    found = []
    seen = set()
    for raw in candidate_strings(args):
        for text, shown in _variants(raw, roots, cwd):
            if text in seen:
                continue
            seen.add(text)
            try:
                digest = _digest(text, salt)
            except ValueError:
                continue
            entry = table.get(digest)
            if not entry or entry.get("kind") == KIND_SENTINEL:
                continue
            if any(item["label"] == entry["label"] for item in found):
                continue
            hit = dict(entry)
            hit["access_path"] = shown
            found.append(hit)
    return found


def match_sentinels(store, args):
    table = {}
    salt = store.get("salt") or ""
    for entry in store.get("paths") or []:
        if entry.get("kind") == KIND_SENTINEL and isinstance(entry.get("hash"), str):
            table[entry["hash"]] = entry
    found = []
    seen = set()
    for raw in candidate_strings(args):
        if raw in seen:
            continue
        seen.add(raw)
        try:
            digest = _digest(raw, salt)
        except ValueError:
            continue
        entry = table.get(digest)
        if not entry or any(item["label"] == entry["label"] for item in found):
            continue
        hit = dict(entry)
        hit["access_path"] = None
        found.append(hit)
    return found


def hits_in_call(store, args, policy=None, cwd=None, tool_name=None):
    """Path and sentinel hits a tool call should act on.

    A seed file's path is not itself a trip: the seeded values are. An asset is a trip
    when the tool is not on that asset's allow list, and also when the call would send
    it outside the root. A decoy is a trip whenever it is named.
    """
    policy = policy or {}
    roots = []
    if policy.get("root"):
        roots.append(policy["root"])
    roots.extend(policy.get("roots") or [])
    found = []
    for entry in match_paths(store, args, roots=roots, cwd=cwd):
        if _tool_trips(entry, policy, tool_name, args):
            found.append(entry)
    found.extend(match_sentinels(store, args))
    return found


def _tool_trips(entry, policy, tool_name, args):
    role = entry.get("role")
    if role == "seed-home":
        return False
    if role != "asset":
        return True
    asset = (policy.get("assets") or {}).get(entry["label"]) or {}
    allow = asset.get("allow_tools") or []
    allowed = bool(tool_name) and tool_name in allow
    if asset.get("never_leaves") and _call_leaves(args, policy):
        return True
    return not allowed


def _call_leaves(args, policy):
    """True when the call names a destination outside the sandbox root."""
    root = policy.get("root")
    for dest in rules.destinations(args):
        if isinstance(dest, str) and dest.startswith("/") and root and _inside(dest, root):
            continue
        if dest:
            return True
    for path in rules.paths_in(args):
        if os.path.isabs(path) and root and not _inside(path, root):
            return True
    return False


def new_token():
    """A fake token that matches the value-canary rules and no built-in secret shape."""
    return "gpcanary" + secrets.token_hex(8)


def render_decoy(kind, token=None, sentinel_url=None):
    """Fake file body. Nothing here is a usable credential or a real key."""
    if kind not in DECOY_KINDS:
        raise PathCanaryError("decoy kind must be one of %s" % ", ".join(DECOY_KINDS))
    token = token or new_token()
    if kind == "env":
        lines = [
            "# decoy file, not a real environment",
            "FAKE_MARKER=%s" % token,
        ]
        if sentinel_url:
            lines.append("INTERNAL_EXPORT_URL=%s" % sentinel_url)
        return lines, "\n".join(lines) + "\n", token
    if kind == "ssh":
        body = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "FAKE NOT A KEY\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        return [], body, None
    if kind == "weights":
        body = b"FAKE-WEIGHTS\n" + secrets.token_bytes(64)
        return [], body, None
    if kind == "dataset":
        row = {"id": "decoy-row", "note": "not a real customer", "token": token}
        return ["token"], (json.dumps(row) + "\n"), token
    body = {
        "username": "decoy-user",
        "login": "decoy-login-value",
        "marker": token,
        "note": "decoy credentials, not a real account",
    }
    return ["marker"], (json.dumps(body, indent=2) + "\n"), token


def write_decoy(path, kind, token=None, sentinel_url=None):
    """Create a decoy. Refuses to overwrite, so a real file cannot be clobbered."""
    if os.path.lexists(path):
        raise PathCanaryError(
            "refusing to overwrite an existing file. add-file registers a file that is "
            "already there without changing it.")
    fields, body, token = render_decoy(kind, token=token, sentinel_url=sentinel_url)
    raw = body if isinstance(body, bytes) else body.encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(raw)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return fields, token, digest


def _filler_row(index):
    return {
        "customer_id": "cus_filler%04d" % index,
        "name": "Filler Row %d" % index,
        "email": "filler%d@example.test" % index,
        "account_number": "1000000000%04d" % index,
        "marker": "ak_filler_" + ("%032d" % index),
    }


def make_seed_values(label):
    """Fake records that look like a customer row. Not registered until the caller asks."""
    customer = "cus_" + secrets.token_hex(8)
    account = "".join(secrets.choice("0123456789") for _ in range(16))
    planted = "ak_live_" + secrets.token_hex(12)
    return [
        (customer, label + "-customer", "customer_id"),
        (account, label + "-account", "account_number"),
        (planted, label + "-marker", "marker"),
    ]


def write_seed_dataset(path, fmt, label):
    """Write a small dataset with one seeded row and two filler rows.

    Returns (values, home_label_suggestion). `values` is a list of (value, label, column)
    the caller registers and then drops. Refuses to overwrite.
    """
    if fmt not in SEED_FORMATS:
        raise PathCanaryError("seed format must be one of %s" % ", ".join(SEED_FORMATS))
    if os.path.lexists(path):
        raise PathCanaryError("refusing to overwrite an existing dataset")
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    seeded = make_seed_values(label)
    seeded_row = {column: value for value, _label, column in seeded}
    seeded_row["name"] = "Avery Lang"
    seeded_row["email"] = "avery.lang@example.test"
    rows = [_filler_row(1), seeded_row, _filler_row(2)]
    columns = ["customer_id", "name", "email", "account_number", "marker"]
    if fmt == "csv":
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
    else:
        connection = sqlite3.connect(path)
        try:
            connection.execute(
                "CREATE TABLE customers (customer_id TEXT, name TEXT, email TEXT, "
                "account_number TEXT, marker TEXT)")
            connection.executemany(
                "INSERT INTO customers VALUES (?, ?, ?, ?, ?)",
                [tuple(row[column] for column in columns) for row in rows])
            connection.commit()
        finally:
            connection.close()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return seeded


def register_seeds(value_store, seeded, state=BASELINE):
    """Register each seeded value. Returns the entries. The values stay in the dataset."""
    entries = []
    for value, label, _column in seeded:
        entries.append(canaries.add(value_store, value, label, state))
    return entries


def text_of_file(path, limit=MAX_SCAN_BYTES):
    try:
        with open(path, "rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return ""
    return data[:limit].decode("utf-8", "replace")
