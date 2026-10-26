"""A member's own key, and the signature that proves a report came from them.

Without this, anybody who knows a member id can file sightings under it. That matters
more as the network grows, not less: the k-threshold counts distinct organizations, and
counting is only meaningful if an organization cannot be impersonated or drowned out by
somebody posting in their name.

The key is made on this machine, kept on this machine, and sent once to the receiver the
member chose, over TLS, when they first report. After that every report carries a
signature over exactly the bytes that were sent, and a receiver that has seen this member
before refuses anything that does not match. First contact establishes who they are, and
nobody can take the name afterwards.

What this does and does not do, said plainly, because the difference matters:

**It stops impersonation.** Once a member has reported, their name is theirs. Somebody
else posting as them is refused.

**It does not stop somebody inventing new members.** Nothing here makes creating a second
identity expensive, so an actor willing to run many senders can still manufacture the
appearance of many organizations. That needs enrolment to cost something, by invitation
or by attestation, and it is a separate decision recorded in the proposals.

HMAC rather than a public key signature because the core of this project depends on the
standard library alone, and the standard library has no asymmetric signing. The cost is
that a third party cannot verify a signature, only the receiver can. Public verifiability
is what attribution needs, and it is the reason to revisit this.

Python 3.9+ standard library only.
"""
import hashlib
import hmac
import json
import os
import secrets
import stat

KEY_NAME = "member-key.json"
SCHEMA_VERSION = 1
# 256 bits from the OS. Long enough that guessing is not a strategy, short enough to
# print if somebody ever needs to move a member to another machine.
KEY_BYTES = 32


def key_path(root):
    return os.path.join(root, KEY_NAME)


def load_or_create(root):
    """This machine's member key, making one the first time it is asked for."""
    path = key_path(root)
    try:
        with open(path, encoding="utf-8") as f:
            record = json.load(f)
        if record.get("schema_version") == SCHEMA_VERSION and record.get("key"):
            return record["key"]
    except (OSError, ValueError):
        pass
    key = secrets.token_hex(KEY_BYTES)
    os.makedirs(root, exist_ok=True)
    # Written before the permissions are narrowed, then narrowed, because a key readable
    # by every account on a shared machine is not a key.
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"schema_version": SCHEMA_VERSION, "key": key,
                   "what_this_is": ("Proves reports came from this member. It is sent "
                                    "once to the receiver and never travels again. "
                                    "Anybody holding it can report as you.")},
                  f, indent=2, sort_keys=True)
        f.write("\n")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key


def fingerprint(key):
    """A short public name for a key, safe to log. Never the key itself."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def sign(key, body):
    """A signature over exactly the bytes being sent.

    Over the bytes rather than over a re-serialised object, because two serialisations of
    the same document differ in whitespace and key order, and a signature that depends on
    how something was formatted is a signature that fails for reasons nobody can see.
    """
    if isinstance(body, str):
        body = body.encode("utf-8")
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify(key, body, signature):
    """Constant time, so a receiver cannot be asked to leak a key one byte at a time."""
    if not key or not signature:
        return False
    return hmac.compare_digest(sign(key, body), str(signature))


REGISTERED_NAME = "registered.json"


def registered_with(root, endpoint):
    """Whether this member has already given their key to this receiver.

    The key travels once. Sending it on every report would make the signature pointless,
    because anybody who could read one request could read the key in it, and the key is
    the thing the signature exists to avoid sending.
    """
    try:
        with open(os.path.join(root, REGISTERED_NAME), encoding="utf-8") as f:
            return endpoint in (json.load(f).get("endpoints") or [])
    except (OSError, ValueError):
        return False


def note_registered(root, endpoint):
    path = os.path.join(root, REGISTERED_NAME)
    try:
        with open(path, encoding="utf-8") as f:
            record = json.load(f)
    except (OSError, ValueError):
        record = {}
    endpoints = sorted(set(record.get("endpoints") or []) | {endpoint})
    os.makedirs(root, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"endpoints": endpoints}, f, indent=2, sort_keys=True)
        f.write("\n")


def forget_registration(root, endpoint):
    """Used when a receiver says it does not know this member after all.

    A receiver that lost its records, or a member moved to a new one, would otherwise be
    stuck signing against a key nobody has.
    """
    path = os.path.join(root, REGISTERED_NAME)
    try:
        with open(path, encoding="utf-8") as f:
            record = json.load(f)
    except (OSError, ValueError):
        return
    endpoints = [e for e in (record.get("endpoints") or []) if e != endpoint]
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"endpoints": endpoints}, f, indent=2, sort_keys=True)
        f.write("\n")
