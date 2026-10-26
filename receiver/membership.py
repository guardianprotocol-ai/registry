"""Who holds a member id, and whether this report really came from them.

Trust on first use. The first time a member reports, the key they send becomes theirs and
is recorded. Every report after that must be signed with it, and one that is not is
refused. Nobody can take a name that is already in use.

This is deliberately not an identity system. It does not know, and does not claim to
know, that a member id belongs to any particular organization in the world. It knows that
whoever reported first still holds the key. Binding a key to a real named organization
needs somebody to verify that and stand behind it, which is a different thing with legal
weight behind it, and the protocol only needs to carry the claim, never to make it.

What it stops: taking over an established member id, and quietly poisoning one
organization's numbers by posting in their name.

What it does not stop: inventing new member ids. Nothing here makes a second identity
expensive. An actor running many senders can still look like many organizations, which
matters because the k-threshold counts organizations. Making enrolment cost something,
by invitation or by attestation, is a separate decision.

Standard library only, no cloud dependency, so a receiver anywhere can implement it.
"""
import hashlib
import hmac

SIGNATURE_HEADER = "X-Guardian-Signature"


class Refused(Exception):
    """This report was not accepted, and the message says why."""


def fingerprint(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def sign(key, body):
    if isinstance(body, str):
        body = body.encode("utf-8")
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()


def check(known_key, body, signature):
    """Whether this body was signed by the holder of the known key.

    Constant time, so a receiver cannot be used to recover a key one byte at a time.
    """
    if not known_key or not signature:
        return False
    return hmac.compare_digest(sign(known_key, body), str(signature))


def decide(org, known, body, signature, offered_key=None):
    """What to do with a report. Returns (key_to_store, note) or raises Refused.

    Three cases, and the middle one is the whole point.

    A member nobody has seen before: their key becomes theirs. Recorded, not questioned,
    because there is nothing yet to check it against.

    A member already known: the signature must match the key recorded for them. This is
    where taking somebody else's name fails.

    A member already known, reporting without a signature: refused. Accepting it would
    mean an established member id could be used by anybody who simply left the header
    out, which would make the whole check decoration.
    """
    if known:
        if not signature:
            raise Refused("%r has reported before and this report is not signed. A "
                          "member id in use can only be reported under by whoever "
                          "holds its key." % org)
        if not check(known, body, signature):
            raise Refused("the signature on this report does not match the key %r "
                          "first reported with." % org)
        return known, "known member"
    if not offered_key:
        # First contact without a key is allowed: a member who has not been given one
        # yet, or an implementation that does not sign. They are recorded unsigned, and
        # from then on anybody may report as them, which is said out loud rather than
        # pretended away.
        return None, "first contact, unsigned"
    if not check(offered_key, body, signature):
        raise Refused("the key offered for %r does not match the signature on the "
                      "report it arrived with." % org)
    return offered_key, "first contact, key recorded"
