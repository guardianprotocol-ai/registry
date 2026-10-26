"""How long a receiver keeps what, and how a member takes their data back.

A receiver holding every sighting forever is holding a live map of which organizations
are under attack, when, and with what. The protocol's whole claim is that it collects as
little as possible, and collecting little in transit while keeping everything at rest is
not that claim, it is half of it.

Two ideas, and the first is the one that matters.

**The identified rows are temporary. The counts are not.** A sighting arrives with a
member id because the k-threshold has to count distinct organizations. Once the window
it belongs to has been aggregated, the member id has done its work: the aggregate says
four organizations saw this, and which four stops being needed. So identified rows carry
an expiry, and the aggregate they contributed to does not.

**A member can take their data back.** Signed with the key they report with, so only they
can ask, and the request names nothing a stranger could use. Without this the protocol
asks organizations to send data to somewhere they cannot leave, which is not a thing a
security team is allowed to agree to.

Standard library only, so this is part of the contract rather than part of our deployment.
"""
import datetime

# How long an identified row lives. Long enough that a late or re-sending member still
# lands in the right window and that a human can look into something the week it
# happened. Short enough that the store is not a history of who was attacked.
IDENTIFIED_DAYS = 30


def expires_at(now=None, days=IDENTIFIED_DAYS):
    """When a row carrying a member id should stop existing."""
    at = now or datetime.datetime.now(datetime.timezone.utc)
    return at + datetime.timedelta(days=days)


def aggregate_key(entry):
    """The cell an entry belongs to, with no member id in it.

    This is what survives. It answers what the research asks, how often a pattern was
    seen and by how many organizations, and cannot answer which organizations, because
    the identity is not in the key and the rows holding it expire.
    """
    return "|".join(str(entry[f]) for f in
                    ("pattern", "action", "hour", "source", "rules_version"))


def describe(days=IDENTIFIED_DAYS):
    """What to tell a member, in the words they will read before agreeing."""
    return ("Reports carrying your member id are deleted after %d days. The counts they "
            "contributed to are kept, and carry no member id. You can delete everything "
            "about you at any time." % days)
