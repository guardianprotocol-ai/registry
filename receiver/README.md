# The sightings receiver

A receiver accepts sightings documents and stores them. This folder holds the HTTP
contract, which is the protocol, and one implementation of it, which is not.

The distinction matters. Distribution is static JSON on a CDN and any number of people can
mirror it. Collection needs something that accepts a POST, and if that something is only
ever our server then the exchange has a single owner. So the contract is written down here
and `main.py` is one deployment of it. An organization that wants to run its own receiver
implements this document, points its members at their own endpoint, and owes us nothing.

## The contract

```
POST <endpoint>
Content-Type: application/json
```

The body is a sightings document as described in `spec/sightings-0.2.md`: exactly the
fields `schema_version`, `org` and `sightings`, where each entry carries exactly the eight
allow-listed fields and nothing else.

| Response | Meaning |
| --- | --- |
| `200` `{"accepted": n, "stored": n}` | Every entry was stored |
| `400` `{"error": "..."}` | The document was refused, and `error` says why |
| `405` | Something other than POST |
| `413` | The body is larger than 256 KB |
| `503` | The receiver could not store it. The sender keeps its evidence and retries |

Three requirements on any implementation.

**Refuse, do not filter.** A receiver that quietly drops an unrecognised field stores the
part it understood and leaves the sender believing the whole document was agreed to. A
document is accepted entirely or refused entirely, and a refusal says what was wrong in
words the sender can act on.

**Be idempotent.** Senders re-send. A member who was offline for a week sends their whole
history on the next poll, and a member who is unsure the last attempt landed sends it
again. Store each sighting under an identity built from all eight fields except `count`,
and let a repeat overwrite rather than add. Counting re-sends would inflate the only
numbers the research reports, and it would inflate them most for the members with the
worst connections.

**Never answer with instructions.** A receiver replies with a count and, when it refuses, a
reason. It does not return rules, settings or advice. Everything a sensor acts on is pulled
from a published agenda that a person wrote, so that a compromised or hostile receiver can
drop data but can never tell a member's machine what to do.

## What a receiver must not do

Publish automatically. This endpoint is the inbound half only. Turning sightings into
alerts other machines will read is a separate step, run deliberately by a person, because
anything published becomes something other people's agents act on.

## Threat model for Season 1

The endpoint is unauthenticated. Anyone who finds the URL can file sightings under an
invented member id. That is a known and accepted position for a first trial, for one
reason: requiring a credential before somebody can take part is the surest way to have
nobody take part, and the data being collected is counts.

What stops it mattering:

- Nothing is published automatically. A person reviews the aggregate before any alert goes
  out, so invented sightings cannot become advice another member's agent acts on.
- The k-threshold needs several distinct organizations before a pattern is reported at all.
- An entry may only name the member the document names, so one sender cannot reach the
  threshold alone by filing under several names.
- Body size and entry count are capped, so a sender cannot make a receiver hold an
  unbounded amount of anything.

What this does not stop: somebody running several senders with different member ids. The
answer to that is proof of possession at enrolment, which is a Season 2 problem and should
be solved when there is something worth attacking.

## Running the tests

```
cd receiver && python3 tests/test_validate.py
```

`validate.py` is standard library only and has no cloud dependency, so the part that
decides what is acceptable runs anywhere. `main.py` is the only file that knows about
Google Cloud.

## This deployment

Cloud Run, in the Firebase project `guardian-protocol-site`, reached through a Hosting
rewrite so the address stays on the protocol's own domain:

```
https://guardianprotocol.network/season1/sightings
```

Operated by Guardian Protocol. Members are told that in the consent text before they agree
to anything, and the address they agreed to is recorded on their own disk.
