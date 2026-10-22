# Guardian Protocol exercise agenda, version 1

Status: draft.

An agenda says **when** a participant's sensor should run a local exercise. It never says
what to run. This document exists mainly to make that boundary explicit, because the obvious
alternative is a command channel and the difference between the two is the difference between
a protocol and a botnet.

## The problem it solves

Coordinating many participants to act in the same hour does not work, and the natural fix is
worse than the problem. A channel that lets an operator invoke actions on participants'
machines would be the most attractive target in the system, and it would have to be removed
before production, so whatever it proved would not be what shipped.

So participants poll. The action is fixed in the installed code. A published agenda carries a
time.

| push | pull |
| --- | --- |
| a central command | a published agenda |
| says what to do | says when |
| inbound channel | outbound fetch only |
| cannot ship | identical in production |

## Document

A JSON object at `<base>/agenda.json`, served over HTTPS.

| Field | Type | Required | Value |
| --- | --- | --- | --- |
| `exercise_id` | string | yes | at most 64 characters, letters, digits, hyphens, underscores |
| `run_after` | string | yes | `YYYY-MM-DDTHH:MM:SSZ`, UTC |
| `respond` | boolean | no | whether to run the response half as well. Default false |
| `note` | string | no | at most 200 characters, shown to the operator |

**An implementation must refuse a document carrying any other field**, rather than ignoring
it. Ignoring an unknown key means a later version that understands it would obey something an
earlier one silently dropped, and the whole guarantee here is about what the document cannot
say.

`exercise_id` names a file on disk, so it may not be a path and may not contain separators or
whitespace.

## Behaviour

An implementation polls at an interval its operator chooses, and:

- runs nothing before `run_after`
- runs an exercise at most once, identified by `exercise_id`, however often it is polled
- treats a missing or unreachable agenda as the ordinary case and stays quiet about it
- records every run, refusal and failure locally
- shares nothing. Building and sending a report stays a separate, deliberate act

The at-most-once requirement is not a nicety. Without it an hourly poll repeats the same
exercise every hour forever, and a participant's sightings fill with one drill.

## What an attacker gains by compromising the publishing point

They can make a participant's machine run an exercise that participant already installed and
consented to, against a lab server on their own machine, which shares nothing. That is the
entire blast radius, and it is why this is a static file rather than a service.

They cannot cause any other action, because no other action is expressible.

## Not in this version

No signature. The agenda is fetched over HTTPS and its shape is checked, which means a
participant trusts the host and the transport. Since the worst a hostile agenda can do is
schedule a consented local exercise, this is a smaller gap than it would be for rule
distribution, which does carry a hash manifest. A signature is expected in a later version.

No way to cancel a scheduled exercise once a participant has run it. Publish a new
`exercise_id` instead.
