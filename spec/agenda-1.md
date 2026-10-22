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
| `settings` | object | no | the permutation to run, from the fixed space below |
| `respond` | boolean | no | kept for agendas written before `settings`. May not contradict it |
| `note` | string | no | at most 200 characters, shown to the operator |

## Settings

This is what makes a controlled experiment possible. An operator may schedule as many
permutations as a study needs, in any order, without any participant being available for
them.

| Setting | Values | What it selects |
| --- | --- | --- |
| `mode` | `block`, `monitor` | whether the sensor blocks or only records |
| `respond` | `true`, `false` | whether the same attack runs before and after a rule update |
| `protected` | `true`, `false` | whether the sensor is in front at all. The control arm |

Every value selects among behaviour the participant installed. **An implementation must
refuse a setting it does not offer, and a known setting with a value outside its list.** A
setting that is silently dropped is a permutation the operator believes they ran and did not,
which is worse for a study than a refusal.

The space is deliberately small. Adding to it is a deliberate act with a test, because each
addition widens what an agenda can cause on somebody else's machine. A setting that took a
path, a URL, a command or free text would stop being a selection and start being an
instruction, and this document exists to keep that line visible.

An implementation must print the permutation it is running and record it alongside the run, so
a participant can see what was asked of their machine without reading the implementation's
source, and an operator can see which arm a machine took without correlating logs.

**An implementation must refuse a document carrying any other field**, rather than ignoring
it. Ignoring an unknown key means a later version that understands it would obey something an
earlier one silently dropped, and the whole guarantee here is about what the document cannot
say.

`exercise_id` names a file on disk, so it may not be a path and may not contain separators or
whitespace.

## Reaching some participants and not others

There is no addressing in an agenda and there is deliberately no participant list anywhere.
A document that named who should run what would need to know who the participants are, and
the whole format is built so that nobody has to.

Cohorts are done with separate agendas instead. An operator publishes more than one, at
different paths, and each participant is told at install time which one to poll.

```
<base>/cohort-a/agenda.json     block mode
<base>/cohort-b/agenda.json     monitor mode
```

So a split test is two files, and a participant can read the agenda they are polling and see
exactly what their machine will be asked to do. Neither property survives a design where one
document addresses many machines.

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
