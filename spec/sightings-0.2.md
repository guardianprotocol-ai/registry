# Guardian Protocol sightings format, version 0.2

Status: draft. Stable enough to implement against, not yet ratified by the working group.

A sighting is what one organization's sensor saw, expressed as counts with no content in
them. This document defines the format so that a second implementation can be written
without reading the first one. `sensor/guardian_sensor/hub.py` is an implementation of this
specification, not the definition of it, and `spec/sightings-0.2.schema.json` checks
conformance mechanically.

The key words must, must not, should and may are used as in RFC 2119.

## Why the format is shaped this way

Three constraints drove every decision below, and they are in tension.

A member has to be able to read the whole of what leaves before it leaves. That rules out
anything a human cannot check in a few seconds, which rules out free text.

A report must not identify its reporter, directly or by accumulation over time. That rules
out anything an attacker could correlate, including fine-grained timestamps.

A reader must be able to tell a real incident from an exercise, and a corroborated signal
from a single claim. That requires provenance to travel with every entry.

The format is therefore an allow-list rather than a redaction. Output is built from a fixed
field list; it is never a record with sensitive fields removed. A redactor is a filter and
an allow-list is a wall, and the difference shows up the first time somebody adds a field
upstream.

## Document

A sightings document is a JSON object.

| Field | Type | Required | Value |
| --- | --- | --- | --- |
| `schema_version` | string | yes | `"0.2"`. Readers must also accept `"0.1"` |
| `org` | string | yes | the member id, matching every entry's `org` |
| `sightings` | array of entry | yes | may be empty |

A document must contain no other members. A reader that finds one must reject the document
rather than ignore the extra member, because a field a reader does not understand may be
carrying content the member never agreed to share.

## Entry

Every entry must have exactly these eight fields, and no others.

| Field | Type | Value |
| --- | --- | --- |
| `org` | string | `^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$` |
| `sensor_version` | string | `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$` |
| `rules_version` | string | `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` |
| `pattern` | string | `^GP-\d{4}$` |
| `action` | string | `flagged` or `blocked` |
| `hour` | string | `^\d{4}-\d{2}-\d{2}T\d{2}$`, UTC |
| `count` | integer | 1 or greater |
| `source` | string | `live` or `drill` |

### org

A pseudonym the member chooses. It must not be a company name, a domain, or anything else
that identifies the organization, and implementations should say so at the point where it is
set rather than only in documentation.

The shape is constrained because the member supplies this value and it travels with every
entry. Without a shape, anything typed here rides out unchecked and the guarantee above
stops being true.

### sensor_version and rules_version

Which implementation produced the entry and which rule set it was running. Both are
constrained for the same reason as `org`: a caller or a release manifest supplies them, so
without a shape they are a free text channel.

`rules_version` is required and must not be a placeholder. An entry whose rule set is unknown
cannot be compared with any other entry, which makes it noise in an aggregate.

### pattern

The registry identifier of the pattern that fired. Four digits, zero padded. A reader that
does not recognise the identifier must keep the entry and count it, because a member running
a newer rule set than the reader is expected rather than exceptional.

### action

What the sensor did. `blocked` means the action was stopped. `flagged` means it was recorded
and allowed, which is what monitor mode does.

These are not severities and must not be read as such. A member running in monitor mode
reports `flagged` for something another member would have `blocked`, so the field describes
the configuration as much as the event.

### hour

The UTC hour the detections fell in, truncated. Minutes, seconds and timezone must not
appear.

An hour is coarse on purpose. A precise timestamp is close to a unique identifier once an
observer holds a few of them, and the point of the format is that it cannot be correlated
back to its reporter.

### count

How many detections of that pattern, action, hour and source. Counting is how the format
avoids carrying events: one entry stands for any number of detections and carries nothing
about any of them.

### source

Where the detection came from.

- `live` means ordinary traffic.
- `drill` means a fire drill, where the member attacked their own machine on purpose.

Drill detections are real detections and they are not incidents. Without this field the two
are indistinguishable once aggregated, and anyone reporting exercises as observed incidents
would be overclaiming whether or not they meant to.

An implementation must set `source` at the moment of detection, not infer it later. The
component that performs the detection is the only one that knows for certain.

A reader processing a `0.1` document, where the field does not exist, must treat a missing
`source` as `live`. This is safe only because a drill marks its own records, so the sole way
to be unmarked is to be a record no drill produced.

## What must never appear

No tool names. No arguments. No URLs. No file paths. No message bodies. No hostnames. No
usernames. No timestamps finer than the hour. No free text of any kind.

These are not removed from the output. A conforming implementation never reads them, which
is a stronger statement and an easier one to verify: the test is whether the producing code
ever touches the fields that hold them.

## Aggregation

An aggregate combines documents from several members. It is defined here because the privacy
guarantee depends on it as much as on the entry format.

An aggregate must withhold any total that fewer than three distinct `org` values contributed
to, and must say that it withheld it rather than omitting the row. A row that vanishes is
indistinguishable from a pattern nobody saw.

Three is a floor, not a target. It is the smallest number at which a total cannot be
attributed to a single member by subtraction, and it is a parameter rather than a constant
because a larger network may want more.

An aggregate must not mix `live` and `drill` in one total. It must either filter to one or
state that it combined them.

An aggregate must reject an entry carrying a field not listed above, rather than aggregating
it. It must accept an entry missing only fields introduced after the version it was written
for, using the defaults given here, because refusing those makes every future field a
breaking change to files other organizations have already written to disk.

## Versioning

`0.2` adds `source` to `0.1`. The change is additive and a `0.1` document remains valid.

The version was raised anyway, because a reader needs to distinguish a missing `source` that
means `live` from a missing `source` that means the producer predates the field. Those are
the same bytes and different facts.

A future version may add fields. It must not change the meaning of an existing field, and it
must not remove one. A field whose meaning needs to change gets a new name.

## Conformance

An implementation conforms if, for every document it produces:

1. Every entry has exactly the eight fields, in any order.
2. Every value matches the shape given for its field.
3. No value is derived from a field in this document's "what must never appear" list.
4. `source` is set by the detecting component.
5. The member can see the whole document before it is written or sent.

Point five is a requirement on the implementation, not on the file. A format that is private
in principle and shared without review in practice is not private.

## Open questions

Listed because an implementer will hit them and should not have to guess.

The three organization floor assumes corroboration is the only basis for trust. A report
whose evidence is proof of possession of a secret only its owner knew could justify a lower
floor, which would change the privacy analysis as well as the latency. This is under
discussion as registry issue 156 and is not part of this version.

There is no signing. Integrity today rests on transport and on a hash manifest for rule
distribution, which catches a corrupted download but not a hostile publisher. A future
version is expected to carry a signature, and implementers should not treat a sightings
document as authenticated.

There is no transport. This version defines a file. How a file reaches an aggregator is out
of scope and currently a commit to a shared repository.
