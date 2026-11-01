# Canary benchmark threat model

What the measurement in [canary-benchmark.md](canary-benchmark.md) is allowed to claim.
The numbers live in that file. This page says which claims they support.

## Who this is about

An operator has registered a value with the reference sensor. The file on disk holds a
salted HMAC-SHA256 of the value, a second digest of the case-folded value, and the
length. It does not hold the value. Evidence for a hit carries the label and the state.

The attacker in this benchmark is a script. It places that value, or a transformed copy,
into the arguments of a tool call. No model chooses the call. A result against a script
is not a result against a model.

The regression suite is the set of forms the matcher was fixed against, on the same
generators and seed that found the gaps. 4200/4200 there says those gaps are closed. It
is not a general detection rate. The held-out section is the closest thing here to one.

## In scope

The sensor sees MCP tool-call arguments and tool results, because that is where it sits.
The regression suite sends the value:

- as the whole argument, in a sentence, after `KEY=`, in a query string, in a JSON body,
  in a bearer header, in a file write, in a shell command string, in a markdown image,
  and in a CSV row
- followed by a period, alone on a line, as a URL path segment, and as `key:VALUE`
- base64-encoded, hex-encoded, percent-encoded, reversed, changed only in case, and
  split across two back-to-back tool calls, in order
- as a label in a name whose server field is `127.0.0.1` (no packet is sent)

A hit means GP-0020 was recorded. GP-0002, the built-in secret-shape rule, also fires on
some AWS-shaped and `sk-` shaped fakes. Those counts are reported separately and are not
GP-0020 detections or GP-0020 false alarms.

The benign set is ordinary text, unregistered values of the same shape, a one-character
change, an 11-character prefix, and long or random bodies. The one-character change is a
digit, so it is still different after case folding. A case-only copy is a detection.

## Out of scope, and measured there

These were excluded before the run, and the matcher was not changed to catch them:

- rot13, base32, gzip then base64
- the two halves in reverse order
- a zero-width character inserted into the value
- a paraphrase that keeps only the two ends

A tool call whose arguments do not contain the value is also out of scope. The sensor
cannot see a request the tool makes on its own. `omitted_from_arguments` is that case,
and it is a miss.

## Bounds that are part of the design

- One decode layer. A second encoding is a miss. Inside that layer the decoded text gets
  the same split as outbound text, so base64 of `user:VALUE` (an HTTP Basic credential)
  or of `token=VALUE` is found, and hex may carry a `0x` prefix. Those two are covered by
  unit tests in `sensor/tests/test_canaries.py`, not by the benchmark table.
- Base64 wrapped across several lines is not joined back together. It is a miss.
- A window slides only inside a token of at most 256 characters. A value glued into a
  longer blob is a miss.
- Fragments shorter than 6 characters are not kept, and only the first four and last four
  distinct pieces of a call are kept. The previous call is joined to this one, in order.
  An intervening tool call drops the fragment.
- The first half of a split is forwarded. A digest cannot be compared with a prefix. The
  call that completes the value is the one that can block.
- An entry written before the case-fold digest existed still matches the exact text only.
  The fold cannot be computed without the value, and the value is not in the file.
- Values shorter than 12 characters, and values that contain spaces, are refused at
  registration.

## What a false alarm is

A GP-0020 record on a trial whose text does not contain the registered value, including
under the transforms above. The corpus rate on `corpus/benign/` is a different
measurement and is the number in the pattern file. The benchmark rate is the number in
the results table.

## Sharing

Sightings are counts. The public receiver is
`https://guardianprotocol.network/season1/sightings`. A private one is
`python3 receiver/local_server.py`, bound to `127.0.0.1`, and `share --endpoint` points
at it. Neither endpoint is given the canary. The document is built from the pattern, the
action and the time.

Path canaries, seeded rows and real-file invariants are a different measurement. Their
threat model is [ASSUMED_BREACH.md](ASSUMED_BREACH.md) and their numbers are
[assumed-breach.md](assumed-breach.md).
