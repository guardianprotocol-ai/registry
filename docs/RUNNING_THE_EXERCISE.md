# Running the exercise

How an operator runs a scheduled exercise across many participants, and how a participant
takes part. Written for Season 1.

Nothing here needs a server. The operator publishes files and reads files. Every machine
acts on its own, which is why there is no channel into anybody's laptop.

## What a participant does, once

```bash
git clone https://github.com/guardianprotocol-ai/registry.git
cd registry/sensor
python3 -m guardian_sensor setup
```

That runs the drill by hand and proves it works. Then one command to take part:

```bash
python3 -m guardian_sensor enroll \
  --base https://guardianprotocol.network/season1 --org <your-member-id>
```

It prints the service it is about to install, writes it, starts it, and confirms it is
running. After that the participant does nothing, ever. The service polls every sixty
seconds, runs an exercise once when one is due, and shares nothing.

Add `--print-only` to see the service and install nothing. Stop at any time with `--remove`.

Everything it writes stays in `~/.guardian`, never in the repository, so updating the code
never touches a participant's records.

A member id is a pseudonym they choose. Never a company name.

### Being credited

Optional, and a separate file on purpose:

```bash
python3 -m guardian_sensor credit --name "Your Name" --github your-handle
```

The pseudonym goes into sightings, which are shared. The name goes here, and goes nowhere
until the participant sends it. One file would have been more convenient and would have
quietly undone the privacy argument the format rests on.

Authorship under `docs/RESEARCH.md` needs a substantive contribution, approval of the final
draft, and willingness to answer for your part. Somebody who ran an exercise may want none
of that, so `--acknowledge-only` asks to be thanked rather than listed. Being acknowledged
is not a lesser thing and assuming otherwise is how people end up as authors of papers they
never read.

## What the operator does, per exercise

### 1. Publish an agenda

A file, not a service. On the site, at `season1/agenda.json`:

```json
{"exercise_id": "season1-a1",
 "run_after": "2026-10-27T14:00:00Z",
 "settings": {"mode": "block", "respond": true},
 "note": "Season 1, arm 1. Nothing leaves your machine."}
```

Commit it. Within the hour, every participant's machine notices, runs that arm locally, and
records what happened. Nobody has to be awake.

### 2. Split the group, if the arm calls for it

Publish more than one agenda at different paths and tell each participant which to poll.
There is no addressing inside an agenda and no participant list anywhere, on purpose.

```
season1/cohort-a/agenda.json    {"settings": {"mode": "block"}}
season1/cohort-b/agenda.json    {"settings": {"mode": "monitor"}}
```

### 3. Ask for reports

Participants do this themselves, because nothing leaves a machine without its owner looking
at it first:

```bash
python3 -m guardian_sensor report --org <id> --evidence .guardian/drill/evidence.jsonl --preview
python3 -m guardian_sensor report --org <id> --evidence .guardian/drill/evidence.jsonl \
  --out sightings-2026-10-27.json
```

Then commit it to the private research repository, under
`trial/sightings/<member-id>/`.

### 4. Watch the exchange respond

```bash
python3 scripts/aggregate_sightings.py trial/sightings --source drill
```

```
pattern     orgs      total
GP-0003        4         12
GP-0019        4          4
GP-0001        2   withheld
```

A total appears once three independent organizations have contributed to it and is withheld
below that, with the reason given. `--source drill` keeps exercises apart from real traffic,
which must never be summed together.

## What gets measured

| Quantity | Where it comes from |
| --- | --- |
| How many participants are live | members reporting at all, including zero detections |
| False alarms on real work | days of ordinary work against flags raised |
| Detection, per arm | caught against got through, control arm against protected |
| Adoption time | `--respond`, the same attack before and after a rule update |
| Time to protection | first sighting to the threshold clearing, across machines |
| Participation | how many of the invited actually ran it |

The last one is a finding whether the number is high or low, and should be reported either
way.

## What this does not measure

The attacks are ours. Every detection in an exercise is marked `source: drill` and must never
be counted as an incident. The exercise proves the reporting path works end to end across
organizations. It says nothing about what real attack traffic looks like, and the paper has
to say so plainly rather than let a reader assume otherwise.

## Why there is no command channel

An operator cannot invoke anything on a participant's machine. An agenda carries a time and a
choice between arms the participant installed, and a document carrying anything else is
refused rather than ignored.

That is not caution for its own sake. A channel that could invoke actions on twenty
developer machines would be the most attractive target in the whole system, and it would have
to be removed before production, so whatever it proved would not be what shipped. Compromising
the publishing point as built buys an attacker one local exercise that the participant already
installed and consented to.

See `spec/agenda-1.md` for the format and `docs/DECISIONS.md` row 24 for the reasoning.
