# Guardian sensor v0 (prototype)

An MCP proxy that sits between an agent and any MCP server, relays every message, and blocks known attack patterns from the registry. Built for anything that speaks MCP over stdio: Claude Code, Codex, Cursor, and agents built on open models. Tested end to end with a simulated MCP client and server, and inside a real Claude Code session as a proxy in front of both a test server and the filesystem server. Other clients are next.

**Prototype. Not for production data yet.** No dependencies beyond Python 3.9+.

## What it catches today

| Pattern | What the sensor does |
| --- | --- |
| GP-0001 Hidden instructions in a tool's output | Notes when a tool result carries instructions for the agent, then blocks any following send to a destination outside your allow-list |
| GP-0002 Sensitive data sent out through a tool call | Blocks tool calls whose arguments contain canary tokens or secrets (API keys, private keys, tokens) |
| GP-0003 Tampered MCP tool | Pins every tool definition the first time it's seen; blocks a tool whose definition later changes; flags descriptions that contain instructions |

The shared rule engine (`guardian_sensor/rules.py`) also has draft checks for GP-0004 to GP-0012 (memory writes, destructive actions, hidden content, credential file reads, agent-to-agent messages, writes to agent config files, source steering, runaway repetition, system prompt leaks). Those checks are covered by `tests/test_rules.py`, and each has a pattern file in `patterns/`. They stay draft until the scan has measured them against the reference agents.

Every block or flag is written to `.guardian/evidence.jsonl`. If the sensor itself hits an error, it relays the message unchanged (fails open) and logs the fault.

## Use it

Wrap any MCP server command:

```bash
python3 /path/to/sensor/run.py --config guardian.json -- <your MCP server command>
```

For example, in Claude Code:

```bash
claude mcp add files-guarded -- python3 /path/to/sensor/run.py --config /path/to/guardian.json -- npx -y @modelcontextprotocol/server-filesystem /path/to/dir
```

Copy `guardian.example.json` to `guardian.json` and list the domains your agents may send data to. Set `"mode": "monitor"` to log without blocking.

## Watch for your own secrets

Every other detection here is a pattern somebody wrote down in advance, which is what an
adaptive attacker reads and routes around. A canary is different in kind. It does not
describe an attack. It fires because a specific value moved, whatever moved it.

The sensor already watches for its own test tokens. These are yours.

```bash
python3 -m guardian_sensor canary add --label "staging payment key"
```

The value is read from a prompt, or piped in, and never passed as an argument, because an
argument lands in shell history and in the process table. Only a salted digest is stored, so
the file listing what the sensor watches for is not itself a secret store.

```bash
python3 -m guardian_sensor canary list
python3 -m guardian_sensor canary arm --label "staging payment key"
python3 -m guardian_sensor canary remove --label "staging payment key"
```

**A canary starts in baseline and reports without blocking, whatever the mode.** Backups,
indexers and data loss scanners legitimately touch things nobody should touch, and the first
thing an operator learns from a badly placed canary should not be that their agent stopped
working. Watch it through a few days of ordinary work. If it never fires, arm it. If it does
fire, move the canary rather than raising the threshold.

What a hit reports is the label and the state. Never the value, not in the evidence, not in
a log line, not in an error.

Where to place one: a credential nothing legitimate uses, a file nothing should read, a row
no query should return.

### What this does not cover

Worth being exact, because the obvious overclaim is easy to make.

**This fires when an agent passes a registered value into a tool call.** It is checked on
outbound arguments, before the call is forwarded, because after that the value has gone.

So it does not detect a platform being breached. In the Railway disclosure of October 2026
an intruder read customer environment variables directly, with no agent involved anywhere,
and nothing here would have fired. What it would catch is the next step: an agent that has
been handed one of those credentials passing it onward.

A refusal does not say which rule fired. That is deliberate and it costs something: a
developer whose legitimate work is blocked has to read the evidence log to learn why, rather
than being told in the response. The reason is that an attacker holding a set of stolen
credentials can send them one at a time and read the answers, and if a canary match looks
different from any other refusal they learn which key is the fake one and take the rest. So
every refusal is identical, and the full reason is recorded locally where only the operator
sees it.

It is also not checked on tool output. A canary coming back from a file read means the agent
now holds the value, which is a different event from the agent sending it, and recording
both under one pattern would make the evidence ambiguous about which happened.

Matching is on whole tokens, so a value spliced into a longer run of characters or re-encoded
on the way out is not found: this catches a credential being passed on, not one being
smuggled. Matching is case sensitive, as credentials are. Values shorter than twelve
characters, and values containing spaces, are refused rather than silently never matched.

## Fire drill

The fastest way to see the sensor work, and the way to join the exchange without waiting to
be attacked.

```bash
python3 -m guardian_sensor drill --org <your-member-id>
```

A lab server runs locally and attacks you: a tool whose definition changes after you
approved it, a tool that appears after approval, and a tool result carrying a canary that
tries to leave. The sensor in front is yours, with your config, and every detection is real.
It takes about a second.

```
GP-0003   a tool definition changes after the operator approved it       caught
GP-0019   a tool appears on the server after approval                    caught
GP-0002   a canary read from a local file tries to leave in a tool call  caught

3 of 3 exercises caught in 0.3 seconds.
```

An exercise that does not fire prints `MISSED`, the command exits non-zero and the sensor's
own log is printed underneath. A drill that reports a clean run while the sensor is broken
would manufacture confidence, which is worse than having no drill.

Nothing is shared. The drill writes to `.guardian/drill` and refuses to run in a directory
holding a real `evidence.jsonl` or `pins.json`, because overwriting pins would reset your
approval baseline and the next listing would re-approve whatever the server offered.

Afterwards, to see what a sighting would look like and share nothing:

```bash
python3 -m guardian_sensor report --org <your-member-id> \
  --evidence .guardian/drill/evidence.jsonl --preview
```

Drill detections are marked `source: drill` in every sighting, so nobody downstream can
count an exercise you ran on yourself as a real incident. See decision 21.

Pick a member id that is not your company name. It is a pseudonym and it is the only
identifier that travels with your sightings.

### The response half

```bash
python3 -m guardian_sensor drill --org <your-member-id> --respond
```

Runs the same attack twice, with a rule update in between.

```
  before the update   GP-0001  got through
  after the update    GP-0001  blocked

The attack got through, a rule arrived, and the same attack was stopped. 0.2 seconds
on one machine, with no human in the loop.
```

The attack is a phrasing that no signature caught until one was written for it, so the
first run is a sensor that genuinely does not know the attack rather than one weakened to
look that way. The difference is in whether the send was blocked, not in whether it was
annotated.

The number is the adoption step only, with the rule already in hand. It leaves out somebody
else seeing the attack first and the report reaching you, which is what the exchange is for
and what is still unmeasured. The command says so itself rather than leaving it to a reader.

## Taking part without reaching out to anything

The control arm, and the way to take part from a machine that cannot reach an external URL.

```bash
python3 -m guardian_sensor enroll --offline --org <your-member-id>
```

Fetches nothing, listens to nothing, shares nothing. It runs the exercise locally on its own
cadence and records what the sensor caught. There is no url anywhere in the installed
service.

This exists for two reasons. It is the baseline the network claim is measured against: the
argument is that value grows as more organizations take part, and that cannot be argued
without knowing what a sensor is worth alone. And it includes anybody behind an egress proxy
that will not reach a published agenda, who was previously excluded by a design decision
nobody made on purpose.

Both arms can run on the same machine one after the other, which is how the difference
between them gets measured per participant rather than across participants.

## Taking part in a scheduled exercise

Install once, leave it running, and the exercise happens without you being available for it.

```bash
python3 -m guardian_sensor agenda --base https://guardianprotocol.network/season1 --org <your-member-id>
```

Safe to run hourly from cron or launchd. It fetches a published agenda, runs the local drill
once when its time has come, and does nothing the rest of the time. A missing agenda is the
ordinary case between exercises and is quiet on purpose.

```
0 * * * * cd ~/guardian && python3 -m guardian_sensor agenda \
            --base https://guardianprotocol.network/season1 --org <your-member-id>
```

An agenda can also say which permutation to run, which is what makes a controlled experiment
possible without anyone being available for it:

```json
{"exercise_id": "season1-p3",
 "run_after": "2026-10-27T14:00:00Z",
 "settings": {"mode": "block", "respond": true},
 "note": "Season 1, arm 3."}
```

`mode` is `block` or `monitor`. `respond` runs the same attack before and after a rule
update. `protected` set to false is the control arm, with no sensor in front, where every
exercise is expected to get through and that is the result. The permutation is printed on
every run and recorded beside it.

**The agenda says when and which arm, never what.** The action is fixed in the installed code and is the
same local drill you can run by hand. A document carrying any other field, or a setting the sensor does not offer, is
refused rather than ignored. The values are a fixed list you can read in
`guardian_sensor/agenda.py`, so what can happen on your machine is settled when you install
it, not when somebody publishes a file. So the worst anyone could do by taking over the publishing point is make your
machine run an exercise you already installed, against a lab server on your own machine, which
shares nothing.

That boundary is the reason this is a static file instead of a service, and it is specified
in `spec/agenda-1.md`. A channel that could invoke arbitrary actions on participants'
machines would be a botnet whoever was running it, and it would have to be removed before
production, so whatever it proved would not be what shipped.

If your machine keeps your home directory locked down, which is normal on a managed laptop,
say where to keep records instead:

```bash
GUARDIAN_HOME=/path/you/can/write python3 -m guardian_sensor enroll \
  --base https://guardianprotocol.network/season1 --org <your-member-id>
```

Nothing is shared by this. Building and sending a report stays a separate, deliberate act.

## Sharing hub, reference implementation

`python3 -m guardian_sensor report --preview` and `python3 -m guardian_sensor update` are the
reference implementation of the sharing hub, used in the Season 2 distributed experiments.
Nothing in Season 1 depends on them: a sightings file is built from an allow-list of eight
fields and leaves your machine only if you share it. See `ARCHITECTURE.md` for what v0 does
and does not do.

## Test it

```bash
python3 tests/test_sensor.py
python3 tests/test_rules.py
python3 tests/test_pinning.py
python3 tests/test_drill.py
```

`test_rules.py` covers the draft rules GP-0004 to GP-0012 directly, each with an attack that must be caught and ordinary work that must not be. The benign half is the point: a rule that blocks real work gets turned off, and a rule that is turned off protects nobody.

`test_sensor.py` runs the same attack twice through a fake MCP server: without the sensor the canary leaks; with it, the exfiltration and the tampered tool are both blocked, a legitimate send to an allowed domain goes through, and evidence is recorded.

## What it costs to run

No model, so no tokens and no per-call charge on any plan or any vendor. The checkpoint is
regex and rule evaluation over text, and the only cost is latency.

Measured on macOS 26.4.1, Python 3.13, 2026-10-09, with the sensor in front of a stdio echo
server, 200 messages:

| | |
| --- | --- |
| Straight to the server | 0.164 ms per message |
| Through the sensor | 0.454 ms per message |
| **Added by the sensor** | **0.290 ms per message** |

The proxy is long lived, so it pays process startup once rather than per call.

Scanning cost is linear in the size of the text, about **365 ms per megabyte**, so a few
hundred bytes of tool output costs a fraction of a millisecond and a 200 KB page costs
roughly 73 ms. Numbers on another machine will differ; the shape will not.

## Known limits (v0)

- It sees only tools that come from MCP servers. An agent's built-in tools (for example Claude Code's own shell, file and web tools) don't pass through MCP; covering those needs the client's hook system, which is next on the list.

- Heuristic instruction detection; attackers can rephrase. Behavior checks (unrequested actions, new destinations) are the stronger signal and grow with each release.
- stdio transport only; HTTP transport and gateway plugins come next.
- Taint lasts for the whole session.
