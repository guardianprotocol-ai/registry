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
