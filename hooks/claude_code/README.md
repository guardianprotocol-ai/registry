# Claude Code hook (prototype)

The MCP sensor only sees tools that come from MCP servers. A client's own tools, its shell, file reads and writes and web fetches, never pass through MCP. This hook closes that gap by running the same rule engine (`sensor/guardian_sensor/rules.py`) inside Claude Code.

**Prototype. Not for production data yet.** No dependencies beyond Python 3.9+.

This is one client's integration, not the way to use the protocol. The gap it closes exists in every client, and [../README.md](../README.md) says what a hook for another one has to do. The sensor on its own needs no hook and works with any MCP client.

## What it does

| Event | What it checks |
| --- | --- |
| `PreToolUse` | `rules.check_call` on the tool and its arguments. In block mode a hit returns a `deny` decision and the call never runs. In monitor mode it is recorded and allowed |
| `PostToolUse` | `rules.check_output` on whatever the tool returned. Flags hidden content (GP-0006) and source steering (GP-0010), and marks the session tainted when a tool result carried instructions |

Every hook run is a separate process, so session state, which tool tainted the session and how often each call has been seen, is kept in one file per session id under `state_dir`. Taint is scoped to its session and does not leak between them.

Blocks and flags are appended to `evidence_path`, the same format the sensor writes.

Fails open. Any fault in the hook, a malformed payload, an unreadable config, leaves the tool call alone and exits 0.

## Install

Copy `guardian.example.json` next to your settings, list the domains your agent may send data to, then add both hooks to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{ "matcher": "*", "hooks": [{ "type": "command",
      "command": "python3 /path/to/hooks/claude_code/guardian_hook.py --config /path/to/guardian.json" }] }],
    "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command",
      "command": "python3 /path/to/hooks/claude_code/guardian_hook.py --config /path/to/guardian.json" }] }]
  }
}
```

Set `"mode": "monitor"` to record without blocking. Run it that way first.

## Test it

```bash
python3 hooks/claude_code/tests/test_hook.py
```

The suite drives the hook the way the client does, a payload on stdin and JSON on stdout. `tests/payloads/` holds payloads recorded from a real Claude Code session, each with the decision it must produce. Recording rather than inventing them matters: the response shape differs per tool, and none of them match what you would guess. `Bash` returns `{"stdout", "stderr"}`, `Read` nests the text under `file.content`, `Write` puts it at the top level, `WebFetch` returns `result`. The hook walks the structure and keeps the strings rather than naming each shape.

## Tested

Unit tested against recorded payloads, and run live inside a headless Claude Code 2.1.274 session on macOS with both hooks installed:

- ordinary work is untouched, with no false positives
- a `Write` carrying a canary token is denied (GP-0002) and the file is not created
- reading a file whose text carries instructions taints the session, and a later `WebFetch` to a domain outside the allow-list is denied (GP-0001), which confirms taint survives between hook processes

Not tested: Windows, other clients, long sessions, and concurrent tool calls writing state at the same time.

## What it costs to run

No model, so no tokens and no per-call charge. The cost is latency, and for the hook it is
dominated by something other than the checking.

Measured on macOS 26.4.1, Python 3.13, 2026-10-09:

| Payload | Added per tool call |
| --- | --- |
| Two bytes, so startup only | 52.1 ms |
| 4 KB file read | 53.4 ms |
| 200 KB web page | 128.8 ms |

A hook is a separate process per tool call, so **about 52 ms of that is Python interpreter
startup rather than inspection**: a 4 KB read spends 1.4 ms being checked and 52 ms starting
up. Scanning itself is linear, roughly 365 ms per megabyte.

For comparison, `sensor/README.md` records the proxy at 0.290 ms per message, because it
starts once and stays running. The same rule engine runs in both.

## Known limits (v0)

- Taint lasts for the rest of the session. A session that reads untrusted content and then makes a legitimate request to a domain outside the allow-list is blocked. Benign cases that must not be blocked are still to be written.
- The `GP-0001` wording says "unrequested send", but the check is taint followed by egress and does not know whether the user asked for it.
- State files are written without locking, so parallel tool calls in one session can lose an update.
- Rules are heuristic. Behavior checks are the stronger signal and grow with each release.
