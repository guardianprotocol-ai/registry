# Client hooks

The MCP sensor sits between an agent and its MCP servers, so it sees every MCP tool call.
It does not see a client's **own** tools. A client's shell, its file reads and writes, its web
fetches and its subagents never pass through MCP, and that is where most of an agent's
actual work happens.

**That gap is in every client, not one.** Closing it needs something running inside the
client, which means one small integration per client, each using the same rule engine in
[`sensor/guardian_sensor/rules.py`](../sensor/guardian_sensor/rules.py). The rules are the
protocol. A hook is just a way of getting them into a place the sensor cannot reach.

## What ships today

| Client | Where | State |
| --- | --- | --- |
| Claude Code | [`claude_code/`](claude_code/) | Prototype, tested against recorded payloads and live sessions |

One, because it is the client this was written on. It is a reference implementation, not the
way to use the protocol, and the sensor alone needs no hook at all and works with any MCP
client.

## Wanted

A hook for any client with a mechanism to inspect its own tool calls. Each one is small,
because the detection logic already exists and is shared:

- Gemini CLI
- Cursor
- Codex CLI
- VS Code extensions that expose tool events
- Anything else with a pre-tool or post-tool extension point

**What a hook has to do**, and nothing more: read whatever the client hands it, pass the text
to the shared rule engine, and return the client's own allow or block shape. Read
[`claude_code/guardian_hook.py`](claude_code/guardian_hook.py) as the worked example. It is
one file, no dependencies beyond the standard library.

Two rules learned from the one that exists, both worth copying:

- **Fail open.** A fault in a hook must never stop the agent. Catch everything, say so on
  stderr, and allow the call. A security tool that breaks someone's editor gets uninstalled.
- **Never trust a session id as a path.** Hash it. It arrives from outside.

If your client has no extension point, the sensor still covers its MCP tools, and measuring
that client with the scanner is a separate and equally useful contribution. See
[TEST_YOUR_AGENT.md](../TEST_YOUR_AGENT.md).
