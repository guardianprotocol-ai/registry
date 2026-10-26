"""Where MCP clients keep their servers, so the sensor can be put in front of them.

Wiring the sensor in by hand means finding a config file, understanding its shape, and
editing JSON without breaking it, once per server, per client, per machine. People do
that once and not again, and a protocol that only protects the servers somebody
remembered to wrap protects nothing in particular.

So the clients are described here as data: where the file is, where servers live inside
it, and what this project is called when it appears in one. Adding a client is adding an
entry.

Nothing here edits anything. This finds and describes; `protect_cli` is what changes a
file, and only after showing what it would change.

Python 3.9+ standard library only.
"""
import json
import os

# A server entry is {"command": ..., "args": [...], "env": {...}}. Wrapped, the command
# becomes this sensor and the original command moves after a bare "--", which is also how
# a wrapped entry is recognised later.
SEPARATOR = "--"
RUN_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "run.py")


def _home(*parts):
    return os.path.join(os.path.expanduser("~"), *parts)


# name, where the config is, and how to reach the server tables inside it.
#
# "nested" means servers live under one key per project rather than at the top level,
# which is how Claude Code keeps them: a server added in one directory is not a server
# anywhere else, and wrapping the lot would reach into projects somebody did not ask
# about. So each is offered separately and named by its project.
CLIENTS = (
    {"name": "claude-code", "path": _home(".claude.json"),
     "nested": ("projects",), "key": "mcpServers",
     "note": "servers are per project, so each project is offered on its own"},
    {"name": "claude-desktop",
     "path": _home("Library", "Application Support", "Claude",
                   "claude_desktop_config.json"),
     "nested": (), "key": "mcpServers",
     "note": "one table for the whole app"},
    {"name": "cursor", "path": _home(".cursor", "mcp.json"),
     "nested": (), "key": "mcpServers", "note": ""},
    {"name": "windsurf", "path": _home(".codeium", "windsurf", "mcp_config.json"),
     "nested": (), "key": "mcpServers", "note": ""},
    {"name": "vscode", "path": _home(".config", "Code", "User", "mcp.json"),
     "nested": (), "key": "servers", "note": ""},
)


def read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def tables(document, client):
    """[(where, table)] for every server table in this document.

    `where` names it for a person: a project path, or the client itself when the client
    keeps one table.
    """
    if document is None:
        return []
    found = []
    if client["nested"]:
        node = document
        for step in client["nested"]:
            node = (node or {}).get(step)
            if not isinstance(node, dict):
                return []
        for where, settings in node.items():
            table = (settings or {}).get(client["key"])
            if isinstance(table, dict) and table:
                found.append((where, table))
        return found
    table = document.get(client["key"])
    if isinstance(table, dict) and table:
        found.append((client["name"], table))
    return found


def is_wrapped(entry):
    """Whether this server already runs behind the sensor.

    Checked by looking for the sensor's own run.py in the arguments rather than by a
    marker key, because a client is free to drop keys it does not recognise and a marker
    that can vanish is worse than no marker.
    """
    args = entry.get("args") or []
    return any(isinstance(a, str) and a.endswith(os.path.join("sensor", "run.py"))
               for a in args)


def wrap(entry, python, config_path):
    """The same server, behind the sensor. The original command moves after the `--`."""
    if is_wrapped(entry):
        return dict(entry)
    original = [entry.get("command")] + list(entry.get("args") or [])
    wrapped = dict(entry)
    wrapped["command"] = python
    wrapped["args"] = [RUN_PY, "--config", config_path, SEPARATOR] + \
        [a for a in original if a is not None]
    return wrapped


def unwrap(entry):
    """The server as it was before the sensor was put in front of it."""
    if not is_wrapped(entry):
        return dict(entry)
    args = list(entry.get("args") or [])
    try:
        after = args[args.index(SEPARATOR) + 1:]
    except ValueError:
        return dict(entry)
    if not after:
        return dict(entry)
    restored = dict(entry)
    restored["command"] = after[0]
    restored["args"] = after[1:]
    return restored


def describe(entry):
    """What a person needs to see to recognise a server, and nothing else.

    An env block routinely holds API keys. Those are never printed: the count is enough
    to show they survive, and showing a key to confirm it was preserved would be a poor
    trade.
    """
    command = entry.get("command") or ""
    args = [a for a in (entry.get("args") or []) if isinstance(a, str)]
    line = " ".join([command] + args)
    env = entry.get("env") or {}
    if env:
        line += "   [%d environment variable%s kept]" % (len(env),
                                                         "" if len(env) == 1 else "s")
    return line


def discover():
    """[(client, path, where, name, entry)] for every MCP server on this machine."""
    out = []
    for client in CLIENTS:
        if not os.path.exists(client["path"]):
            continue
        document = read(client["path"])
        for where, table in tables(document, client):
            for name, entry in sorted(table.items()):
                if isinstance(entry, dict):
                    out.append((client, client["path"], where, name, entry))
    return out
