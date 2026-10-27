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


#: What a nested client's own top-level table is called when it is named for a person.
#: Shared, because the half that finds a table and the half that writes to it have to
#: agree on it: they did not, and the write failed on a table the reader had just found.
USER_SCOPE = "user scope"


def _home(*parts):
    return os.path.join(os.path.expanduser("~"), *parts)


# name, where the config is, and how to reach the server tables inside it.
#
# "nested" means servers live under one key per project as well as at the top level,
# which is how Claude Code keeps them: a server added in one directory is not a server
# anywhere else, and wrapping the lot would reach into projects somebody did not ask
# about. So each is offered separately and named by its project. A nested client also
# keeps a table of its own, for servers added at user scope, and both are read.
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
    {"name": "gemini-cli", "path": _home(".gemini", "settings.json"),
     "nested": (), "key": "mcpServers", "note": ""},
)

# Clients whose configuration can be read and must not be written.
#
# Codex keeps its servers in TOML. The standard library reads TOML and does not write it,
# and rewriting somebody's configuration by editing the text would lose their comments
# and their formatting and occasionally their file. A tool that mangles a config while
# installing itself has done more harm than the attack it was there for.
#
# So these are found and reported with the exact change to make, and left alone. Being
# told precisely what to add is worth a great deal more than not being told the server
# exists.
READ_ONLY = (
    {"name": "codex", "path": _home(".codex", "config.toml"),
     "key": "mcp_servers", "format": "toml",
     "note": "TOML, so this is shown rather than changed"},
)


def read_toml(path):
    try:
        import tomllib
    except ImportError:                     # Python 3.9 and 3.10
        return None
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, ValueError):
        return None


def discover_read_only():
    """[(client, path, name, entry)] for servers this cannot safely change."""
    out = []
    for client in READ_ONLY:
        if not os.path.exists(client["path"]):
            continue
        document = read_toml(client["path"])
        table = (document or {}).get(client["key"]) or {}
        for name, entry in sorted(table.items()):
            if isinstance(entry, dict):
                out.append((client, client["path"], name, entry))
    return out


def toml_instruction(entry, python, config_path):
    """The lines to put in a TOML config, for somebody doing it by hand."""
    wrapped = wrap(entry, python, config_path)
    args = ", ".join(json.dumps(a) for a in wrapped.get("args") or [])
    return ('command = %s\nargs = [%s]'
            % (json.dumps(wrapped.get("command")), args))


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
    # A client with per-project tables can also keep one of its own, and Claude Code does:
    # `claude mcp add --scope user` writes to the top level of the same file. Those servers
    # were invisible here, and the command still said "Protected", which is worse than
    # finding nothing: somebody would believe their agents were behind the sensor.
    table = document.get(client["key"])
    if isinstance(table, dict) and table:
        found.append((USER_SCOPE if client["nested"] else client["name"], table))
    if client["nested"]:
        node = document
        for step in client["nested"]:
            node = (node or {}).get(step)
            if not isinstance(node, dict):
                return found
        for where, settings in node.items():
            table = (settings or {}).get(client["key"])
            if isinstance(table, dict) and table:
                found.append((where, table))
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


# ---------- The client's own tools ----------
#
# An MCP proxy sees tools that come from MCP servers. A client's own shell, file reads
# and writes and web fetches never pass through MCP, and most people running Claude Code
# have no MCP servers at all, so wrapping servers alone leaves the common case with no
# live coverage whatsoever.
#
# A client that offers hooks can run the same rule engine over its own tools. That is
# where a client is named here: not as another place to find servers, but as a place the
# detection can reach tools the proxy cannot.

HOOK_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "hooks", "claude_code", "guardian_hook.py")

HOOK_CLIENTS = (
    {"name": "claude-code", "path": _home(".claude", "settings.json"),
     "events": ("PreToolUse", "PostToolUse"),
     "note": "runs the rules over the client's own shell, file and web tools"},
)


def hook_command(python, config_path, hook_py=None):
    return "%s %s --config %s" % (python, hook_py or HOOK_PY, config_path)


def _is_ours(hook):
    command = (hook or {}).get("command") or ""
    return isinstance(command, str) and command.endswith("guardian_hook.py") or \
        "guardian_hook.py" in command


def hooks_present(settings, events):
    """Which of these events already run this project's hook."""
    installed = []
    table = (settings or {}).get("hooks") or {}
    for event in events:
        for matcher in table.get(event) or []:
            if any(_is_ours(h) for h in (matcher or {}).get("hooks") or []):
                installed.append(event)
                break
    return installed


def add_hooks(settings, events, command):
    """The same settings with this project's hook on each event.

    Appended beside whatever is already there. Somebody's existing hooks are theirs and
    replacing them to install a security tool would be its own kind of attack.
    """
    out = json.loads(json.dumps(settings or {}))
    table = out.setdefault("hooks", {})
    for event in events:
        entries = table.setdefault(event, [])
        if any(any(_is_ours(h) for h in (m or {}).get("hooks") or [])
               for m in entries):
            continue
        entries.append({"matcher": "*",
                        "hooks": [{"type": "command", "command": command}]})
    return out


def remove_hooks(settings, events):
    """The same settings with only this project's hook taken out."""
    out = json.loads(json.dumps(settings or {}))
    table = out.get("hooks") or {}
    for event in events:
        kept = []
        for matcher in table.get(event) or []:
            hooks = [h for h in (matcher or {}).get("hooks") or [] if not _is_ours(h)]
            if hooks:
                entry = dict(matcher)
                entry["hooks"] = hooks
                kept.append(entry)
            elif not (matcher or {}).get("hooks"):
                kept.append(matcher)
        if kept:
            table[event] = kept
        else:
            table.pop(event, None)
    if not table:
        out.pop("hooks", None)
    return out
