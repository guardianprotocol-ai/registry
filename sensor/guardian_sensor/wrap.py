"""Put the sensor in front of the MCP servers a client already has.

Installing is not the hard part. Editing the config is: every server entry has to be
rewritten by hand to run through the proxy, in a file whose location differs per client,
and a mistake there is a client that silently stops working.

This module does the rewriting. The pure functions take and return data, so the whole
rewrite can be tested without a config file anywhere on disk. Python 3.9+ standard
library only.
"""
import copy
import json
import os
import sys

SENTINEL = "guardian_sensor"

# Where clients keep their MCP servers. A client that is not installed contributes
# nothing, so an unknown entry here is harmless. Paths are expanded per platform.
KNOWN_CONFIGS = (
    ("Claude Desktop", "~/Library/Application Support/Claude/claude_desktop_config.json"),
    ("Claude Desktop", "~/.config/Claude/claude_desktop_config.json"),
    ("Claude Desktop", "~/AppData/Roaming/Claude/claude_desktop_config.json"),
    ("Claude Code", "~/.claude.json"),
    ("Claude Code (project)", ".mcp.json"),
    ("Cursor", "~/.cursor/mcp.json"),
    ("Cursor (project)", ".cursor/mcp.json"),
    ("Gemini CLI", "~/.gemini/settings.json"),
    ("Gemini CLI (project)", ".gemini/settings.json"),
    ("VS Code (project)", ".vscode/mcp.json"),
)

# The keys a client uses to hold its server table. Different clients, same shape.
SERVER_KEYS = ("mcpServers", "servers")


def find_configs(home=None, cwd=None, exists=os.path.exists):
    """Every known config file that is actually present. Returns (client, path) pairs."""
    home = home or os.path.expanduser("~")
    cwd = cwd or os.getcwd()
    found, seen = [], set()
    for client, raw in KNOWN_CONFIGS:
        path = (os.path.join(home, raw[2:]) if raw.startswith("~/")
                else os.path.join(cwd, raw))
        path = os.path.normpath(path)
        if path in seen or not exists(path):
            continue
        seen.add(path)
        found.append((client, path))
    return found


def is_wrapped(entry):
    """True if this server already runs through the sensor.

    Checked before every rewrite. Wrapping a wrapped server produces a proxy in front of a
    proxy, which still works and is impossible to read, so the second wrap is refused
    rather than merely discouraged.
    """
    args = entry.get("args") or []
    return SENTINEL in (entry.get("command") or "") or SENTINEL in args


def is_stdio(entry):
    """Only a server the client launches can be proxied over stdio.

    An entry with a url is reached over HTTP by the client itself, so there is no pipe to
    sit in. Those are skipped and named, never silently ignored.
    """
    return bool(entry.get("command")) and not entry.get("url")


def wrap_entry(entry, config_path, python=None):
    """One server entry, rewritten to run through the sensor. Pure."""
    python = python or sys.executable
    wrapped = copy.deepcopy(entry)
    wrapped["command"] = python
    wrapped["args"] = (["-m", SENTINEL, "--config", config_path, "--",
                        entry["command"]] + list(entry.get("args") or []))
    return wrapped


def plan(config, config_path, python=None):
    """What wrapping this config would do, as a list of (name, action, reason).

    Nothing is written and nothing is decided here. The caller prints the plan, and only
    writes if the operator agrees, because this edits a file the operator depends on and
    did not write.
    """
    actions = []
    for key in SERVER_KEYS:
        for name, entry in sorted((config.get(key) or {}).items()):
            if not isinstance(entry, dict):
                actions.append((name, "skip", "not an object, left alone"))
            elif is_wrapped(entry):
                actions.append((name, "skip", "already behind the sensor"))
            elif not is_stdio(entry):
                where = "a url, so the client connects directly" if entry.get("url") else \
                        "no command to launch"
                actions.append((name, "skip", where))
            else:
                actions.append((name, "wrap", " ".join(
                    [entry["command"]] + list(entry.get("args") or []))[:60]))
    return actions


def apply(config, config_path, python=None):
    """A new config with every stdio server wrapped. The input is never mutated."""
    out = copy.deepcopy(config)
    for key in SERVER_KEYS:
        servers = out.get(key)
        if not isinstance(servers, dict):
            continue
        for name, entry in servers.items():
            if isinstance(entry, dict) and is_stdio(entry) and not is_wrapped(entry):
                servers[name] = wrap_entry(entry, config_path, python)
    return out


def undo(config):
    """Take the sensor back out, restoring each server's original command.

    An undo that only half works is worse than none, because the operator believes they
    have removed it. So the original command is read back out of the wrapped arguments
    rather than guessed, and an entry that does not parse is left exactly as it is.
    """
    out = copy.deepcopy(config)
    for key in SERVER_KEYS:
        servers = out.get(key)
        if not isinstance(servers, dict):
            continue
        for name, entry in servers.items():
            if not isinstance(entry, dict) or not is_wrapped(entry):
                continue
            args = list(entry.get("args") or [])
            if "--" not in args:
                continue
            original = args[args.index("--") + 1:]
            if not original:
                continue
            restored = copy.deepcopy(entry)
            restored["command"] = original[0]
            restored["args"] = original[1:]
            if not restored["args"]:
                restored.pop("args", None)
            servers[name] = restored
    return out
