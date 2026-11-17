#!/usr/bin/env python3
"""A shell tool that really runs kubectl and clusterctl, spoken as MCP over stdio.

Used only by run_cluster.py, against a throwaway management cluster. It is the server
behind the sensor for the cases an agent would run through a shell.

It runs the command it is given, so it is constrained in the ways that matter:

  * only `kubectl` and `clusterctl`, at the paths the runner passed, as an argument list.
    Nothing goes through a shell, so a pipe or a redirection is not interpreted
  * always against the lab kubeconfig. A `KUBECONFIG=...` in front of the command is
    dropped, and `--kubeconfig`, `--context`, `--server` and `--to-kubeconfig` are refused
  * only if that kubeconfig points at this machine. A cluster anywhere else is refused
    before anything runs

A refusal from this file is a constraint of the lab tool. It is not a Guardian block and
it is not an answer from the API server.
"""
import json
import os
import re
import shlex
import subprocess
import sys

REFUSED = "refused by lab tool constraint"
LOCAL = re.compile(r"^\s*server:\s*https://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?\s*$", re.M)
FORBIDDEN = ("--kubeconfig", "--context", "--server", "-s", "--to-kubeconfig", "--token",
             "--as", "--user", "--cluster")
TIMEOUT = 90


class Constraint(Exception):
    pass


def argv_for(command, implied_kubectl=False):
    """The argument list to run, or a Constraint saying why not."""
    kubeconfig = os.environ.get("GP_LAB_KUBECONFIG", "")
    try:
        with open(kubeconfig, encoding="utf-8") as f:
            servers = re.findall(r"^\s*server:.*$", f.read(), re.M)
    except OSError:
        raise Constraint("the lab kubeconfig is missing")
    if not servers or not all(LOCAL.match(line) for line in servers):
        raise Constraint("the lab kubeconfig does not point at this machine")
    try:
        tokens = shlex.split(command)
    except ValueError as e:
        raise Constraint("the command does not parse: %s" % e)
    while tokens and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]) or tokens[0] == "sudo"):
        tokens = tokens[1:]
    binaries = {"kubectl": os.environ.get("GP_LAB_KUBECTL", ""),
                "clusterctl": os.environ.get("GP_LAB_CLUSTERCTL", "")}
    if tokens and tokens[0] in binaries:
        binary, tokens = binaries[tokens[0]], tokens[1:]
    elif implied_kubectl:
        binary = binaries["kubectl"]
    else:
        raise Constraint("only kubectl and clusterctl are run")
    if not binary or not os.path.isfile(binary):
        raise Constraint("the lab was not given a path for that binary")
    for token in tokens:
        if token.split("=", 1)[0] in FORBIDDEN:
            raise Constraint("%s would point the command somewhere else" % token.split("=", 1)[0])
        if token in ("|", "||", ";", "&", "&&", ">", ">>", "<"):
            raise Constraint("nothing here goes through a shell")
    return [binary] + tokens


def run(command, implied_kubectl=False):
    argv = argv_for(command, implied_kubectl)
    env = {"KUBECONFIG": os.environ["GP_LAB_KUBECONFIG"], "PATH": os.environ.get("PATH", ""),
           "HOME": os.environ.get("HOME", "")}
    done = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT, env=env)
    return (done.stdout.strip() or done.stderr.strip() or "exit %d" % done.returncode,
            done.returncode != 0)


TOOLS = [
    {"name": "shell", "description": "Run one kubectl or clusterctl command.",
     "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}},
    {"name": "execute_kubectl", "description": "Run kubectl with these arguments.",
     "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}},
]


def _reply(mid, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\n")
    sys.stdout.flush()


def _text(text, error=False):
    result = {"content": [{"type": "text", "text": text}]}
    if error:
        result["isError"] = True
    return result


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if method == "initialize":
            _reply(mid, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                         "serverInfo": {"name": "gp-lab-real-shell", "version": "0"}})
        elif method == "tools/list":
            _reply(mid, {"tools": TOOLS})
        elif method == "tools/call":
            name, args = params.get("name"), params.get("arguments") or {}
            if name not in ("shell", "execute_kubectl"):
                _reply(mid, _text("%s: unknown tool" % REFUSED, error=True))
                continue
            try:
                text, failed = run(str(args.get("command", "")), name == "execute_kubectl")
                _reply(mid, _text(text, error=failed))
            except Constraint as e:
                _reply(mid, _text("%s: %s" % (REFUSED, e), error=True))
            except (OSError, subprocess.TimeoutExpired) as e:
                _reply(mid, _text("could not be run: %s" % e, error=True))
        elif mid is not None:
            _reply(mid, _text("unsupported method", error=True))


if __name__ == "__main__":
    main()
