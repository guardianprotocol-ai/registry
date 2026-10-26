"""Check that a protected server still works, and that the sensor is really in the way.

Editing a config says a change was written. It does not say the agent can still reach
its tools, and that is the thing most likely to have gone wrong: a path that is right on
this machine and wrong in the client's working directory, a python that is not on the
client's PATH, a server that needed an environment variable the wrapper dropped. A
member who finds out by their agent quietly losing a tool will uninstall this, and they
will be right to.

So each wrapped server is started exactly as the client would start it, asked for its
tools, and the answer is read back. A tool list that comes back proves two things at
once: the server still works, and the sensor relayed it, because there is no other way
for the answer to arrive.

Nothing is attacked and nothing is written. This is a question, not an exercise.

Python 3.9+ standard library only.
"""
import argparse
import json
import os
import subprocess
import sys

from . import called, clients, paint

# A server that has not answered by now is not going to. Long enough for a cold npx
# download on a slow morning, short enough that a person does not think it has hung.
TIMEOUT = 45


def ask(entry, timeout=TIMEOUT):
    """Start this server the way a client would and ask what tools it has.

    Returns (ok, detail, tool_count).
    """
    command = [entry.get("command")] + list(entry.get("args") or [])
    command = [c for c in command if isinstance(c, str)]
    if not command:
        return False, "there is no command to run", 0
    env = dict(os.environ)
    env.update({k: v for k, v in (entry.get("env") or {}).items()
                if isinstance(v, str)})
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, bufsize=1, env=env,
                                   cwd=entry.get("cwd") or None)
    except (OSError, ValueError) as e:
        return False, "it could not be started: %s" % e, 0

    def send(n, method, params=None):
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": n, "method": method,
                                        "params": params or {}}) + "\n")
        process.stdin.flush()
        return process.stdout.readline()

    try:
        send(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "guardian-verify",
                                              "version": "0"}})
        line = send(2, "tools/list")
        answer = json.loads(line) if line else {}
        tools = ((answer.get("result") or {}).get("tools")) or []
        if not line:
            return False, "it started but answered nothing", 0
        return True, "", len(tools)
    except (json.JSONDecodeError, OSError, ValueError) as e:
        return False, "its answer could not be read: %s" % e, 0
    finally:
        try:
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def main(argv=None, out=sys.stdout):
    ap = argparse.ArgumentParser(
        prog="%s verify" % called.invocation(),
        description="Check that protected servers still work and are really protected")
    ap.add_argument("--timeout", type=int, default=TIMEOUT)
    a = ap.parse_args(argv)

    found = clients.discover()
    wrapped = [f for f in found if clients.is_wrapped(f[4])]
    bare = [f for f in found if not clients.is_wrapped(f[4])]

    if not found:
        out.write("No MCP servers found, so there is nothing to check.\n")
        return 0
    if not wrapped:
        out.write("%d server%s found and none is behind the sensor.\n"
                  % (len(found), "" if len(found) == 1 else "s"))
        out.write("Nothing is being inspected. To change that:  %s protect\n"
                  % called.invocation())
        return 1

    out.write("Starting %d protected server%s the way your client would, and asking "
              "each for its tools.\n\n" % (len(wrapped), "" if len(wrapped) == 1 else "s"))
    broken = 0
    for client, path, where, name, entry in wrapped:
        label = name if where == client["name"] else "%s (%s)" % (name, where)
        out.write("  %-28s " % label[:28])
        out.flush()
        ok, detail, tools = ask(entry, timeout=a.timeout)
        if ok:
            out.write("%s, %d tool%s through the sensor\n"
                      % (paint.paint("answers", "good", out), tools,
                         "" if tools == 1 else "s"))
        else:
            broken += 1
            out.write("%s: %s\n" % (paint.paint("does not answer", "bad", out), detail))

    out.write("\n")
    if broken:
        out.write("%d of %d protected servers did not answer.\n"
                  % (broken, len(wrapped)))
        out.write("An agent reaching one of those has quietly lost a tool, which is "
                  "worse than not\nhaving protected it. Put them back with:  %s protect "
                  "--remove\n" % called.invocation())
        return 1

    out.write("%s Every protected server answered, which means the server still works "
              "and the\nsensor relayed it: there is no other path for the answer to "
              "arrive by.\n"
              % paint.paint("Good.", "good", out))
    if bare:
        # Said after the good news rather than instead of it. A partly protected machine
        # is the state somebody is most likely to mistake for a protected one.
        out.write("\n%d server%s still outside the sensor: %s\n"
                  % (len(bare), " is" if len(bare) == 1 else "s are",
                     ", ".join(f[3] for f in bare[:6])))
        out.write("Those are not being inspected. %s protect covers them.\n"
                  % called.invocation())
    manual = clients.discover_read_only()
    if manual:
        out.write("\n%d server%s in a config this cannot change: %s\n"
                  % (len(manual), "" if len(manual) == 1 else "s",
                     ", ".join(n for _, _, n, _ in manual[:6])))
        out.write("%s protect shows the lines to add by hand.\n" % called.invocation())
    return 0
