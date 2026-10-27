"""Put the sensor in front of the MCP servers an agent on this machine actually uses.

Until this existed the sensor protected whatever somebody had hand wired, which in
practice is one server on one machine, once. The drill proves the sensor catches an
attack. This is what makes it catch one aimed at the person running it.

Nothing is changed without being shown first. The file is copied before it is written,
every server is named with the command it runs, and anything already behind the sensor is
left alone so running this twice does nothing the first run did not.

It edits configuration files that belong to somebody else's tools, which is the most
intrusive thing in this project, so the order is: find, show, ask, back up, write.

Python 3.9+ standard library only.
"""
import argparse
import datetime
import json
import os
import shutil
import sys

from . import called, clients, home, paint

CONFIG_NAME = "guardian.json"


def config_path(root=None):
    return os.path.join(root or home.data_dir(), CONFIG_NAME)


def ensure_config(root=None, out=sys.stdout):
    """The sensor's own settings, written once if they are not there.

    Monitor rather than block on a first install, deliberately. The first thing a sensor
    does on somebody's real work should not be to stop it: a false positive on day one
    is how a security tool gets uninstalled on day one. They can change one word when
    they trust it.
    """
    path = config_path(root)
    if os.path.exists(path):
        return path, False
    where = os.path.dirname(path)
    os.makedirs(where, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"mode": "monitor",
                   "allowlist": [],
                   # Absolute, and pointed at the member's own records.
                   #
                   # The hook defaults both of these to a relative `.guardian/`, which is
                   # right for running it by hand and wrong for a service: a hook installed
                   # in a client writes to whatever directory the agent happens to be
                   # working in. Detections then scatter across the user's projects, and
                   # `status`, `report` and `share` read the member's home and find
                   # nothing. A real detection could be made and never reach the exchange.
                   #
                   # Found by installing the hooks, catching a real taint-then-act chain in
                   # a live session, and then watching `report --preview` say "Entries: 0".
                   "evidence_path": os.path.join(where, "evidence.jsonl"),
                   "state_dir": os.path.join(where, "hook-state"),
                   "_mode": ("monitor records and allows. Change to block once you trust "
                             "it, and a detection will stop the call instead."),
                   "_allowlist": ("domains your agents may send data to. Anything else "
                                  "counts as outside when a tool result carried "
                                  "instructions."),
                   "_evidence_path": ("where detections are written. The same file "
                                      "status, report and share read."),
                   }, f, indent=2, sort_keys=True)
        f.write("\n")
    return path, True


def _backup(path):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    copy = "%s.guardian-backup-%s" % (path, stamp)
    shutil.copy2(path, copy)
    return copy


def _apply(document, client, where, name, entry):
    """Put a changed entry back where it came from.

    A nested client has per-project tables and one of its own, so `where` is either a
    project or the user scope sentinel. Writing the sentinel as though it were a project
    is how this failed: the reader found a user scoped server and the writer could not
    put it back.
    """
    if client["nested"] and where != clients.USER_SCOPE:
        node = document
        for step in client["nested"]:
            node = node[step]
        node[where][client["key"]][name] = entry
    else:
        document[client["key"]][name] = entry


def hook_plan(remove=False):
    """[(client, path, settings, after, events)] for clients whose own tools can be covered.

    Separate from the server plan because it answers a different question. A proxy
    covers tools that arrive over MCP; this covers the client's own shell, file and web
    tools, which never do. Most people running a client have no MCP servers at all, so
    without this the common case gets no live coverage at all.
    """
    out = []
    for client in clients.HOOK_CLIENTS:
        if not os.path.exists(os.path.dirname(client["path"])):
            continue
        settings = clients.read(client["path"])
        if settings is None and os.path.exists(client["path"]):
            continue                   # unreadable, so left alone rather than replaced
        settings = settings or {}
        present = clients.hooks_present(settings, client["events"])
        if remove:
            if not present:
                continue
            after = clients.remove_hooks(settings, client["events"])
        else:
            if len(present) == len(client["events"]):
                continue
            after = clients.add_hooks(
                settings, client["events"],
                clients.hook_command(sys.executable, config_path()))
        out.append((client, client["path"], settings, after, present))
    return out


def plan(remove=False):
    """[(client, path, where, name, before, after)] for everything that would change."""
    python = sys.executable
    settings = config_path()
    out = []
    for client, path, where, name, entry in clients.discover():
        wrapped = clients.is_wrapped(entry)
        if remove and not wrapped:
            continue
        if not remove and wrapped:
            continue
        after = (clients.unwrap(entry) if remove
                 else clients.wrap(entry, python, settings))
        out.append((client, path, where, name, entry, after))
    return out


def main(argv=None, out=sys.stdout):
    ap = argparse.ArgumentParser(
        prog="%s protect" % called.invocation(),
        description="Put the sensor in front of the MCP servers on this machine")
    ap.add_argument("--remove", action="store_true",
                    help="take the sensor back out of every server it is in front of")
    ap.add_argument("--print-only", action="store_true",
                    help="show what would change and write nothing")
    ap.add_argument("--yes", action="store_true", help="skip the question")
    a = ap.parse_args(argv)

    found = clients.discover()
    hooks = hook_plan(remove=a.remove)
    # Servers this cannot safely change, reported so nobody believes a client was
    # checked and found clean when it was never readable in the first place.
    manual = [] if a.remove else clients.discover_read_only()
    if not found and not hooks and not manual:
        out.write("No MCP servers found on this machine.\n\n")
        out.write("Looked in:\n")
        for client in clients.CLIENTS:
            mark = "found" if os.path.exists(client["path"]) else "not there"
            out.write("  %-16s %-10s %s\n" % (client["name"], mark, client["path"]))
        out.write("\nA client with no servers configured has nothing for the sensor to "
                  "sit in front of,\nand no client here offers a way to reach its own "
                  "tools.\n")
        return 0

    changes = plan(remove=a.remove)
    protected = [f for f in found if clients.is_wrapped(f[4])]

    out.write("%d MCP server%s on this machine, %d already behind the sensor.\n"
              % (len(found), "" if len(found) == 1 else "s", len(protected)))
    if hooks and not a.remove:
        out.write("%d client%s can also have the rules run over its own shell, file and "
                  "web tools,\nwhich never pass through MCP and are invisible to a "
                  "proxy.\n" % (len(hooks), "" if len(hooks) == 1 else "s"))
    out.write("\n")

    if not changes and not hooks:
        if a.remove:
            out.write("Nothing to take out. No server here runs behind the sensor.\n")
        else:
            out.write("%s\n" % paint.paint("Every server is already protected.", "good",
                                           out))
            out.write("Running this again changes nothing, which is how it should "
                      "behave.\n")
        return 0

    verb = "take the sensor out of" if a.remove else "put the sensor in front of"
    if changes:
        out.write("About to %s %d server%s:\n\n"
                  % (verb, len(changes), "" if len(changes) == 1 else "s"))
    by_file = {}
    for client, path, where, name, before, after in changes:
        by_file.setdefault(path, []).append((client, where, name, before, after))
    for path, entries in sorted(by_file.items()):
        out.write("  %s\n" % path)
        for client, where, name, before, after in entries:
            label = name if where == client["name"] else "%s  (%s)" % (name, where)
            out.write("    %s\n" % label)
            out.write("      now:  %s\n" % clients.describe(before))
            out.write("      then: %s\n" % clients.describe(after))
        out.write("\n")

    if hooks:
        out.write("And %s the rules over the client's own tools:\n\n"
                  % ("stop running" if a.remove else "run"))
        for client, path, _, _, present in hooks:
            out.write("  %s\n" % path)
            out.write("    %-14s %s\n" % (client["name"], client["note"]))
            if present and not a.remove:
                out.write("      already on: %s\n" % ", ".join(present))
        out.write("\n    Anything already in that file stays. Somebody's own hooks are "
                  "theirs, and\n    replacing them to install a security tool would be "
                  "its own kind of attack.\n\n")

    if changes:
        out.write("Environment variables are carried across untouched and are never "
                  "printed here.\n")
    if not a.remove:
        settings, made = ensure_config()
        out.write("Settings: %s%s\n"
                  % (settings, ", created just now" if made else ""))
        out.write("It starts in monitor mode, which records and allows. The first thing "
                  "a sensor does\nto somebody's real work should not be to stop it. "
                  "Change one word when you trust it.\n")
    if manual:
        settings = config_path()
        out.write("%d server%s this cannot change for you:\n\n"
                  % (len(manual), "" if len(manual) == 1 else "s"))
        for client, path, name, entry in manual:
            out.write("  %-10s %-16s %s\n"
                      % (client["name"], name, clients.describe(entry)))
        out.write("\n    %s\n" % manual[0][1])
        out.write("    %s\n\n" % manual[0][0]["note"])
        out.write("    In that file, under the entry for %s, replace the command and "
                  "args with:\n\n" % manual[0][2])
        for line in clients.toml_instruction(manual[0][3], sys.executable,
                                             settings).splitlines():
            out.write("      %s\n" % line)
        out.write("\n    Everything else in that entry stays as it is. The same shape "
                  "works for the\n    others, with their own command and args after "
                  "the double dash.\n\n")

    out.write("Each file is copied before it is written.\n")
    out.write("Undo with: %s protect --remove\n\n" % called.invocation())

    if a.print_only:
        out.write("Nothing was written.\n")
        return 0
    if not a.yes:
        try:
            answer = input("  do it [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            out.write("\n")
            answer = ""
        if not answer.startswith("y"):
            out.write("\nNothing was changed.\n")
            return 0

    written = 0
    for path, entries in sorted(by_file.items()):
        document = clients.read(path)
        if document is None:
            out.write("\nCould not read %s, so it was left alone.\n" % path)
            continue
        copy = _backup(path)
        for client, where, name, _, after in entries:
            try:
                _apply(document, client, where, name, after)
            except (KeyError, TypeError) as e:
                out.write("\nCould not change %s in %s (%s). The file is unchanged and "
                          "a copy is at %s.\n" % (name, path, e, copy))
                return 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(document, f, indent=2)
            f.write("\n")
        written += len(entries)
        out.write("  %s  (copy at %s)\n" % (path, os.path.basename(copy)))

    for client, path, _, after, _ in hooks:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        copy = _backup(path) if os.path.exists(path) else None
        with open(path, "w", encoding="utf-8") as f:
            json.dump(after, f, indent=2, sort_keys=True)
            f.write("\n")
        written += 1
        out.write("  %s%s\n" % (path, "  (copy at %s)" % os.path.basename(copy)
                                 if copy else "  (created)"))

    out.write("\n%s %d change%s.\n"
              % (paint.paint("Done." if a.remove else "Protected.", "good", out),
                 written, "" if written == 1 else "s"))
    if not a.remove:
        out.write("Restart your client so it launches the servers again. Until it does, "
                  "it is still\nrunning the ones it started earlier.\n")
    return 0
