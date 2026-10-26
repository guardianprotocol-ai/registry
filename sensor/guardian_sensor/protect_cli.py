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
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"mode": "monitor",
                   "allowlist": [],
                   "_mode": ("monitor records and allows. Change to block once you trust "
                             "it, and a detection will stop the call instead."),
                   "_allowlist": ("domains your agents may send data to. Anything else "
                                  "counts as outside when a tool result carried "
                                  "instructions.")}, f, indent=2, sort_keys=True)
        f.write("\n")
    return path, True


def _backup(path):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    copy = "%s.guardian-backup-%s" % (path, stamp)
    shutil.copy2(path, copy)
    return copy


def _apply(document, client, where, name, entry):
    """Put a changed entry back where it came from."""
    if client["nested"]:
        node = document
        for step in client["nested"]:
            node = node[step]
        node[where][client["key"]][name] = entry
    else:
        document[client["key"]][name] = entry


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
    if not found:
        out.write("No MCP servers found on this machine.\n\n")
        out.write("Looked in:\n")
        for client in clients.CLIENTS:
            mark = "found" if os.path.exists(client["path"]) else "not there"
            out.write("  %-16s %-10s %s\n" % (client["name"], mark, client["path"]))
        out.write("\nA client with no servers configured has nothing for the sensor to "
                  "sit in front of.\nAdd a server to your client first, then run this "
                  "again.\n")
        return 0

    changes = plan(remove=a.remove)
    protected = [f for f in found if clients.is_wrapped(f[4])]

    out.write("%d MCP server%s on this machine, %d already behind the sensor.\n\n"
              % (len(found), "" if len(found) == 1 else "s", len(protected)))

    if not changes:
        if a.remove:
            out.write("Nothing to take out. No server here runs behind the sensor.\n")
        else:
            out.write("%s\n" % paint.paint("Every server is already protected.", "good",
                                           out))
            out.write("Running this again changes nothing, which is how it should "
                      "behave.\n")
        return 0

    verb = "take the sensor out of" if a.remove else "put the sensor in front of"
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

    out.write("Environment variables are carried across untouched and are never printed "
              "here.\n")
    if not a.remove:
        settings, made = ensure_config()
        out.write("Settings: %s%s\n"
                  % (settings, ", created just now" if made else ""))
        out.write("It starts in monitor mode, which records and allows. The first thing "
                  "a sensor does\nto somebody's real work should not be to stop it. "
                  "Change one word when you trust it.\n")
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

    out.write("\n%s %d server%s.\n"
              % (paint.paint("Done." if a.remove else "Protected.", "good", out),
                 written, "" if written == 1 else "s"))
    if not a.remove:
        out.write("Restart your client so it launches the servers again. Until it does, "
                  "it is still\nrunning the ones it started earlier.\n")
    return 0
