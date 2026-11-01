"""Command line for registered canaries: add, list, arm and remove.

The value is read from a prompt or from standard input, never from a command line argument,
because an argument lands in shell history and in the process table where any other user on
the machine can read it. That is a small detail and it is the whole point of the feature.

Python 3.9+ standard library only.
"""
import argparse
import getpass
import os
import sys

from . import breach
from . import called
from . import canaries
from . import home
from . import path_canaries

COMMANDS = ("add", "list", "arm", "remove", "add-file", "decoy", "seed", "watch")


def _read_value(stream=None, prompt=True):
    """The secret, from a terminal prompt or from a pipe. Never echoed, never an argument."""
    stream = stream if stream is not None else sys.stdin
    if not stream.isatty():
        return stream.readline().rstrip("\n")
    if not prompt:
        return ""
    return getpass.getpass("Paste the canary value (not shown): ")


def add(argv, out=sys.stdout, stream=None):
    ap = argparse.ArgumentParser(
        prog="%s canary add" % called.invocation(),
        description="Register a value the sensor should watch for in outbound tool calls")
    ap.add_argument("--label", required=True,
                    help="how you will recognise this canary later. Never the value itself")
    ap.add_argument("--file", default=canaries.DEFAULT_PATH)
    ap.add_argument("--armed", action="store_true",
                    help="skip the baseline period and block immediately. Only do this for a "
                         "value you are certain no legitimate process touches")
    # Somebody reaching for --value has guessed the obvious interface, and refusing them
    # with argparse's "unrecognized arguments" reads as a missing feature rather than a
    # decision. The decision is the point of the whole command, so it is explained here.
    for argument in argv or []:
        if argument == "--value" or argument.startswith("--value="):
            out.write("There is no --value, on purpose.\n\n")
            out.write("A value passed as an argument is written to your shell history and "
                      "is visible\nin the process list to anybody else on this machine, "
                      "which would leak the exact\nsecret you are asking the sensor to "
                      "watch for.\n\n")
            out.write("Paste it at the prompt instead:\n")
            out.write("  %s canary add --label %s\n\n" % (called.invocation(), "NAME"))
            out.write("Or pipe it in, if something else already holds it:\n")
            out.write("  cat secret.txt | %s canary add --label %s\n"
                      % (called.invocation(), "NAME"))
            return 2

    a = ap.parse_args(argv)

    value = _read_value(stream)
    if not value:
        out.write("No value given. Pipe it in, or run this in a terminal to be prompted.\n")
        return 2

    store = canaries.load(a.file)
    try:
        entry = canaries.add(store, value, a.label,
                             canaries.ARMED if a.armed else canaries.BASELINE)
    except canaries.CanaryError as e:
        out.write("Refused: %s\n" % e)
        return 1
    # The value is dropped here and never written anywhere. Only its salted digest is kept.
    del value
    canaries.save(store, a.file)

    out.write("Registered %r as %s.\n" % (entry["label"], entry["state"]))
    out.write("The value itself was not stored and cannot be recovered from %s.\n" % a.file)
    if entry["state"] == canaries.BASELINE:
        out.write("\nIt is in baseline, so a hit is reported and nothing is blocked. Watch it "
                  "for a few days\nof ordinary work. If it never fires, arm it:\n\n")
        out.write("  %s canary arm --label %r\n\n"
                  % (called.invocation(), entry["label"]))
        out.write("If it does fire during baseline, the canary is in the wrong place. Move it "
                  "rather than\nraising the threshold.\n")
    else:
        out.write("\nArmed immediately, so a hit will block the call. If ordinary work "
                  "touches this value,\nthat will stop an agent mid task.\n")
    return 0


def list_(argv, out=sys.stdout):
    ap = argparse.ArgumentParser(prog="%s canary list" % called.invocation())
    ap.add_argument("--file", default=canaries.DEFAULT_PATH)
    ap.add_argument("--paths", default=path_canaries.default_path(),
                    help="path and sentinel canaries, stored as digests")
    ap.add_argument("--evidence", default=home.path("evidence.jsonl"),
                    help="where hit counts are read from")
    a = ap.parse_args(argv)
    store = canaries.load(a.file)
    rows = store.get("canaries", [])
    path_store = path_canaries.load(a.paths)
    path_rows = path_store.get("paths", [])
    if not rows and not path_rows:
        out.write("No canaries registered. The sensor is watching for its own test tokens "
                  "only, not for\nanything of yours.\n")
        return 0

    hits = canaries.hits_by_label(a.evidence)
    if rows:
        width = max(max(len(c["label"]) for c in rows), len("LABEL"))
        out.write("%-*s  %-9s %s\n" % (width, "LABEL", "STATE", "HITS"))
        for c in sorted(rows, key=lambda c: c["label"]):
            out.write("%-*s  %-9s %s\n" % (width, c["label"], c["state"],
                                            hits.get(c["label"], 0)))
        out.write("\nValues are stored as salted digests and are not recoverable from this file.\n")
    if path_rows:
        path_hits = path_canaries.hits_by_label(a.evidence)
        width = max(max(len(c["label"]) for c in path_rows), len("LABEL"))
        out.write("\n%-*s  %-9s  %-8s  %-9s %s\n" % (width, "PATH", "STATE", "KIND", "ROLE", "HITS"))
        for c in sorted(path_rows, key=lambda c: c["label"]):
            out.write("%-*s  %-9s  %-8s  %-9s %s\n" % (
                width, c["label"], c["state"], c.get("kind", "path"), c.get("role", "decoy"),
                path_hits.get(c["label"], 0)))
        out.write("\nPaths and sentinel strings are stored as salted digests and are not "
                  "recoverable from this file.\n")

    # A canary that fires during its baseline is in the wrong place, and an operator reading
    # a list of zeros would arm it. Saying so here is the difference between the baseline
    # period working and being a formality.
    fired = [c["label"] for c in rows
             if c["state"] == canaries.BASELINE and hits.get(c["label"], 0)]
    if fired:
        out.write("\nStill in baseline and already firing: %s.\n"
                  % ", ".join(sorted(fired)))
        out.write("Something legitimate is touching those values. Move the canary rather "
                  "than arming it.\n")
    quiet = [c["label"] for c in rows
             if c["state"] == canaries.BASELINE and not hits.get(c["label"], 0)]
    if quiet:
        out.write("\nIn baseline and quiet so far: %s.\n" % ", ".join(sorted(quiet)))
        out.write("Arm one once a few days of ordinary work have gone by without it "
                  "firing.\n")
    return 0


def arm(argv, out=sys.stdout):
    ap = argparse.ArgumentParser(prog="%s canary arm" % called.invocation())
    ap.add_argument("--label", required=True)
    ap.add_argument("--file", default=canaries.DEFAULT_PATH)
    ap.add_argument("--paths", default=path_canaries.default_path())
    a = ap.parse_args(argv)
    store = canaries.load(a.file)
    path_store = path_canaries.load(a.paths)
    armed_value = canaries.arm(store, a.label)
    armed_path = path_canaries.arm(path_store, a.label)
    if armed_value is None and armed_path is None:
        out.write("No canary labelled %r.\n" % a.label)
        return 1
    if armed_value is not None:
        canaries.save(store, a.file)
    if armed_path is not None:
        path_canaries.save(path_store, a.paths)
    out.write("%r is armed. A hit will now block the call.\n" % a.label)
    return 0


def remove(argv, out=sys.stdout):
    ap = argparse.ArgumentParser(prog="%s canary remove" % called.invocation())
    ap.add_argument("--label", required=True)
    ap.add_argument("--file", default=canaries.DEFAULT_PATH)
    ap.add_argument("--paths", default=path_canaries.default_path())
    a = ap.parse_args(argv)
    store = canaries.load(a.file)
    path_store = path_canaries.load(a.paths)
    removed_value = canaries.remove(store, a.label)
    removed_path = path_canaries.remove(path_store, a.label)
    if not removed_value and not removed_path:
        out.write("No canary labelled %r.\n" % a.label)
        return 1
    if removed_value:
        canaries.save(store, a.file)
    if removed_path:
        path_canaries.save(path_store, a.paths)
    out.write("Removed %r. The sensor no longer watches for it.\n" % a.label)
    return 0


def _state(armed):
    return canaries.ARMED if armed else canaries.BASELINE


def add_file(argv, out=sys.stdout):
    ap = argparse.ArgumentParser(
        prog="%s canary add-file" % called.invocation(),
        description="Register a file by its path. The path is not written into the canary file.")
    ap.add_argument("path")
    ap.add_argument("--label", required=True)
    ap.add_argument("--root", default=None, help="sandbox root. A path that resolves outside it is refused")
    ap.add_argument("--role", default="decoy", choices=path_canaries.ROLES)
    ap.add_argument("--armed", action="store_true")
    ap.add_argument("--never-leaves", action="store_true",
                    help="store a digest of the file bytes and treat a copy as a trip")
    ap.add_argument("--allow-process", action="append", default=[],
                    help="for an asset, a process name that may read it. Repeat to name more than one")
    ap.add_argument("--paths", default=path_canaries.default_path())
    ap.add_argument("--policy", default=path_canaries.default_policy_path())
    a = ap.parse_args(argv)
    store = path_canaries.load(a.paths)
    try:
        entry = path_canaries.add_path(
            store, a.path, a.label, state=_state(a.armed), role=a.role, root=a.root,
            content=a.never_leaves or a.role == "asset")
    except path_canaries.PathCanaryError as exc:
        out.write("Refused: %s\n" % exc)
        return 1
    path_canaries.save(store, a.paths)
    if a.role == "asset" or a.allow_process or a.root or a.never_leaves:
        policy = breach.load_policy(a.policy)
        if a.root and not policy.get("root"):
            policy["root"] = os.path.abspath(a.root)
        asset = policy["assets"].setdefault(entry["label"], {
            "allow_processes": [], "allow_tools": [], "never_leaves": False})
        for name in a.allow_process:
            if name not in asset["allow_processes"]:
                asset["allow_processes"].append(name)
        if a.never_leaves:
            asset["never_leaves"] = True
        breach.save_policy(policy, a.policy)
    out.write("Registered %r as %s (%s).\n" % (entry["label"], entry["state"], entry["role"]))
    out.write("The path was not stored and cannot be recovered from %s.\n" % a.paths)
    return 0


def decoy(argv, out=sys.stdout):
    ap = argparse.ArgumentParser(
        prog="%s canary decoy" % called.invocation(),
        description="Write a fake file and register its path. Refuses to overwrite anything.")
    ap.add_argument("--kind", required=True, choices=path_canaries.DECOY_KINDS)
    ap.add_argument("--path", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--root", default=None)
    ap.add_argument("--armed", action="store_true")
    ap.add_argument("--sentinel-url", default=None,
                    help="a loopback URL to mention in the file and register as a sentinel")
    ap.add_argument("--paths", default=path_canaries.default_path())
    ap.add_argument("--values", default=canaries.DEFAULT_PATH)
    a = ap.parse_args(argv)
    try:
        _fields, token = path_canaries.write_decoy(
            a.path, a.kind, sentinel_url=a.sentinel_url)
        store = path_canaries.load(a.paths)
        entry = path_canaries.add_path(
            store, a.path, a.label, state=_state(a.armed), role="decoy", root=a.root,
            content=True)
        if a.sentinel_url:
            path_canaries.add_sentinel(
                store, a.sentinel_url, a.label + "-sentinel", state=_state(a.armed))
        path_canaries.save(store, a.paths)
        if token:
            value_store = canaries.load(a.values)
            canaries.add(value_store, token, a.label + "-token", _state(a.armed))
            canaries.save(value_store, a.values)
            del token
    except (path_canaries.PathCanaryError, canaries.CanaryError) as exc:
        out.write("Refused: %s\n" % exc)
        return 1
    out.write("Wrote a %s decoy and registered %r as %s.\n" % (a.kind, entry["label"], entry["state"]))
    out.write("The file is fake. Its path was not stored.\n")
    return 0


def seed(argv, out=sys.stdout):
    ap = argparse.ArgumentParser(
        prog="%s canary seed" % called.invocation(),
        description="Plant fake customer records in a dataset and register them as value canaries.")
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--format", required=True, choices=path_canaries.SEED_FORMATS, dest="fmt")
    ap.add_argument("--label", required=True)
    ap.add_argument("--root", default=None)
    ap.add_argument("--armed", action="store_true")
    ap.add_argument("--paths", default=path_canaries.default_path())
    ap.add_argument("--values", default=canaries.DEFAULT_PATH)
    ap.add_argument("--policy", default=path_canaries.default_policy_path())
    a = ap.parse_args(argv)
    try:
        seeded = path_canaries.write_seed_dataset(a.dataset, a.fmt, a.label)
        value_store = canaries.load(a.values)
        entries = path_canaries.register_seeds(value_store, seeded, _state(a.armed))
        canaries.save(value_store, a.values)
        path_store = path_canaries.load(a.paths)
        home_entry = path_canaries.add_path(
            path_store, a.dataset, a.label + "-file", state=_state(a.armed),
            role="seed-home", root=a.root)
        path_canaries.save(path_store, a.paths)
        policy = breach.load_policy(a.policy)
        if a.root and not policy.get("root"):
            policy["root"] = os.path.abspath(a.root)
        for entry in entries:
            policy["seeds"][entry["label"]] = home_entry["label"]
        breach.save_policy(policy, a.policy)
        del seeded
    except (path_canaries.PathCanaryError, canaries.CanaryError, breach.BreachError) as exc:
        out.write("Refused: %s\n" % exc)
        return 1
    out.write("Planted seeded records in the dataset and registered %d value canaries.\n"
              % len(entries))
    out.write("The values are in the dataset. Only their digests were stored.\n")
    return 0


def watch(argv, out=sys.stdout):
    ap = argparse.ArgumentParser(
        prog="%s canary watch" % called.invocation(),
        description="Watch a root and quarantine armed canaries when any process touches them.")
    ap.add_argument("--root", required=True)
    ap.add_argument("--policy", default=path_canaries.default_policy_path())
    ap.add_argument("--paths", default=path_canaries.default_path())
    ap.add_argument("--values", default=canaries.DEFAULT_PATH)
    ap.add_argument("--audit", default=None)
    ap.add_argument("--evidence", default=home.path("evidence.jsonl"))
    ap.add_argument("--backend", default="auto", choices=("auto", "inotify", "poll"))
    a = ap.parse_args(argv)
    policy = breach.load_policy(a.policy)
    policy["root"] = os.path.abspath(a.root)
    if a.audit:
        policy["audit_path"] = a.audit
    store = path_canaries.load(a.paths)
    value_store = canaries.load(a.values)
    watcher = breach.Watcher(
        a.root, store, policy, value_store=value_store,
        audit_path=a.audit, evidence_path=a.evidence, backend=a.backend)
    watcher.start()
    out.write("Watching %s with %s. A trip is written locally and is not sent anywhere.\n"
              % (policy["root"], watcher.backend))
    if watcher.sentinel:
        out.write("Decoy endpoint: %s\n" % watcher.sentinel_url())
    out.flush()
    try:
        while True:
            time_sleep()
    except KeyboardInterrupt:
        watcher.stop()
        out.write("Stopped.\n")
    return 0


def time_sleep():
    import time
    time.sleep(0.5)


def main(argv, out=sys.stdout, stream=None):
    if not argv or argv[0] not in COMMANDS:
        out.write("Usage: %s canary {%s}\n" % (called.invocation(), "|".join(COMMANDS)))
        return 2
    command, rest = argv[0], argv[1:]
    try:
        if command == "add":
            return add(rest, out=out, stream=stream)
        if command == "list":
            return list_(rest, out=out)
        if command == "arm":
            return arm(rest, out=out)
        if command == "add-file":
            return add_file(rest, out=out)
        if command == "decoy":
            return decoy(rest, out=out)
        if command == "seed":
            return seed(rest, out=out)
        if command == "watch":
            return watch(rest, out=out)
        return remove(rest, out=out)
    except (canaries.CanaryError, path_canaries.PathCanaryError, breach.BreachError) as e:
        out.write("Refused: %s\n" % e)
        return 1
