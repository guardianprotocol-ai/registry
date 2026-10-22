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

from . import canaries

COMMANDS = ("add", "list", "arm", "remove")


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
        prog="guardian_sensor canary add",
        description="Register a value the sensor should watch for in outbound tool calls")
    ap.add_argument("--label", required=True,
                    help="how you will recognise this canary later. Never the value itself")
    ap.add_argument("--file", default=canaries.DEFAULT_PATH)
    ap.add_argument("--armed", action="store_true",
                    help="skip the baseline period and block immediately. Only do this for a "
                         "value you are certain no legitimate process touches")
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
        out.write("  python3 -m guardian_sensor canary arm --label %r\n\n" % entry["label"])
        out.write("If it does fire during baseline, the canary is in the wrong place. Move it "
                  "rather than\nraising the threshold.\n")
    else:
        out.write("\nArmed immediately, so a hit will block the call. If ordinary work "
                  "touches this value,\nthat will stop an agent mid task.\n")
    return 0


def list_(argv, out=sys.stdout):
    ap = argparse.ArgumentParser(prog="guardian_sensor canary list")
    ap.add_argument("--file", default=canaries.DEFAULT_PATH)
    ap.add_argument("--evidence", default=os.path.join(".guardian", "evidence.jsonl"),
                    help="where hit counts are read from")
    a = ap.parse_args(argv)
    store = canaries.load(a.file)
    rows = store.get("canaries", [])
    if not rows:
        out.write("No canaries registered. The sensor is watching for its own test tokens "
                  "only, not for\nanything of yours.\n")
        return 0

    hits = canaries.hits_by_label(a.evidence)
    width = max(max(len(c["label"]) for c in rows), len("LABEL"))
    out.write("%-*s  %-9s %s\n" % (width, "LABEL", "STATE", "HITS"))
    for c in sorted(rows, key=lambda c: c["label"]):
        out.write("%-*s  %-9s %s\n" % (width, c["label"], c["state"],
                                        hits.get(c["label"], 0)))
    out.write("\nValues are stored as salted digests and are not recoverable from this file.\n")

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
    ap = argparse.ArgumentParser(prog="guardian_sensor canary arm")
    ap.add_argument("--label", required=True)
    ap.add_argument("--file", default=canaries.DEFAULT_PATH)
    a = ap.parse_args(argv)
    store = canaries.load(a.file)
    if canaries.arm(store, a.label) is None:
        out.write("No canary labelled %r.\n" % a.label)
        return 1
    canaries.save(store, a.file)
    out.write("%r is armed. A hit will now block the call.\n" % a.label)
    return 0


def remove(argv, out=sys.stdout):
    ap = argparse.ArgumentParser(prog="guardian_sensor canary remove")
    ap.add_argument("--label", required=True)
    ap.add_argument("--file", default=canaries.DEFAULT_PATH)
    a = ap.parse_args(argv)
    store = canaries.load(a.file)
    if not canaries.remove(store, a.label):
        out.write("No canary labelled %r.\n" % a.label)
        return 1
    canaries.save(store, a.file)
    out.write("Removed %r. The sensor no longer watches for it.\n" % a.label)
    return 0


def main(argv, out=sys.stdout, stream=None):
    if not argv or argv[0] not in COMMANDS:
        out.write("Usage: python3 -m guardian_sensor canary {%s}\n" % "|".join(COMMANDS))
        return 2
    command, rest = argv[0], argv[1:]
    try:
        if command == "add":
            return add(rest, out=out, stream=stream)
        if command == "list":
            return list_(rest, out=out)
        if command == "arm":
            return arm(rest, out=out)
        return remove(rest, out=out)
    except canaries.CanaryError as e:
        out.write("Refused: %s\n" % e)
        return 1
