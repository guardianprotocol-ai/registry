"""Agreeing to share, and then sharing without being asked again.

Four commands. `on` records consent after showing exactly what will be sent. `now` sends.
`off` revokes. With no command it says where things stand.

Sending happens as part of the poll once consent exists, so a member agrees once and then
does nothing. That is the point: a protocol whose data only moves when somebody remembers to
move it is not a network.

Python 3.9+ standard library only.
"""
import argparse
import json
import os
import sys

from . import called, hub, paint, share

COMMANDS = ("on", "off", "now", "status")
DEFAULT_ENDPOINT = "https://guardianprotocol.network/season1/sightings"


def _document(root, org, since=None):
    paths = [os.path.join(root, "drill", "evidence.jsonl"),
             os.path.join(root, "evidence.jsonl")]
    records = hub.read_evidence([p for p in paths if os.path.exists(p)], since=since)
    rules_version = hub.rules_version_from(records) or "unrecorded"
    return hub.build_sightings(records, org, rules_version)


def on(argv, out=sys.stdout, root=None):
    ap = argparse.ArgumentParser(prog="guardian share on",
                                 description="Agree to send sightings automatically")
    ap.add_argument("--org", default=os.environ.get("GUARDIAN_ORG"))
    ap.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    ap.add_argument("--home", default=None)
    ap.add_argument("--yes", action="store_true", help="skip the question")
    a = ap.parse_args(argv)
    root = root or _home(a.home)

    if not a.org or not hub.ORG_RE.match(a.org):
        out.write("A member id is needed. It is the pseudonym your sightings carry.\n")
        out.write("  %s share on --org your-member-id\n" % called.invocation())
        return 2

    # Shown before agreement, built from their own evidence, so the question is about a real
    # document rather than a description of one.
    try:
        document = _document(root, a.org)
    except hub.HubError as e:
        out.write("Cannot build a document yet: %s\n" % e)
        return 1

    out.write("This is the whole of what would be sent, now and in future:\n\n")
    out.write(hub.preview_text(document) + "\n\n")
    out.write("To %s\n" % a.endpoint)
    out.write("Automatically, as part of the poll, so you are not asked again.\n")
    out.write("Stop at any time with: %s share off\n\n" % called.invocation())

    if not a.yes:
        try:
            answer = input("  agree to send this [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            out.write("\n")
            answer = ""
        if not answer.startswith("y"):
            out.write("\nNot agreed. Nothing will be sent.\n")
            return 1

    share.record_consent(root, a.org, a.endpoint)
    out.write("\n%s Recorded in %s.\n"
              % (paint.paint("Agreed.", "good", out), share.consent_path(root)))
    out.write("Sightings will be sent as part of the poll. Nothing else changes.\n")
    return 0


def off(argv, out=sys.stdout, root=None):
    ap = argparse.ArgumentParser(prog="guardian share off")
    ap.add_argument("--home", default=None)
    a = ap.parse_args(argv)
    root = root or _home(a.home)
    try:
        os.remove(share.consent_path(root))
        out.write("Stopped. Nothing further will be sent.\n")
        out.write("What you already sent cannot be recalled, and it was counts only.\n")
    except OSError:
        out.write("Not sharing. Nothing was being sent.\n")
    return 0


def now(argv, out=sys.stdout, root=None, opener=None):
    ap = argparse.ArgumentParser(prog="guardian share now",
                                 description="Send what there is, once")
    ap.add_argument("--home", default=None)
    ap.add_argument("--since", default=None, metavar="YYYY-MM-DD")
    a = ap.parse_args(argv)
    root = root or _home(a.home)

    agreed = share.consent(root)
    if not agreed:
        out.write("Not sharing. Agree first, after seeing what would be sent:\n")
        out.write("  %s share on --org your-member-id\n" % called.invocation())
        return 1

    try:
        document = _document(root, agreed["org"], since=a.since)
    except hub.HubError as e:
        out.write("Cannot build a document: %s\n" % e)
        return 1

    ok, message = share.send(document, agreed["endpoint"], opener=opener)
    share.note_sent(root, document, ok, message)
    entries = len(document["sightings"])
    if ok:
        out.write("Sent %d entr%s: %s\n" % (entries, "y" if entries == 1 else "ies", message))
        return 0
    # A receiver being down is a delay, not a loss, and saying so stops somebody thinking
    # their evidence is gone.
    out.write("Not sent: %s\n" % message)
    out.write("Your evidence is still here and the next attempt will send it.\n")
    return 1


def status(argv, out=sys.stdout, root=None):
    ap = argparse.ArgumentParser(prog="guardian share")
    ap.add_argument("--home", default=None)
    a = ap.parse_args(argv)
    root = root or _home(a.home)
    agreed = share.consent(root)
    if not agreed:
        out.write("Not sharing. Your sightings stay on this machine.\n\n")
        out.write("To agree, after seeing exactly what would be sent:\n")
        out.write("  %s share on --org your-member-id\n" % called.invocation())
        return 0
    out.write("Sharing as %s, to %s\n\n" % (agreed["org"], agreed["endpoint"]))
    out.write("  %s\n\n" % agreed["what_is_sent"])
    sent = os.path.join(root, share.SENT_NAME)
    if os.path.exists(sent):
        lines = [json.loads(l) for l in open(sent, encoding="utf-8") if l.strip()]
        good = sum(1 for l in lines if l.get("ok"))
        out.write("  %d send(s), %d accepted\n" % (len(lines), good))
    out.write("\nStop with: %s share off\n" % called.invocation())
    return 0


def _home(explicit):
    if explicit:
        return os.path.abspath(explicit)
    override = os.environ.get("GUARDIAN_HOME")
    if override:
        return os.path.abspath(override)
    return os.path.join(os.path.expanduser("~"), ".guardian")


def main(argv, out=sys.stdout):
    # A leading flag means they asked for status with options, not a subcommand. Printing
    # usage at somebody who typed a valid thing is the kind of small rudeness that makes a
    # tool feel unfinished.
    if not argv or argv[0].startswith("-"):
        return status(list(argv), out=out)
    command, rest = argv[0], argv[1:]
    if command not in COMMANDS:
        out.write("Usage: %s share {%s}\n" % (called.invocation(), "|".join(COMMANDS)))
        return 2
    if command == "on":
        return on(rest, out=out)
    if command == "off":
        return off(rest, out=out)
    if command == "now":
        return now(rest, out=out)
    return status(rest, out=out)
