"""One question at a time, and no flags to look up.

Taking part was five commands, each needing a flag somebody had to find in a document. Every
one of those is a place to stop, and a participant who stops at step three has done the work
of installing and produced nothing.

So this asks instead. Member id, then it runs the drill so they see the thing work before
being asked to install anything, then which arm, then whether they want to be credited. Every
answer it needs it asks for; every answer it can infer it does not ask about.

Nothing here does anything the other commands do not. It fills in their arguments.

Python 3.9+ standard library only.
"""
import argparse
import os
import sys

from . import called, canaries, credit, drill, enroll, hub, paint

PUBLISH_BASE = "https://guardianprotocol.network/season1"


def _ask(prompt, out, default=None, validate=None, explain=None):
    """One question. Returns the answer, or None if the person gave up.

    Explanation prints once, above the question, rather than after a rejection. Somebody who
    has to be told why only after guessing wrong has been made to feel stupid by a tool.
    """
    if explain:
        out.write("%s\n" % explain)
    suffix = " [%s]" % default if default else ""
    while True:
        try:
            answer = input("  %s%s: " % (prompt, suffix)).strip()
        except (EOFError, KeyboardInterrupt):
            out.write("\n")
            return None
        answer = answer or default or ""
        if not answer:
            out.write("    Needed, or press ctrl-c to stop.\n")
            continue
        if validate:
            problem = validate(answer)
            if problem:
                out.write("    %s\n" % problem)
                continue
        return answer


def _yes(prompt, out, default=True):
    suffix = "Y/n" if default else "y/N"
    try:
        answer = input("  %s [%s]: " % (prompt, suffix)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        out.write("\n")
        return False
    if not answer:
        return default
    return answer.startswith("y")


def _agenda_reachable(base, opener=None):
    """Whether anything is published yet. Used to set expectations, never to refuse.

    A participant who installs the networked arm before an exercise exists sees nothing
    happen, checks status, sees nothing happen, and concludes it is broken. It is not: there
    is nothing to run. Saying so costs one request and saves that conversation.
    """
    import urllib.request
    opener = opener or urllib.request.urlopen
    try:
        with opener(base.rstrip("/") + "/agenda.json", timeout=10) as response:
            return bool(response.read())
    except Exception:
        return False


def _bad_org(value):
    if not hub.ORG_RE.match(value):
        return ("Three to thirty two characters, lowercase letters, digits and hyphens. "
                "Not a company name.")
    return None


def main(argv=None, out=sys.stdout):
    ap = argparse.ArgumentParser(
        prog="guardian setup",
        description="Take part, one question at a time. Asks before it does anything.")
    ap.add_argument("--base", default=PUBLISH_BASE, help="where exercises are published")
    ap.add_argument("--home", default=None, help="where to keep records")
    a = ap.parse_args([] if argv is None else argv)

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        out.write("This asks questions, so it needs a terminal.\n\n")
        out.write("Without one, the same thing in two commands:\n\n")
        out.write("  %s drill --org YOUR-ID\n" % called.invocation())
        out.write("  %s enroll --offline --org YOUR-ID\n" % called.invocation())
        return 2

    where = enroll.data_dir(a.home) if a.home is None else os.path.abspath(a.home)

    from . import banner
    banner.show(out)
    out.write("Four questions. Nothing is installed or sent until you have seen it.\n\n")

    # 1. The pseudonym. Asked first because everything else carries it.
    org = _ask("member id", out, validate=_bad_org,
               explain="A pseudonym you choose. It is the only identifier that travels with\n"
                       "anything you share, so it must not be your company name.")
    if not org:
        out.write("\nStopped. Nothing was done.\n")
        return 1

    # 2. Show it working before asking to install anything. Somebody who has watched their
    # own sensor catch three attacks is being asked a different question afterwards.
    out.write("\nRunning the drill, which attacks this machine through your own sensor.\n")
    out.write("Nothing leaves the machine.\n\n")
    code = drill.main(["--org", org, "--dir", os.path.join(where, "drill"),
                       "--no-next-steps"], out=out)
    if code != 0:
        out.write("\nThe drill did not come out clean, so nothing will be installed.\n")
        out.write("Please send me what it printed. That is more useful than a clean run.\n")
        return code

    # 3. Which arm. Both are valid and the comparison between them is the research, so the
    # question is put as a choice rather than as a default with an escape hatch.
    out.write("\nTwo ways to take part, both useful:\n\n")
    out.write("  networked  polls a published schedule, so an exercise can run without\n")
    out.write("             you being available for it. Never listens, nothing inbound.\n")
    out.write("  offline    reaches out to nothing at all. runs on its own schedule.\n")
    out.write("             the control arm: what the sensor is worth alone.\n")
    out.write("  neither    stop here. the drill above already told you something.\n\n")
    # Networked by default, because it is the arm the research needs most and a default is
    # the answer most people give. Offline stays one word away and is named as the control
    # arm rather than as the lesser option.
    arm = _ask("which", out, default="networked",
               validate=lambda v: None if v in ("offline", "networked", "neither")
               else "One of: networked, offline, neither.")
    if not arm:
        arm = "neither"

    # Checked before installing, not after. A networked install against a base with nothing
    # published polls into silence, which is correct and looks broken, and somebody who
    # checks status and sees nothing concludes it did not work.
    if arm == "networked":
        nothing_yet = not _agenda_reachable(a.base)
        if nothing_yet:
            out.write("\nNothing is scheduled at %s yet.\n" % a.base)
            out.write("That is expected before an exercise is published. This will sit "
                      "quietly and run one\nwhen it appears, so there is nothing to see "
                      "until then.\n")

    installed = False
    if arm != "neither":
        args = ["--org", org] + (["--offline"] if arm == "offline"
                                 else ["--base", a.base])
        out.write("\n")
        enroll.main(args + ["--print-only", "--brief"], out=out)
        if _yes("install it", out):
            rc = enroll.main(args, out=out)
            installed = rc == 0
        else:
            out.write("\nNot installed. You can run this again any time.\n")

    # 4. Credit. Asked last, because it is the only question about them rather than about
    # their machine, and because somebody who has just seen it work is better placed to
    # decide whether they want their name on it.
    out.write("\nCredit in the research is optional and separate from anything you share.\n")
    out.write("Your sightings carry the pseudonym and never your name.\n\n")
    if _yes("record how you want to be credited", out, default=False):
        name = _ask("your name", out)
        if name:
            handle = _ask("github handle, or leave blank", out, default="-")
            handle = "" if handle in ("-", "") else handle
            author = _yes("list you as an author if your contribution is substantive",
                          out, default=True)
            try:
                record = credit.build(name, handle, "", acknowledge_only=not author)
                credit.save(record, os.path.join(where, "credit.json"))
                out.write("\nRecorded in %s. It goes nowhere until you send it.\n"
                          % os.path.join(where, "credit.json"))
            except credit.CreditError as e:
                out.write("\nNot recorded: %s\n" % e)

    out.write("\n%s\n" % paint.paint("Done.", "good", out))
    out.write("  member id   %s\n" % org)
    out.write("  taking part %s\n" % (arm if installed else "not installed"))
    out.write("  records in  %s\n\n" % where)
    out.write("To see what you would share, and share nothing:\n")
    out.write("  %s report --org %s --evidence %s --preview\n\n"
              % (called.invocation(), org,
                 os.path.join(where, "drill", "evidence.jsonl")))
    out.write("To check on it later:\n  %s status\n" % called.invocation())
    if arm == "neither" or not installed:
        out.write("\nNothing is running. To take part later:\n  %s setup\n"
                  % called.invocation())
    return 0
