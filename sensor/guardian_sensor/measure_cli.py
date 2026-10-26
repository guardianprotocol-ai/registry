"""Measure a real agent on this machine, rather than only the lab server.

The drill proves the sensor catches an attack against a server written to be attacked.
Every machine running it produces the same three results, which is the right way to
measure how fast a detection travels and tells nobody anything about how a real agent
behaves.

That second question needs somebody's actual harness, their actual model, at a version
only they are running. A thousand people each measuring the agent they already have is a
thousand data points nobody can produce alone, and it was reachable only by knowing that
a separate tool existed in another folder. So it is a command.

It costs tokens, on their account, so nothing here runs without being asked. What is
published is a rate and an interval, never a transcript.

Python 3.9+ standard library only.
"""
import argparse
import os
import subprocess
import sys

from . import called, paint

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCANNER = os.path.join(ROOT, "scanner")
# The floor the project will quote a rate above. Fewer runs than this and the interval is
# so wide that the number says nothing, which is worse than no number because somebody
# will quote it anyway.
MIN_RUNS = 20


def _scanner():
    sys.path.insert(0, SCANNER)
    from guardian_scanner import targets
    return targets


def _rows():
    """Harnesses this machine could measure, with the controls left out.

    The scripted targets exist to check the harness itself and are not a finding about
    any agent, so offering them here would invite somebody to report one as a result.
    """
    return [r for r in _scanner().available() if not r[0].startswith("scripted:")]


def main(argv=None, out=sys.stdout):
    ap = argparse.ArgumentParser(
        prog="%s measure" % called.invocation(),
        description="Measure an agent on this machine against the registry's attacks")
    ap.add_argument("--target", default=None,
                    help="which harness, for example claude-code. Omit to be shown what "
                         "this machine can measure")
    ap.add_argument("--model", default=None,
                    help="pin the harness to one model. Recorded with the result, and "
                         "without it the result says the model was unrecorded")
    ap.add_argument("--pattern", action="append", dest="only", metavar="GP-nnnn")
    ap.add_argument("--repeat", type=int, default=MIN_RUNS)
    ap.add_argument("--sensor", action="store_true",
                    help="put the sensor in front, which is the other half of the "
                         "comparison")
    ap.add_argument("--record", default=None, metavar="DIR",
                    help="write a result file per pattern, usually ../results")
    ap.add_argument("--yes", action="store_true", help="skip the question")
    a = ap.parse_args(argv)

    rows = _rows()
    if not a.target:
        out.write("Harnesses this machine can measure:\n\n")
        for name, installed, credentials, note in rows:
            state = ("ready" if installed and credentials is not False
                     else "not installed" if not installed else "no credentials found")
            out.write("  %-14s %-20s %s\n" % (name, state, note[:44]))
        out.write("\nA measurement runs a real agent many times and costs tokens on "
                  "your account.\n")
        out.write("Nothing runs until you name one:\n")
        out.write("  %s measure --target %s\n"
                  % (called.invocation(), rows[0][0] if rows else "claude-code"))
        out.write("\nAnd the other half of the comparison, the same agent with the "
                  "sensor in front:\n")
        out.write("  %s measure --target %s --sensor\n"
                  % (called.invocation(), rows[0][0] if rows else "claude-code"))
        return 0

    known = {name for name, _, _, _ in rows}
    if a.target not in known:
        out.write("No harness called %r. This machine can measure: %s\n"
                  % (a.target, ", ".join(sorted(known)) or "none"))
        return 2
    for name, installed, credentials, _ in rows:
        if name != a.target:
            continue
        if not installed:
            out.write("%s is not installed here.\n" % a.target)
            return 1
        if credentials is False:
            out.write("%s is installed but no credentials were found, so it would fail "
                      "every run.\n" % a.target)
            out.write("A run that errors is left out of the rate rather than counted as "
                      "a defence, so this\nwould produce nothing rather than something "
                      "wrong, and it would still cost you time.\n")
            return 1

    if a.repeat < MIN_RUNS:
        # Said rather than silently corrected, because somebody who asked for five runs
        # has a reason and should know why the answer is twenty.
        out.write("%d runs is below the floor of %d this project will quote a rate "
                  "above.\n" % (a.repeat, MIN_RUNS))
        out.write("Fewer runs than that leaves an interval so wide the number says "
                  "nothing, and\nsomebody will quote it anyway. Running %d.\n\n"
                  % MIN_RUNS)
        a.repeat = MIN_RUNS

    patterns = a.only or []
    out.write("About to run %s%s against %s, %d times per pattern.\n"
              % (a.target, " with the sensor in front" if a.sensor else "",
                 ", ".join(patterns) if patterns else "every runnable pattern",
                 a.repeat))
    out.write("This drives a real agent, so it costs tokens on your own account.\n")
    if not a.model:
        out.write("No model named, so the result will say the model was unrecorded. "
                  "Pass --model to\npin it, which is what makes the number comparable "
                  "with somebody else's.\n")
    out.write("\n")
    if not a.yes:
        try:
            answer = input("  run it [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            out.write("\n")
            answer = ""
        if not answer.startswith("y"):
            out.write("\nNot run. Nothing was started and nothing was charged.\n")
            return 0

    command = [sys.executable, "-m", "guardian_scanner", "run",
               "--target", a.target, "--repeat", str(a.repeat)]
    if a.sensor:
        command.append("--sensor")
    if a.model:
        command += ["--model", a.model]
    for pattern in patterns:
        command += ["--pattern", pattern]
    if a.record:
        command += ["--record", os.path.abspath(a.record)]
    out.write("\n")
    out.flush()
    done = subprocess.run(command, cwd=SCANNER)
    if done.returncode == 0 and a.record:
        out.write("\n%s\n" % paint.paint("Recorded.", "good", out))
        out.write("A result file names the harness and its version, the model, how many "
                  "runs it took\nand the interval around the rate. Open a pull request "
                  "with it and it joins the matrix.\n")
    return done.returncode
