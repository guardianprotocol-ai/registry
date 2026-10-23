"""Am I taking part, and what has happened?

The question a participant has a week after installing something and forgetting it. Without
an answer they have two options: read a log, or ask. Both are worse than a command, and the
second one costs somebody else's time.

Deliberately read-only and local. It fetches nothing, reports nothing anywhere, and says
only what is already on this machine. A status command that phoned home about a machine's
health would be the thing this protocol refuses to be.

Python 3.9+ standard library only.
"""
import argparse
import json
import os
import sys

from . import called, canaries, credit, paint

DEFAULT_HOME = os.path.join(".guardian")


def home(explicit=None):
    if explicit:
        return os.path.abspath(explicit)
    override = os.environ.get("GUARDIAN_HOME")
    if override:
        return os.path.abspath(override)
    return os.path.join(os.path.expanduser("~"), ".guardian")


def _read_jsonl(path):
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return out


def gather(root):
    """Everything worth saying, as data, so it can be tested without reading a screen."""
    agenda_log = _read_jsonl(os.path.join(root, "agenda.jsonl"))
    runs = [r for r in agenda_log if r.get("outcome") in ("ran", "failed")]
    evidence = _read_jsonl(os.path.join(root, "drill", "evidence.jsonl"))
    canary_store = None
    try:
        canary_store = canaries.load(os.path.join(root, "canaries.json"))
    except canaries.CanaryError:
        canary_store = {"canaries": [], "broken": True}
    return {
        "root": root,
        "exists": os.path.isdir(root),
        "runs": runs,
        "last_run": runs[-1] if runs else None,
        "refusals": [r for r in agenda_log if r.get("outcome") == "refused"],
        "detections": len(evidence),
        "patterns": sorted({p for r in evidence for p in r.get("patterns", [])}),
        "canaries": (canary_store or {}).get("canaries", []),
        "canaries_broken": bool((canary_store or {}).get("broken")),
        "credit": credit.load(os.path.join(root, "credit.json")),
    }


def render(state, out=sys.stdout):
    def good(text):
        return paint.paint(text, "good", out)

    def bad(text):
        return paint.paint(text, "bad", out)

    def dim(text):
        return paint.paint(text, "dim", out)

    if not state["exists"]:
        out.write("Not taking part. Nothing has been installed in %s.\n\n" % state["root"])
        out.write("To try the sensor without installing anything:\n\n")
        out.write("  %s drill\n" % called.invocation())
        return 1

    out.write("Records in %s\n\n" % state["root"])

    runs = state["runs"]
    if runs:
        last = state["last_run"]
        arm = "offline" if (last.get("settings") or {}).get("offline") else "networked"
        out.write("  %-22s %s\n" % ("exercises run", good(str(len(runs)))))
        out.write("  %-22s %s, %s\n" % ("most recent", last.get("exercise_id", "unnamed"),
                                        last.get("time", "")[:16]))
        out.write("  %-22s %s\n" % ("arm", arm))
    else:
        out.write("  %-22s %s\n" % ("exercises run", dim("none yet")))

    if state["refusals"]:
        out.write("  %-22s %s\n" % ("agendas refused", bad(str(len(state["refusals"])))))

    out.write("  %-22s %d\n" % ("detections recorded", state["detections"]))
    if state["patterns"]:
        out.write("  %-22s %s\n" % ("patterns seen", ", ".join(state["patterns"])))

    if state["canaries_broken"]:
        out.write("  %-22s %s\n" % ("your canaries", bad("file unusable, not being watched")))
    elif state["canaries"]:
        armed = [c for c in state["canaries"] if c["state"] == canaries.ARMED]
        out.write("  %-22s %d registered, %d armed\n"
                  % ("your canaries", len(state["canaries"]), len(armed)))
    else:
        out.write("  %-22s %s\n" % ("your canaries", dim("none registered")))

    if state["credit"]:
        out.write("  %-22s %s\n" % ("credited as", state["credit"].get("name", "")))
    else:
        out.write("  %-22s %s\n" % ("credited as", dim("not recorded")))

    out.write("\n")
    # What to do next, which is the part somebody actually wants. A status that lists facts
    # and leaves the reader to work out the implication has done half the job.
    if not runs:
        out.write("Nothing has run yet. If you enrolled, it runs on its own when an "
                  "exercise is due.\nTo run one now:  %s drill\n"
                  % called.invocation())
    elif not state["credit"]:
        out.write("You have taken part and are not credited anywhere. If you want to be "
                  "named in the research:\n\n  %s credit --name \"Your Name\" --github "
                  "your-handle\n" % called.invocation())
    else:
        out.write("Nothing needs doing. To see what you would share:\n  %s report "
                  "--preview\n" % called.invocation())
    return 0


def main(argv=None, out=sys.stdout):
    ap = argparse.ArgumentParser(
        prog="guardian status",
        description="What this machine has done. Reads local files and nothing else.")
    ap.add_argument("--home", default=None, help="where records are kept")
    ap.add_argument("--json", action="store_true", help="the same, as JSON")
    a = ap.parse_args([] if argv is None else argv)

    state = gather(home(a.home))
    if a.json:
        printable = {k: v for k, v in state.items() if k != "credit"}
        printable["credited"] = bool(state["credit"])
        out.write(json.dumps(printable, indent=2, sort_keys=True, default=str) + "\n")
        return 0
    return render(state, out)
