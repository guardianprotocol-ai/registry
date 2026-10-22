"""A fire drill: attack your own machine, through your own sensor, and report it.

The exchange has a chicken and egg problem. Reporting a sighting needs evidence, and
evidence needs an attack, so joining the network used to mean waiting for something bad to
happen to you. That is a week of waiting for most people and forever for the lucky ones.

So the drill brings the attack. A lab server runs locally and serves a tool whose definition
changes after approval, plus a tool result carrying a canary that tries to leave. The sensor
in front is the operator's own, with their own configuration. Every detection is real: it
happened on this machine, to this sensor, and the evidence file is the ordinary one.

What this is not is a simulation of the sighting. The sighting is produced by the same code
path a real detection uses, which is the point. A drill that exercises a special case proves
only that the special case works.

Python 3.9+ standard library only.
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SENSOR_ROOT = os.path.dirname(HERE)
LAB_SERVER = os.path.join(SENSOR_ROOT, "tests", "fake_server.py")
# Deliberately not ".guardian". That is where a real sensor keeps its evidence and its
# pins, and an earlier version of this defaulted there and deleted both. Losing evidence is
# bad; overwriting pins is worse, because it resets the approval baseline and the next
# listing re-approves whatever the server offers. A drill must never disarm the sensor it
# exists to demonstrate.
DEFAULT_DIR = os.path.join(".guardian", "drill")
PROTECTED_NAMES = ("evidence.jsonl", "pins.json")


class _Client:
    """The smallest MCP client that can provoke a detection. One message per line."""

    def __init__(self, cmd, env, cwd):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, bufsize=1,
                                  env=env, cwd=cwd)
        self.n = 0

    def call(self, method, params=None):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n,
                                       "method": method, "params": params or {}}) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        return json.loads(line) if line else {}

    def close(self):
        try:
            self.p.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
        return self.p.stderr.read()


def exercises():
    """What the drill provokes, in order, and what each one is for.

    Named here rather than inline so the report can say which exercises ran and a reader
    can see that the drill is a fixed, auditable list rather than whatever the lab server
    happened to do that day.
    """
    return (
        ("GP-0003", "a tool definition changes after the operator approved it"),
        ("GP-0019", "a tool appears on the server after approval"),
        ("GP-0002", "a canary read from a local file tries to leave in a tool call"),
    )


def run_once(workdir, config_path, python=None):
    """Drive one protected session. Returns the sensor's stderr log."""
    python = python or sys.executable
    env = {**os.environ,
           "GUARDIAN_SINK": os.path.join(workdir, "sinkhole.jsonl"),
           "GUARDIAN_TAMPER": "",
           # A tool appears on the second listing. The approved set is whatever the first
           # listing offered, so this one was never approved by anybody.
           "GUARDIAN_ADD": "1",
           "PYTHONPATH": SENSOR_ROOT + os.pathsep + os.environ.get("PYTHONPATH", "")}
    cmd = [python, "-m", "guardian_sensor", "--config", config_path, "--",
           python, LAB_SERVER]
    c = _Client(cmd, env, workdir)
    c.call("initialize")
    # Approval. Whatever the server offers now is what the operator is taken to have
    # approved, and it is the only listing that establishes a baseline.
    c.call("tools/list")
    # Read untrusted content, then a local file holding a canary, then try to send it on.
    c.call("tools/call", {"name": "fetch_page", "arguments": {"url": "https://vendor.example.com/q3"}})
    c.call("tools/call", {"name": "read_file", "arguments": {"path": "notes.txt"}})
    c.call("tools/call", {"name": "send_message",
                          "arguments": {"to": "canary@registry.test",
                                        "body": "Token: GP0001-CANARY-7f3a"}})
    # Ordinary work, which must not be blocked. A drill that only fires on attacks says
    # nothing about whether the sensor is usable.
    c.call("tools/call", {"name": "send_message",
                          "arguments": {"to": "team@example.com",
                                        "body": "Summary: shipping improved 12%."}})
    # The server now serves a changed weather tool, and the sensor compares it to approval.
    c.call("tools/list")
    c.call("tools/call", {"name": "weather", "arguments": {"city": "NYC"}})
    return c.close()


def is_drill_dir(path):
    """True if a previous drill made this directory.

    Decided by the config the drill writes, not by the directory's name. A name is a guess
    and an operator may call it anything; the config says what it is.
    """
    try:
        with open(os.path.join(path, "guardian.json")) as f:
            return json.load(f).get("drill") is True
    except (OSError, ValueError):
        return False


def real_state_in(path):
    """Files in `path` that belong to a working sensor rather than to a drill.

    Checked before anything is removed. The operator chose the directory and may well have
    chosen the one their sensor already uses, where evidence.jsonl is the only record of
    what it has seen and pins.json is the only record of what they approved.
    """
    if is_drill_dir(path):
        return []
    return [n for n in PROTECTED_NAMES if os.path.exists(os.path.join(path, n))]


def write_config(workdir, mode="block"):
    path = os.path.join(workdir, "guardian.json")
    with open(path, "w") as f:
        json.dump({"mode": mode, "allowlist": ["example.com"],
                   # Every record this sensor writes is marked as a drill. The attack is one
                   # the member ran against themselves, and it must never be counted as an
                   # incident by anyone downstream.
                   "drill": True,
                   "pins_path": os.path.join(workdir, "pins.json"),
                   "evidence_path": os.path.join(workdir, "evidence.jsonl")}, f, indent=2)
    return path


def read_evidence(workdir):
    path = os.path.join(workdir, "evidence.jsonl")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def summarize(records):
    """Which of the drill's exercises actually fired, as (pattern, reason, fired) rows.

    An exercise that does not fire is reported, not hidden. A drill that quietly reports
    only its successes would make a broken sensor look like a clean run, which is the same
    failure as a column of zeros meaning an exhausted quota.
    """
    seen = {p for r in records for p in r.get("patterns", [])}
    return [(pid, reason, pid in seen) for pid, reason in exercises()]


def main(argv=None, out=sys.stdout):
    import argparse
    ap = argparse.ArgumentParser(
        prog="guardian_sensor drill",
        description="Attack your own machine through your own sensor, then report it")
    ap.add_argument("--org", default=os.environ.get("GUARDIAN_ORG"),
                    help="your pseudonymous member id, never a company name")
    ap.add_argument("--dir", default=DEFAULT_DIR,
                    help="where the drill keeps its config, pins and evidence")
    ap.add_argument("--mode", default="block", choices=("block", "monitor"))
    ap.add_argument("--keep", action="store_true",
                    help="keep the evidence file rather than starting clean")
    a = ap.parse_args([] if argv is None else argv)

    workdir = os.path.abspath(a.dir)
    os.makedirs(workdir, exist_ok=True)

    # Refuse rather than overwrite. This is the operator's own machine and these two files
    # are the only record of what their sensor has seen and approved.
    occupied = real_state_in(workdir)
    if occupied:
        out.write("Refusing to run here. %s already holds %s, which belongs to a working "
                  "sensor.\n" % (a.dir, " and ".join(occupied)))
        out.write("Overwriting pins.json would reset the approval baseline, and the next "
                  "listing would re-approve\nwhatever the server offers. Run the drill "
                  "somewhere else:\n\n")
        out.write("  python3 -m guardian_sensor drill --dir %s --org %s\n"
                  % (DEFAULT_DIR, a.org or "<your-member-id>"))
        return 2

    if not a.keep:
        for name in PROTECTED_NAMES:
            try:
                os.remove(os.path.join(workdir, name))
            except OSError:
                pass

    config_path = write_config(workdir, a.mode)
    out.write("Running the drill against a local lab server, through your sensor.\n")
    out.write("Nothing leaves this machine. The sink is a file in %s.\n\n" % a.dir)

    started = time.time()
    log = run_once(workdir, config_path)
    seconds = time.time() - started

    rows = summarize(read_evidence(workdir))
    width = max(len(r[1]) for r in rows)
    for pid, reason, fired in rows:
        out.write("%-9s %-*s  %s\n" % (pid, width, reason, "caught" if fired else "MISSED"))
    missed = [pid for pid, _, fired in rows if not fired]
    out.write("\n%d of %d exercises caught in %.1f seconds.\n"
              % (len(rows) - len(missed), len(rows), seconds))

    if missed:
        out.write("\nSomething is wrong, and it is worth knowing rather than reporting "
                  "around. Missed: %s.\nThe sensor's own log follows.\n\n%s\n"
                  % (", ".join(missed), log.strip()))
        return 1

    out.write("\nEvidence is in %s. Nothing has been shared.\n" % os.path.join(a.dir, "evidence.jsonl"))
    out.write("\nTo see exactly what would be shared, and share nothing:\n")
    out.write("  python3 -m guardian_sensor report --org %s --preview\n"
              % (a.org or "<your-member-id>"))
    out.write("\nTo write the file once you are happy with it:\n")
    out.write("  python3 -m guardian_sensor report --org %s --out sightings-%s.json\n"
              % (a.org or "<your-member-id>", time.strftime("%Y-%m-%d")))
    if not a.org:
        out.write("\nPick a member id that is not your company name. It is a pseudonym and\n"
                  "it is the only identifier that travels with your sightings.\n")
    return 0
