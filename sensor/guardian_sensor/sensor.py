"""Guardian sensor v0: an MCP stdio proxy (prototype).

Sits between an MCP client (Claude Code, Codex, Cursor, any agent) and a real MCP
server. It relays every JSON-RPC message and applies the registry's detections:

  * tools/list results: pins each tool definition; blocks tools whose definition
    changed after approval, flags descriptions containing instructions (GP-0003)
  * tools/call results: notes when a tool's output carried instructions (taint)
  * tools/call results: flags hidden content (GP-0006) and source steering (GP-0010)
  * tools/call requests: after taint, blocks sends outside the allow-list (GP-0001),
    destructive calls (GP-0005), memory writes with instructions (GP-0004), credential
    file reads (GP-0007), instructions passed to other agents (GP-0008) and writes of
    instructions into shared files or agent config (GP-0009); always blocks secrets and
    canaries in arguments (GP-0002, GP-0012) and runaway repetition (GP-0011)

Usage in an MCP client config, wrapping a real server:
  python3 -m guardian_sensor --config guardian.json -- <real server command...>

Fails open: if the sensor itself hits an error on a message, it relays the message
unchanged and logs the fault. Prototype, not for production data.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import threading

from . import canaries
from . import rules

DEFAULT_CONFIG = {
    "mode": "block",                 # "block" or "monitor"
    "allowlist": [],                 # domains data may be sent to
    "pins_path": ".guardian/pins.json",
    "evidence_path": ".guardian/evidence.jsonl",
    "max_repeat": 10,                # identical calls allowed per session (GP-0011)
    "canaries_path": ".guardian/canaries.json",
}


# One refusal, the same for every rule. Naming the rule that fired is an oracle: an attacker
# holding a set of stolen credentials can send them one at a time and learn which are
# registered canaries from the answers, then exfiltrate only the real ones. That turns a
# canary into a filter that helps them.
#
# Naming every rule except canaries does not fix it, because then the unnamed answer is
# itself the signal. Two distinguishable refusals are an oracle whatever the wording, so
# there is one.
#
# The cost is that a developer whose legitimate work is blocked is not told why in the
# response. They are told where to look, and the reason is already there in full, on their
# own machine, with the tool name and the matching detail. That is a better trade than
# telling an adversary which of their stolen keys is the fake one.
REFUSAL = ("Blocked by Guardian sensor. This action was stopped by local policy. "
           "The reason, including which rule matched, is recorded in this machine's "
           "Guardian evidence log.")


def _refusal(hits):
    """What the agent is told when a call is refused. The same for every rule, deliberately.

    `hits` is accepted and not used, so that a future change has to delete this argument on
    purpose rather than discover that varying the response by rule is an oracle.
    """
    return REFUSAL


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class Sensor:
    def __init__(self, config: dict):
        self.cfg = {**DEFAULT_CONFIG, **config}
        self.state = {"tainted_by": None, "counts": {}}
        self.pending = {}            # request id -> (method, params)
        self.blocked_tools = set()
        self.pins = self._load_json(self.cfg["pins_path"], {})
        # Loaded once. A canary list that changed mid-session would make the evidence
        # ambiguous about what was being watched for at the moment of a detection.
        try:
            self.canaries = canaries.load(self.cfg["canaries_path"])
        except canaries.CanaryError as e:
            # A broken canary file must not silently mean "watch for nothing". The sensor
            # keeps running, because its other checks still protect, and says so loudly.
            sys.stderr.write("[guardian] canary file unusable, registered canaries are NOT "
                             "being watched for: %s\n" % e)
            self.canaries = {"canaries": []}
        # Whether a baseline exists. The first listing is the operator approving the server
        # as it stands, so every tool in it is pinned. Every listing after that is compared
        # against the baseline, which is the only moment a tool appearing can be seen as an
        # addition rather than as a first sighting.
        self.approved = bool(self.pins)
        self.lock = threading.Lock()

    # ---------- storage ----------
    def _load_json(self, path, default):
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return default

    def _save_pins(self):
        os.makedirs(os.path.dirname(self.cfg["pins_path"]) or ".", exist_ok=True)
        with open(self.cfg["pins_path"], "w") as f:
            json.dump(self.pins, f, indent=2)

    def evidence(self, pattern_ids, action, detail):
        rec = {"time": now(), "patterns": pattern_ids, "reasons": [rules.RULES[p] for p in pattern_ids],
               "action": action, "detail": detail, "sensor": "guardian-sensor v0 (prototype)",
               # Which rule bundle was actually loaded, so a sighting cannot claim a rule
               # set the sensor was not running. A sensor pointed at a stripped bundle
               # otherwise produces evidence that looks fully armed.
               "rules_fingerprint": rules.signatures_fingerprint()}
        # Marked here, at the moment of detection, because this is the only place that knows
        # for certain. Anything deciding later would be guessing, and a drill mistaken for an
        # incident is the one error this whole project cannot afford to publish.
        if self.cfg.get("drill"):
            rec["drill"] = True
        os.makedirs(os.path.dirname(self.cfg["evidence_path"]) or ".", exist_ok=True)
        with open(self.cfg["evidence_path"], "a") as f:
            f.write(json.dumps(rec) + "\n")
        sys.stderr.write(f"[guardian] {action.upper()} {', '.join(pattern_ids)}: {json.dumps(detail)}\n")
        return rec

    # ---------- client -> server ----------
    def inspect_request(self, msg):
        """Return a JSON-RPC response to send back instead of forwarding, or None to forward."""
        method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if mid is not None and method:
            self.pending[mid] = (method, params)
        if method != "tools/call":
            return None
        name, args = params.get("name"), params.get("arguments") or {}
        detail = {"tool": name}
        found = rules.check_call(name, args, self.state, self.cfg)
        if name in self.blocked_tools:
            found.append(("GP-0003", {"reason": "tool definition changed since approval"}))

        # A canary the operator registered, found in what is about to leave. Checked here,
        # before the call is forwarded, because afterwards the value has already gone.
        hit_canaries = canaries.matches(self.canaries, rules.text_of(args))
        armed = [c for c in hit_canaries if c["state"] == canaries.ARMED]
        for c in hit_canaries:
            found.append(("GP-0020", canaries.redacted(c)))

        for pid, d in found:
            detail.update(d)
        hits = [pid for pid, _ in found]

        if not hits:
            return None
        action = "blocked" if self.cfg["mode"] == "block" else "flagged"
        # A canary still in baseline reports and does not block, whatever the mode. It has
        # not yet been shown that ordinary work leaves it alone, and the first thing an
        # operator learns from a badly placed canary should not be that their agent stopped
        # working. A canary the operator armed blocks like anything else.
        #
        # Compared as a set. An earlier version compared the list, so two canaries firing at
        # once produced ["GP-0020", "GP-0020"], missed the comparison and blocked. Baseline
        # quietly stopped being baseline on the day an operator registered a second canary,
        # which is precisely the surprise this is here to prevent.
        if set(hits) == {"GP-0020"} and not armed:
            action = "flagged"
        self.evidence(sorted(set(hits)), action, detail)
        if action == "flagged":
            return None
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "isError": True,
            "content": [{"type": "text", "text": _refusal(hits)}]}}

    # ---------- server -> client ----------
    def inspect_response(self, msg):
        mid = msg.get("id")
        method, params = self.pending.pop(mid, (None, None))
        result = msg.get("result") or {}
        if method == "tools/list":
            changed = False
            blocking = "blocked" if self.cfg["mode"] == "block" else "flagged"
            listed = []
            for tool in result.get("tools", []):
                name, fp = tool.get("name"), rules.tool_fingerprint(tool)
                listed.append(name)
                if name not in self.pins and not self.approved:
                    # Approval. Nothing to compare against yet, so this is the baseline.
                    self.pins[name] = fp
                    changed = True
                elif name not in self.pins:
                    # A tool that was not there when the operator approved the server. The
                    # operator never saw it, so it cannot have been approved, and a server
                    # that can add a tool silently can add any tool at all. Pinning it here
                    # would approve it on the operator's behalf, which is what this sensor
                    # exists to prevent.
                    self.blocked_tools.add(name)
                    self.evidence(["GP-0019"], blocking,
                                  {"tool": name, "reason": "tool appeared after approval"})
                elif self.pins[name] != fp:
                    self.blocked_tools.add(name)
                    self.evidence(["GP-0003"], blocking,
                                  {"tool": name, "reason": "definition changed since approval"})
                if rules.has_instructions(tool.get("description", "")):
                    self.evidence(["GP-0003"], "flagged", {"tool": name, "reason": "description contains instructions"})
            # A tool that disappears is reported and never unpinned. Removing the pin would
            # let a server drop a tool and reintroduce it as a first sighting, which turns
            # the check above into something an attacker can step around at will.
            for gone in sorted(set(self.pins) - set(listed)):
                if gone not in self.blocked_tools:
                    self.evidence(["GP-0019"], "flagged",
                                  {"tool": gone, "reason": "approved tool no longer listed"})
            if changed:
                self.approved = True
                self._save_pins()
        elif method == "tools/call":
            text = " ".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict))
            source = (params or {}).get("name")
            for pid, d in rules.check_output(source, text, self.state):
                self.evidence([pid], "flagged", {"tool": source, **d})
        return msg


def pump(src, dst, handler, sensor, reply_to=None):
    for line in src:
        try:
            msg = json.loads(line)
            out = handler(msg)
            if isinstance(out, dict) and out is not msg and reply_to is not None:
                reply_to.write(json.dumps(out) + "\n")
                reply_to.flush()
                continue
        except Exception as e:  # fail open
            sys.stderr.write(f"[guardian] sensor fault, relaying unchanged: {e}\n")
        try:
            dst.write(line if line.endswith("\n") else line + "\n")
            dst.flush()
        except (BrokenPipeError, ValueError):
            # The other end has gone: the server exited, or the client hung up. Relaying
            # further is pointless and raising here would crash the proxy on a normal
            # disconnect, which the client sees as the sensor breaking its MCP server.
            sys.stderr.write("[guardian] the other end closed the pipe, stopping the relay\n")
            return


# The sharing hub commands. Anything else is the proxy, so the way the sensor has always
# been started keeps working unchanged.
HUB_COMMANDS = ("report", "update")
DRILL_COMMAND = "drill"
CANARY_COMMAND = "canary"
AGENDA_COMMAND = "agenda"
ENROLL_COMMAND = "enroll"
CREDIT_COMMAND = "credit"


COMMANDS = (
    ("drill", "attack your own machine through your own sensor, and see what it caught"),
    ("canary", "register values the sensor should watch for: add, list, arm, remove"),
    ("enroll", "take part in scheduled exercises. Installs once, then nothing"),
    ("agenda", "run a published exercise when its time has come. Safe to run often"),
    ("report", "build an anonymized sightings file, previewing it first"),
    ("update", "fetch and verify a published rule set"),
    ("credit", "record how you want to be credited in the research"),
)


def usage(out=sys.stdout):
    """What this can do, which was previously findable only by reading the source.

    argparse showed the proxy's own options and nothing else, so a participant running
    --help saw no mention of any of the commands below. For a tool being handed to people
    who have not read the repository, that is the difference between usable and not.
    """
    width = max(len(name) for name, _ in COMMANDS)
    out.write("Guardian sensor. An MCP proxy, and the commands around it.\n\n")
    out.write("  python3 -m guardian_sensor <command> [options]\n\n")
    for name, what in COMMANDS:
        out.write("  %-*s  %s\n" % (width, name, what))
    out.write("\nEach command explains itself with --help.\n")
    out.write("\nAs a proxy, with the real server after a double dash:\n\n")
    out.write("  python3 -m guardian_sensor --config guardian.json -- <server command>\n")
    out.write("\nStart here if you are new:\n\n")
    out.write("  python3 -m guardian_sensor drill --org <a-pseudonym-you-choose>\n")
    return 0


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    # Before argparse, because argparse would answer --help with the proxy's options and
    # never mention a command. A bare invocation asks for help rather than erroring.
    if not args or args[0] in ("help", "--help", "-h", "commands"):
        if not args or args[0] in ("help", "commands") or len(args) == 1:
            return usage()
    if args[:1] and args[0] in HUB_COMMANDS:
        from . import hub_cli
        return hub_cli.main(args)
    if args[:1] == [DRILL_COMMAND]:
        from . import drill
        return drill.main(args[1:])
    if args[:1] == [CANARY_COMMAND]:
        from . import canary_cli
        return canary_cli.main(args[1:])
    if args[:1] == [AGENDA_COMMAND]:
        from . import agenda
        return agenda.main(args[1:])
    if args[:1] == [ENROLL_COMMAND]:
        from . import enroll
        return enroll.main(args[1:])
    if args[:1] == [CREDIT_COMMAND]:
        from . import credit
        return credit.main(args[1:])

    # A word that is not a command and not a flag, with no -- anywhere, is a mistyped
    # command rather than a server to launch. Without this it falls through to the proxy and
    # the person is told their MCP server could not be started, which is true and useless:
    # they typed "scan" and got an error about executables.
    known = {name for name, _ in COMMANDS}
    if (args and not args[0].startswith("-") and args[0] not in known
            and "--" not in args and "/" not in args[0] and os.sep not in args[0]):
        sys.stderr.write("There is no %r command.\n\n" % args[0])
        close = [name for name in sorted(known)
                 if name.startswith(args[0][:2]) or args[0][:2] in name]
        if close:
            sys.stderr.write("Did you mean: %s\n\n" % ", ".join(close))
        usage(sys.stderr)
        return 2

    ap = argparse.ArgumentParser(prog="guardian_sensor")
    ap.add_argument("--config", default=None)
    ap.add_argument("server", nargs=argparse.REMAINDER)
    a = ap.parse_args(args)
    server_cmd = a.server[1:] if a.server[:1] == ["--"] else a.server
    if not server_cmd:
        ap.error("give the real MCP server command after --")
    # Hand edited by whoever set this up, so a typo in it is the common case rather than the
    # exotic one. A JSONDecodeError traceback tells somebody their config is broken in the
    # least useful way available.
    cfg = {}
    if a.config:
        try:
            with open(a.config) as f:
                cfg = json.load(f)
        except OSError as e:
            raise SystemExit("cannot read the config %s: %s. Point --config at a file that "
                             "exists, or leave it out to use the defaults." % (a.config, e))
        except ValueError as e:
            raise SystemExit("the config %s is not valid JSON: %s. A trailing comma or a "
                             "missing quote is the usual cause." % (a.config, e))
        if not isinstance(cfg, dict):
            raise SystemExit("the config %s should be a JSON object, like "
                             '{"mode": "block"}.' % a.config)
    sensor = Sensor(cfg)

    try:
        proc = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                text=True, bufsize=1)
    except OSError as e:
        raise SystemExit(f"cannot start the MCP server {' '.join(server_cmd)!r}: {e}. "
                         "The command after -- is run as given, so check the name and that it "
                         "is installed and executable.")
    t = threading.Thread(target=pump, args=(proc.stdout, sys.stdout, sensor.inspect_response, sensor), daemon=True)
    t.start()
    pump(sys.stdin, proc.stdin, sensor.inspect_request, sensor, reply_to=sys.stdout)
    _shut_down(proc)
    t.join(timeout=5)
    return 0


def _shut_down(proc, grace=5):
    """Close stdin and make sure the server is actually gone.

    A server that does not exit when its stdin closes used to raise TimeoutExpired out of
    main, which left the client looking at a stack trace and left the server running as an
    orphan holding the pipes open. One per session adds up over a working day.
    """
    try:
        proc.stdin.close()
    except (BrokenPipeError, OSError):
        pass
    for stop in (None, proc.terminate, proc.kill):
        if stop is not None:
            stop()
        try:
            return proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            if stop is None:
                sys.stderr.write("[guardian] the MCP server did not exit when the client "
                                 "disconnected, stopping it\n")
    return proc.poll()


if __name__ == "__main__":
    main()
