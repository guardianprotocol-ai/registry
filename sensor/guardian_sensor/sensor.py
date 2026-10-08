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

from . import rules

DEFAULT_CONFIG = {
    "mode": "block",                 # "block" or "monitor"
    "allowlist": [],                 # domains data may be sent to
    "pins_path": ".guardian/pins.json",
    "evidence_path": ".guardian/evidence.jsonl",
    "max_repeat": 10,                # identical calls allowed per session (GP-0011)
}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class Sensor:
    def __init__(self, config: dict):
        self.cfg = {**DEFAULT_CONFIG, **config}
        self.state = {"tainted_by": None, "counts": {}}
        self.pending = {}            # request id -> (method, params)
        self.blocked_tools = set()
        self.pins = self._load_json(self.cfg["pins_path"], {})
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
               "action": action, "detail": detail, "sensor": "guardian-sensor v0 (prototype)"}
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
        for pid, d in found:
            detail.update(d)
        hits = [pid for pid, _ in found]

        if not hits:
            return None
        action = "blocked" if self.cfg["mode"] == "block" else "flagged"
        self.evidence(sorted(set(hits)), action, detail)
        if action == "flagged":
            return None
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "isError": True,
            "content": [{"type": "text", "text": f"Blocked by Guardian sensor ({', '.join(sorted(set(hits)))}). "
                                                 "This action was stopped because it matches a known attack pattern."}]}}

    # ---------- server -> client ----------
    def inspect_response(self, msg):
        mid = msg.get("id")
        method, params = self.pending.pop(mid, (None, None))
        result = msg.get("result") or {}
        if method == "tools/list":
            changed = False
            for tool in result.get("tools", []):
                name, fp = tool.get("name"), rules.tool_fingerprint(tool)
                if name not in self.pins:
                    self.pins[name] = fp
                    changed = True
                elif self.pins[name] != fp:
                    self.blocked_tools.add(name)
                    self.evidence(["GP-0003"], "blocked" if self.cfg["mode"] == "block" else "flagged",
                                  {"tool": name, "reason": "definition changed since approval"})
                if rules.has_instructions(tool.get("description", "")):
                    self.evidence(["GP-0003"], "flagged", {"tool": name, "reason": "description contains instructions"})
            if changed:
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


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if args[:1] and args[0] in HUB_COMMANDS:
        from . import hub_cli
        return hub_cli.main(args)

    ap = argparse.ArgumentParser(prog="guardian_sensor")
    ap.add_argument("--config", default=None)
    ap.add_argument("server", nargs=argparse.REMAINDER)
    a = ap.parse_args(args)
    server_cmd = a.server[1:] if a.server[:1] == ["--"] else a.server
    if not server_cmd:
        ap.error("give the real MCP server command after --")
    cfg = json.load(open(a.config)) if a.config else {}
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
