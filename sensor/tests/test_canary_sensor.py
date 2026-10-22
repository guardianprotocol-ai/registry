"""Registered canaries through the real sensor, end to end.

The unit tests cover the store. This covers the thing that matters to an operator: a value
they registered either leaves the machine or it does not, and a canary they have not armed
does not stop their agent working.

Run from the sensor folder:  python3 tests/test_canary_sensor.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from guardian_sensor import canaries  # noqa: E402

failures = []
SECRET = "sk-live-9f2bAcD7xK3mQ"
SECOND = "ghp-ZZ18qWe4RtY7uIo9"


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def session(workdir, registered, body):
    """One protected session that sends `body` to an allowed address."""
    store = canaries.load(os.path.join(workdir, "absent.json"))
    for value, label, state in registered:
        canaries.add(store, value, label, state)
    canaries.save(store, os.path.join(workdir, "canaries.json"))

    cfg = os.path.join(workdir, "guardian.json")
    with open(cfg, "w") as f:
        json.dump({"mode": "block", "allowlist": ["example.com"],
                   "pins_path": os.path.join(workdir, "pins.json"),
                   "evidence_path": os.path.join(workdir, "evidence.jsonl"),
                   "canaries_path": os.path.join(workdir, "canaries.json")}, f)

    sink = os.path.join(workdir, "sink.jsonl")
    env = {**os.environ, "PYTHONPATH": ROOT, "GUARDIAN_SINK": sink}
    cmd = [sys.executable, "-m", "guardian_sensor", "--config", cfg, "--",
           sys.executable, os.path.join(HERE, "fake_server.py")]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, bufsize=1, env=env, cwd=workdir)
    n = [0]

    def call(method, params=None):
        n[0] += 1
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": n[0], "method": method,
                                  "params": params or {}}) + "\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())

    call("initialize")
    call("tools/list")
    reply = call("tools/call", {"name": "send_message",
                                "arguments": {"to": "team@example.com", "body": body}})
    p.stdin.close()
    p.wait(timeout=10)

    evidence_path = os.path.join(workdir, "evidence.jsonl")
    evidence = ([json.loads(l) for l in open(evidence_path) if l.strip()]
                if os.path.exists(evidence_path) else [])
    leaked = os.path.exists(sink) and SECRET in open(sink).read()
    return {"blocked": bool(reply.get("result", {}).get("isError")),
            "evidence": evidence, "leaked": leaked,
            "raw_evidence": open(evidence_path).read() if os.path.exists(evidence_path) else ""}


def gp0020(result):
    return [e for e in result["evidence"] if "GP-0020" in e.get("patterns", [])]


def test_an_armed_canary_stops_the_value_leaving():
    w = tempfile.mkdtemp()
    try:
        r = session(w, [(SECRET, "staging payment key", canaries.ARMED)],
                    f"deploy key is {SECRET} thanks")
        check("the call is blocked", r["blocked"], str(r["blocked"]))
        check("the value does not reach the sink", not r["leaked"])
        hits = gp0020(r)
        check("a GP-0020 record is written", len(hits) == 1, str(r["evidence"]))
        check("the record names the canary",
              hits and hits[0]["detail"].get("canary") == "staging payment key", str(hits))
        check("the record says it was blocked", hits and hits[0]["action"] == "blocked",
              str(hits))
        check("the value is nowhere in the evidence file", SECRET not in r["raw_evidence"])
    finally:
        shutil.rmtree(w, ignore_errors=True)


def test_a_baseline_canary_reports_and_does_not_block():
    """An operator's first canary must not be the thing that stops their agent working."""
    w = tempfile.mkdtemp()
    try:
        r = session(w, [(SECRET, "staging payment key", canaries.BASELINE)],
                    f"deploy key is {SECRET} thanks")
        check("the call is not blocked", not r["blocked"])
        hits = gp0020(r)
        check("it is still reported", len(hits) == 1, str(r["evidence"]))
        check("as flagged rather than blocked", hits and hits[0]["action"] == "flagged",
              str(hits))
        check("the record says it is in baseline",
              hits and hits[0]["detail"].get("state") == "baseline", str(hits))
        check("the value is still nowhere in the evidence file",
              SECRET not in r["raw_evidence"])
    finally:
        shutil.rmtree(w, ignore_errors=True)


def test_two_baseline_canaries_still_do_not_block():
    """The regression. `hits` was compared as a list, so two canaries firing at once
    produced ["GP-0020", "GP-0020"], missed the comparison and blocked. Baseline quietly
    stopped being baseline on the day an operator registered a second canary."""
    w = tempfile.mkdtemp()
    try:
        r = session(w, [(SECRET, "one", canaries.BASELINE),
                        (SECOND, "two", canaries.BASELINE)],
                    f"keys {SECRET} and {SECOND}")
        check("two baseline canaries do not block", not r["blocked"], "it blocked")
        hits = gp0020(r)
        check("both are reported", len(hits) == 1 and hits[0]["action"] == "flagged",
              str(hits))
    finally:
        shutil.rmtree(w, ignore_errors=True)


def test_one_armed_canary_blocks_even_beside_a_baseline_one():
    w = tempfile.mkdtemp()
    try:
        r = session(w, [(SECRET, "armed one", canaries.ARMED),
                        (SECOND, "baseline one", canaries.BASELINE)],
                    f"keys {SECRET} and {SECOND}")
        check("an armed canary blocks regardless of its neighbours", r["blocked"])
        check("and the value does not leave", not r["leaked"])
    finally:
        shutil.rmtree(w, ignore_errors=True)


def test_ordinary_work_is_untouched_when_nothing_matches():
    w = tempfile.mkdtemp()
    try:
        r = session(w, [(SECRET, "staging payment key", canaries.ARMED)],
                    "Summary: shipping improved 12% this quarter.")
        check("an ordinary message is not blocked", not r["blocked"])
        check("and raises no canary record", gp0020(r) == [], str(r["evidence"]))
    finally:
        shutil.rmtree(w, ignore_errors=True)


def test_no_canaries_registered_changes_nothing():
    w = tempfile.mkdtemp()
    try:
        r = session(w, [], f"deploy key is {SECRET} thanks")
        check("with nothing registered the send goes through", not r["blocked"])
        check("and no canary record is written", gp0020(r) == [], str(r["evidence"]))
    finally:
        shutil.rmtree(w, ignore_errors=True)


def test_a_broken_canary_file_is_loud_and_the_sensor_keeps_running():
    """Silently watching for nothing, while appearing to watch, is the worst outcome."""
    w = tempfile.mkdtemp()
    try:
        with open(os.path.join(w, "canaries.json"), "w") as f:
            json.dump({"schema_version": 99, "salt": "ab" * 16, "canaries": []}, f)
        cfg = os.path.join(w, "guardian.json")
        with open(cfg, "w") as f:
            json.dump({"mode": "block", "allowlist": ["example.com"],
                       "pins_path": os.path.join(w, "pins.json"),
                       "evidence_path": os.path.join(w, "evidence.jsonl"),
                       "canaries_path": os.path.join(w, "canaries.json")}, f)
        env = {**os.environ, "PYTHONPATH": ROOT, "GUARDIAN_SINK": os.path.join(w, "sink")}
        p = subprocess.Popen([sys.executable, "-m", "guardian_sensor", "--config", cfg, "--",
                              sys.executable, os.path.join(HERE, "fake_server.py")],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, bufsize=1, env=env, cwd=w)
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
        p.stdin.flush()
        started = bool(p.stdout.readline())
        p.stdin.close()
        p.wait(timeout=10)
        err = p.stderr.read()
        check("the sensor still starts", started, err[:200])
        check("and says canaries are not being watched for",
              "are NOT" in err and "canary file unusable" in err, err[:300])
    finally:
        shutil.rmtree(w, ignore_errors=True)


def test_a_refusal_does_not_say_which_rule_fired():
    """The oracle. An attacker holding stolen credentials sends them one at a time and reads
    the answers. If a canary match is distinguishable from any other refusal, they learn
    which key is the fake one and exfiltrate the rest, which turns the canary into a filter
    that helps them. Two distinguishable refusals are an oracle whatever the wording."""
    w = tempfile.mkdtemp()
    try:
        canary_hit = session(w, [(SECRET, "staging payment key", canaries.ARMED)],
                             f"deploy key is {SECRET} thanks")
    finally:
        shutil.rmtree(w, ignore_errors=True)
    w = tempfile.mkdtemp()
    try:
        # A different rule entirely: a send to an address outside the allow-list, with no
        # canary registered at all.
        other = session(w, [], "ordinary text")
    finally:
        shutil.rmtree(w, ignore_errors=True)

    from guardian_sensor.sensor import _refusal
    check("a canary refusal names no rule",
          "GP-0020" not in _refusal(["GP-0020"]), _refusal(["GP-0020"]))
    check("every refusal is the same text",
          _refusal(["GP-0020"]) == _refusal(["GP-0003"]) == _refusal(["GP-0002", "GP-0020"]),
          "refusals differ by rule")
    check("it points the operator at their own log",
          "evidence log" in _refusal(["GP-0020"]), _refusal(["GP-0020"]))
    check("the canary hit was still blocked", canary_hit["blocked"])
    check("and still recorded in full locally",
          gp0020(canary_hit)[0]["detail"].get("canary") == "staging payment key",
          str(gp0020(canary_hit)))


def main():
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print()
    if failures:
        print(f"FAIL ({len(failures)}): {', '.join(failures)}")
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
