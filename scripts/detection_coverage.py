#!/usr/bin/env python3
"""Detection coverage: replay existing fixtures through the MCP proxy sensor itself, and
report which patterns in the catalog were detected, which were blocked, and which have no
fixture at all.

    python3 scripts/detection_coverage.py           print the report
    python3 scripts/detection_coverage.py --json    the same, machine readable
    python3 scripts/detection_coverage.py --write   regenerate docs/DETECTION_COVERAGE.md
    python3 scripts/detection_coverage.py --check   fail if a fixture is no longer detected,
                                                    or if the page is out of date

This is defensive regression testing. It authors nothing: every fixture is an existing
corpus case in corpus/attacks/ or corpus/benign/, or an existing mode of the test MCP
server in sensor/tests/fake_server.py. Canary tokens and .test destinations only.

What it adds to scripts/rule_gate.py. The gate calls the shared rule engine directly,
which is the right test for a rule. This drives the sensor's own request path:
Sensor.inspect_request decides block or forward and Sensor.inspect_response sets taint,
exactly as the stdio pump calls them, so it measures what the proxy does with a hit
(blocked, flagged, or forwarded) and what it records as evidence, including the parts the
rule engine does not own: the refusal, the canary matcher and the baseline rule. Tool
definition patterns (GP-0003, GP-0019), which the gate cannot replay, are run through the
real proxy process in front of the test server, and the server's own call log is the
ground truth for whether the call arrived. And it reports over the whole pattern catalog
with its MITRE ATLAS mapping, so a pattern with no fixture shows up as a gap rather than
as silence.

Kept small on purpose: at most two attack fixtures per pattern, chosen by file name, so
the run takes about a second and the same tree always gives the same report.

A replayed fixture shows the sensor still catches a known, scripted case. It is not a
detection rate, not a pentest, and not evidence of catching anything in the wild.

Python 3.9+ standard library only.
"""
import argparse
import atexit
import contextlib
import glob
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SENSOR_DIR = os.path.join(ROOT, "sensor")
CORPUS = os.path.join(ROOT, "corpus")
PATTERNS = os.path.join(ROOT, "patterns")
FAKE_SERVER = os.path.join(SENSOR_DIR, "tests", "fake_server.py")
PAGE = os.path.join(ROOT, "docs", "DETECTION_COVERAGE.md")
MAX_PER_PATTERN = 2

# The two tool definition patterns, as modes the test server already has. Each lists the
# tools twice: the first listing is approval, the second is what changed after it.
SERVER_FIXTURES = [
    {"id": "fake-server-tampered-weather", "expect": "GP-0003",
     "description": "The weather tool's description changes after approval.",
     "env": {}, "call": {"name": "weather", "arguments": {"city": "NYC"}}},
    {"id": "fake-server-tool-added-after-approval", "expect": "GP-0019",
     "description": "A tool appears on the second listing that was not approved.",
     "env": {"GUARDIAN_ADD": "1"},
     "call": {"name": "diagnostics_upload", "arguments": {"payload": "diagnostics"}}},
]

# Why a pattern with a sensor rule has no fixture here. Anything not named is a plain gap.
NO_FIXTURE_NOTES = {
    "GP-0020": "registered canaries are each operator's own values, so no corpus case can "
               "carry one; measured by benchmarks/canary_benchmark.py",
    "GP-0041": "path and seeded-record canaries need an operator's registered files; "
               "measured by benchmarks/assumed_breach.py",
}


def _isolate():
    """Pin the run to this repository's rules and a throwaway home, before any import.

    The sensor prefers a rule bundle the member adopted and merges a member's own
    patterns, which is right for a sensor and wrong for a report about this tree.
    """
    os.environ["GUARDIAN_SIGNATURES"] = os.path.join(SENSOR_DIR, "guardian_sensor",
                                                     "signatures.json")
    home = tempfile.mkdtemp(prefix="guardian-coverage-home-")
    atexit.register(shutil.rmtree, home, True)
    os.environ["GUARDIAN_HOME"] = home
    sys.path.insert(0, SENSOR_DIR)
    sys.path.insert(0, os.path.join(ROOT, "scanner"))
    return home


def load_catalog():
    """Every pattern: id, title, status, ATLAS technique ids."""
    from guardian_scanner import yamlish
    catalog = []
    for path in sorted(glob.glob(os.path.join(PATTERNS, "GP-*.yaml"))):
        doc = yamlish.load_file(path)
        atlas = ((doc.get("maps_to") or {}).get("atlas")) or []
        catalog.append({
            "id": doc["id"], "title": doc.get("title", ""), "status": doc.get("status"),
            "atlas": [str(a).split()[0] for a in atlas],
        })
    return catalog


def load_cases(kind):
    cases = []
    for path in sorted(glob.glob(os.path.join(CORPUS, kind, "*.json"))):
        with open(path, encoding="utf-8") as f:
            case = json.load(f)
        case["_file"] = os.path.relpath(path, ROOT)
        cases.append(case)
    return cases


def select_fixtures(attacks):
    """At most MAX_PER_PATTERN cases per expected pattern, first by file name."""
    chosen, seen = [], {}
    for case in attacks:
        n = seen.get(case["expect"], 0)
        if n < MAX_PER_PATTERN:
            chosen.append(case)
            seen[case["expect"]] = n + 1
    return chosen


def _sensor_config(work, policy, case):
    cfg = {"mode": "block",
           "pins_path": os.path.join(work, "pins.json"),
           "evidence_path": os.path.join(work, "evidence.jsonl"),
           "canaries_path": os.path.join(work, "canaries.json"),
           "path_canaries_path": os.path.join(work, "path-canaries.json"),
           "breach_policy_path": os.path.join(work, "breach-policy.json")}
    cfg.update(policy.get("default_config", {}))
    cfg.update(case.get("config", {}))
    return cfg


def _evidence(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def replay_case(case, policy):
    """Drive one corpus case through Sensor.inspect_request and inspect_response.

    An `output` event is a tools/call to its source tool, forwarded, then the server's
    result coming back through inspect_response, which is where taint is set. A `call`
    event is a tools/call through inspect_request, which returns a refusal or None.
    """
    from guardian_sensor.sensor import Sensor
    with tempfile.TemporaryDirectory(prefix="guardian-coverage-") as work:
        cfg = _sensor_config(work, policy, case)
        refused = forwarded = 0
        with contextlib.redirect_stderr(io.StringIO()):
            sensor = Sensor(cfg)
            mid = 0
            for event in case["events"]:
                if "output" in event:
                    o = event["output"]
                    mid += 1
                    request = {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                               "params": {"name": o["source"], "arguments": {}}}
                    if sensor.inspect_request(request) is not None:
                        refused += 1
                        continue
                    sensor.inspect_response({"jsonrpc": "2.0", "id": mid, "result": {
                        "content": [{"type": "text", "text": o["text"]}]}})
                elif "call" in event:
                    c = event["call"]
                    for _ in range(c.get("times", 1)):
                        mid += 1
                        out = sensor.inspect_request(
                            {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                             "params": {"name": c["name"], "arguments": c["args"]}})
                        if out is not None:
                            refused += 1
                        else:
                            forwarded += 1
                else:
                    raise ValueError("%s: unknown event %s" % (case["_file"], list(event)))
        records = _evidence(cfg["evidence_path"])
    return _verdict(case.get("expect"), records, refused)


def _verdict(expect, records, refused):
    raised = sorted({p for r in records for p in r["patterns"]})
    blocked = sorted({p for r in records if r["action"] == "blocked" for p in r["patterns"]})
    if expect is None:
        outcome = "blocked" if refused else ("flagged" if raised else "forwarded")
    elif expect in blocked and refused:
        outcome = "blocked"
    elif expect in raised:
        outcome = "flagged"
    else:
        outcome = "missed"
    return {"outcome": outcome, "raised": raised, "refused_calls": refused}


def replay_server_fixture(fixture):
    """The real proxy process in front of the test server, as a client would run it."""
    with tempfile.TemporaryDirectory(prefix="guardian-coverage-") as work:
        cfg_path = os.path.join(work, "guardian.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump({"mode": "block", "allowlist": ["example.com"],
                       "pins_path": os.path.join(work, "pins.json"),
                       "evidence_path": os.path.join(work, "evidence.jsonl"),
                       "canaries_path": os.path.join(work, "canaries.json"),
                       "path_canaries_path": os.path.join(work, "path-canaries.json"),
                       "breach_policy_path": os.path.join(work, "breach-policy.json")}, f)
        calls_log = os.path.join(work, "calls.jsonl")
        env = dict(os.environ)
        env.update({"PYTHONPATH": SENSOR_DIR, "GUARDIAN_CALLS": calls_log,
                    "GUARDIAN_SINK": os.path.join(work, "sink.jsonl"),
                    "GUARDIAN_RECORDS": os.path.join(work, "records.jsonl"),
                    "GUARDIAN_MEMORY": os.path.join(work, "memory.jsonl"),
                    "GUARDIAN_AGENT_INBOX": os.path.join(work, "inbox.jsonl")})
        env.pop("GUARDIAN_TAMPER", None)
        env.pop("GUARDIAN_WIDEN", None)
        env.pop("GUARDIAN_ADD", None)
        env.update(fixture["env"])
        cmd = [sys.executable, "-m", "guardian_sensor", "--config", cfg_path, "--",
               sys.executable, FAKE_SERVER]
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": fixture["call"]},
        ]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, cwd=work, env=env)
        replies = {}
        try:
            for msg in messages:
                proc.stdin.write(json.dumps(msg) + "\n")
                proc.stdin.flush()
                line = proc.stdout.readline()
                if not line:
                    break
                reply = json.loads(line)
                replies[reply.get("id")] = reply
        finally:
            proc.stdin.close()
            proc.stderr.read()
            proc.wait(timeout=30)
        refused = int(bool(((replies.get(4) or {}).get("result") or {}).get("isError")))
        reached = []
        if os.path.exists(calls_log):
            with open(calls_log, encoding="utf-8") as f:
                reached = [json.loads(line).get("tool") for line in f if line.strip()]
        verdict = _verdict(fixture["expect"], _evidence(os.path.join(work, "evidence.jsonl")),
                           refused)
        # Refused by the proxy is not enough. The server must never have seen the call.
        if verdict["outcome"] == "blocked" and fixture["call"]["name"] in reached:
            verdict["outcome"] = "flagged"
        verdict["reached_server"] = fixture["call"]["name"] in reached
        return verdict


def run():
    _isolate()
    from guardian_sensor import rules
    with open(os.path.join(CORPUS, "policy.json"), encoding="utf-8") as f:
        policy = json.load(f)
    catalog = load_catalog()
    fixtures = []
    for case in select_fixtures(load_cases("attacks")):
        result = replay_case(case, policy)
        fixtures.append({"id": case["id"], "source": case["_file"], "via": "sensor",
                         "expect": case["expect"], **result})
    for fx in SERVER_FIXTURES:
        result = replay_server_fixture(fx)
        fixtures.append({"id": fx["id"], "source": "sensor/tests/fake_server.py",
                         "via": "proxy process", "expect": fx["expect"], **result})

    benign = []
    for case in load_cases("benign"):
        result = replay_case(dict(case, expect=None), policy)
        benign.append({"id": case["id"], "source": case["_file"],
                       "known_false_alarm": case.get("known_false_alarm"), **result})

    patterns = []
    for p in catalog:
        mine = [f for f in fixtures if f["expect"] == p["id"]]
        outcomes = [f["outcome"] for f in mine]
        if not mine:
            coverage = "no fixture"
        elif all(o == "blocked" for o in outcomes):
            coverage = "blocked"
        elif "missed" in outcomes:
            coverage = "missed"
        else:
            coverage = "detected, not always blocked"
        patterns.append({**p, "sensor_rule": p["id"] in rules.RULES,
                         "fixtures": [f["id"] for f in mine], "outcomes": outcomes,
                         "coverage": coverage,
                         "note": NO_FIXTURE_NOTES.get(p["id"]) if not mine else None})

    techniques = sorted({t for p in catalog for t in p["atlas"]})
    blocked_techniques = sorted({t for p in patterns if p["coverage"] == "blocked"
                                 for t in p["atlas"]})
    problems = find_problems(fixtures, benign)
    return {"max_fixtures_per_pattern": MAX_PER_PATTERN, "patterns": patterns,
            "fixtures": fixtures, "benign": benign,
            "atlas": {"mapped": techniques, "with_a_blocked_fixture": blocked_techniques},
            "problems": problems}


def find_problems(fixtures, benign):
    """What fails the check: a fixture no longer detected, or ordinary work blocked
    that is not a tracked false alarm. A fixture that drops from blocked to flagged does
    not fail here; it changes the page, and --check fails on that instead, so the change
    is visible in the diff of the pull request that caused it."""
    problems = ["fixture no longer detected: %s (expected %s, raised %s)"
                % (f["id"], f["expect"], ", ".join(f["raised"]) or "nothing")
                for f in fixtures if f["outcome"] == "missed"]
    problems += ["ordinary work blocked through the proxy: %s" % b["id"]
                 for b in benign if b["outcome"] == "blocked"
                 and b.get("known_false_alarm") not in b["raised"]]
    return problems


def summary(result):
    pats = result["patterns"]
    count = lambda c: sum(1 for p in pats if p["coverage"] == c)  # noqa: E731
    fixtures = result["fixtures"]
    benign = result["benign"]
    return {
        "patterns": len(pats),
        "with_sensor_rule": sum(1 for p in pats if p["sensor_rule"]),
        "with_fixture": sum(1 for p in pats if p["fixtures"]),
        "blocked": count("blocked"),
        "detected_not_always_blocked": count("detected, not always blocked"),
        "missed": count("missed"),
        "no_fixture": count("no fixture"),
        "fixtures": len(fixtures),
        "fixtures_blocked": sum(1 for f in fixtures if f["outcome"] == "blocked"),
        "fixtures_flagged": sum(1 for f in fixtures if f["outcome"] == "flagged"),
        "fixtures_missed": sum(1 for f in fixtures if f["outcome"] == "missed"),
        "benign": len(benign),
        "benign_forwarded": sum(1 for b in benign if b["outcome"] == "forwarded"),
        "benign_flagged": sum(1 for b in benign if b["outcome"] == "flagged"),
        "benign_blocked": sum(1 for b in benign if b["outcome"] == "blocked"),
        "atlas_mapped": len(result["atlas"]["mapped"]),
        "atlas_with_a_blocked_fixture": len(result["atlas"]["with_a_blocked_fixture"]),
    }


def markdown(result):
    s = summary(result)
    lines = [
        "# Detection coverage through the proxy",
        "",
        "Generated by `python3 scripts/detection_coverage.py --write`. Do not edit by hand:",
        "`python3 check.py` fails if this page and the repository disagree, and fails if a",
        "fixture that used to be detected no longer is.",
        "",
        "Every fixture below already existed: a corpus case, or a mode of the test MCP",
        "server. Each is replayed through the sensor's own request path, so the result is",
        "what the proxy did with it: **blocked** (refused before it was forwarded),",
        "**flagged** (recorded as evidence and forwarded), or **missed**. At most %d attack"
        % result["max_fixtures_per_pattern"],
        "fixtures per pattern are replayed. This is a regression measurement over scripted",
        "cases. It is not a detection rate, not a pentest, and not evidence of catching",
        "anything in the wild. See [DETECTION_COVERAGE_SUITE.md](DETECTION_COVERAGE_SUITE.md).",
        "",
        "## Summary",
        "",
        "| Measure | Count |",
        "| --- | --- |",
        "| Patterns in the catalog | %d |" % s["patterns"],
        "| Patterns with a rule in the sensor | %d |" % s["with_sensor_rule"],
        "| Patterns with at least one fixture replayed | %d |" % s["with_fixture"],
        "| Patterns whose every fixture was blocked | %d |" % s["blocked"],
        "| Patterns detected but not always blocked | %d |" % s["detected_not_always_blocked"],
        "| Patterns with a missed fixture | %d |" % s["missed"],
        "| Patterns with no fixture | %d |" % s["no_fixture"],
        "| Attack fixtures replayed | %d |" % s["fixtures"],
        "| Attack fixtures blocked / flagged / missed | %d / %d / %d |"
        % (s["fixtures_blocked"], s["fixtures_flagged"], s["fixtures_missed"]),
        "| Benign cases replayed | %d |" % s["benign"],
        "| Benign cases forwarded untouched / flagged / blocked | %d / %d / %d |"
        % (s["benign_forwarded"], s["benign_flagged"], s["benign_blocked"]),
        "| ATLAS techniques the catalog maps to | %d |" % s["atlas_mapped"],
        "| Of those, with a pattern whose every fixture was blocked | %d |"
        % s["atlas_with_a_blocked_fixture"],
        "",
        "## Every pattern",
        "",
        "| Pattern | Title | ATLAS | Sensor rule | Fixtures | Coverage |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for p in result["patterns"]:
        fx = ", ".join("%s (%s)" % (i, o) for i, o in zip(p["fixtures"], p["outcomes"]))
        cov = p["coverage"] + ("; " + p["note"] if p["note"] else "")
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            p["id"], p["title"], ", ".join("`%s`" % t for t in p["atlas"]) or "custom",
            "yes" if p["sensor_rule"] else "no", fx or "none", cov))
    lines += ["",
              "A pattern detected in a tool's output (GP-0006, GP-0010) is flagged, never",
              "blocked: the sensor records it and marks the session tainted, and does not",
              "withhold what a tool returned. Later calls that act on that content are what",
              "the request-side rules block.",
              "", "## Fixtures", "",
              "| Fixture | Expects | Through | Outcome | Patterns raised |",
              "| --- | --- | --- | --- | --- |"]
    for f in result["fixtures"]:
        lines.append("| `%s` | %s | %s | %s | %s |" % (
            f["source"], f["expect"], f["via"], f["outcome"], ", ".join(f["raised"]) or "none"))
    unusual = [b for b in result["benign"] if b["outcome"] != "forwarded"]
    lines += ["", "## Ordinary work", "",
              "Every benign corpus case is replayed through the same path. Each should be",
              "forwarded with nothing recorded."]
    if unusual:
        lines += ["", "| Case | Outcome | Patterns raised | Known false alarm |",
                  "| --- | --- | --- | --- |"]
        for b in unusual:
            lines.append("| `%s` | %s | %s | %s |" % (
                b["source"], b["outcome"], ", ".join(b["raised"]) or "none",
                b["known_false_alarm"] or "no"))
    else:
        lines += ["", "All %d were." % len(result["benign"])]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write", action="store_true", help="regenerate the page")
    ap.add_argument("--check", action="store_true", help="fail if the page is stale")
    args = ap.parse_args(argv)
    result = run()
    page = markdown(result)
    problems = list(result["problems"])
    if args.write:
        with open(PAGE, "w", encoding="utf-8") as f:
            f.write(page)
    if args.check:
        try:
            with open(PAGE, encoding="utf-8") as f:
                current = f.read()
        except OSError:
            current = None
        if current != page:
            problems.append("docs/DETECTION_COVERAGE.md is out of date. Run "
                            "python3 scripts/detection_coverage.py --write")
    if args.json:
        print(json.dumps({**result, "summary": summary(result), "problems": problems},
                         indent=2, sort_keys=True))
    else:
        s = summary(result)
        print("Patterns: %d in the catalog, %d with a fixture, %d blocked, %d detected but "
              "not always blocked, %d missed, %d with no fixture"
              % (s["patterns"], s["with_fixture"], s["blocked"],
                 s["detected_not_always_blocked"], s["missed"], s["no_fixture"]))
        print("Attack fixtures through the proxy: %d blocked, %d flagged, %d missed, of %d"
              % (s["fixtures_blocked"], s["fixtures_flagged"], s["fixtures_missed"],
                 s["fixtures"]))
        print("Ordinary work: %d of %d forwarded untouched"
              % (s["benign_forwarded"], s["benign"]))
        for p in problems:
            print("FAIL %s" % p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
