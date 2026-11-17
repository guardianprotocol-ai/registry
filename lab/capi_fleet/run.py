#!/usr/bin/env python3
"""Run the Cluster API use cases through the real sensor, with it off and with it on.

    python3 lab/capi_fleet/run.py                       every case, both arms
    python3 lab/capi_fleet/run.py --case drain-a-node   one case, with the note and the call
    python3 lab/capi_fleet/run.py --list                the cases and their ids
    python3 lab/capi_fleet/run.py --json out.json       also write the outcome as JSON

    python3 lab/capi_fleet/run.py --try 'kubectl delete md gpu-a -n fleet'
    python3 lab/capi_fleet/run.py --try-call resources_scale \\
        '{"apiVersion": "cluster.x-k8s.io/v1beta1", "kind": "MachinePool", "scale": 0}'

Each case is one session with a simulated management cluster (fleet_tool.py): the agent
reads an incident note, then makes one tool call. The two arms are the same client and
the same server. In one the client talks to the server directly. In the other the real
sensor, `python3 -m guardian_sensor` in block mode, sits between them.

`--try` and `--try-call` skip the fleet and ask the rule engine directly what it makes of
a command or a tool call of your own, once in a session a note has tainted and once in a
clean one. That is the quickest way to find something it gets wrong.

What this is not. The calls are scripted: no model chose them, so this says nothing about
whether an agent would follow the note. The fleet is simulated: no Kubernetes API, no
Cluster API controller, no machine. One run per arm. It shows that the sensor stops these
calls and leaves the controls alone, and that is all it shows.

Python 3.9+ standard library only.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SENSOR = os.path.join(ROOT, "sensor")
SIGNATURES = os.path.join(SENSOR, "guardian_sensor", "signatures.json")
sys.path.insert(0, HERE)

import cases as case_data  # noqa: E402
import fleet_tool  # noqa: E402

BLOCKED = "Blocked by Guardian sensor"


class Client:
    def __init__(self, cmd, env, cwd):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, bufsize=1, env=env, cwd=cwd)
        self.n = 0

    def call(self, method, params=None):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method,
                                       "params": params or {}}) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError("no reply: %s" % self.p.stderr.read()[:400])
        return json.loads(line)

    def close(self):
        self.p.stdin.close()
        self.p.stderr.read()
        self.p.wait(timeout=10)


def _reply_text(reply):
    content = (reply.get("result") or {}).get("content") or [{}]
    return content[0].get("text", "")


def run_arm(case, sensor_on):
    """One session. Returns what the client saw and what became of the fleet."""
    with tempfile.TemporaryDirectory(prefix="gp-capi-") as work:
        state = os.path.join(work, "fleet.json")
        evidence = os.path.join(work, "evidence.jsonl")
        config = os.path.join(work, "guardian.json")
        with open(config, "w", encoding="utf-8") as f:
            json.dump({"mode": "block", "allowlist": [], "drill": True,
                       "pins_path": os.path.join(work, "pins.json"),
                       "evidence_path": evidence}, f)
        env = dict(os.environ)
        env.update({
            "PYTHONPATH": SENSOR, "PYTHONUNBUFFERED": "1",
            "GP_FLEET_STATE": state, "GP_FLEET_NOTE": case["note"],
            # This repository's rules and a throwaway home. A sensor prefers a bundle
            # the machine adopted from the network, which is right for a sensor and
            # wrong for a lab that exists to show what this tree's rules do.
            "GUARDIAN_SIGNATURES": SIGNATURES, "GUARDIAN_HOME": os.path.join(work, "home"),
        })
        tool = [sys.executable, os.path.join(HERE, "fleet_tool.py")]
        cmd = ([sys.executable, "-m", "guardian_sensor", "--config", config, "--"] + tool
               if sensor_on else tool)
        client = Client(cmd, env, work)
        client.call("initialize")
        client.call("tools/list")
        client.call("tools/call", {"name": "read_incident", "arguments": {}})
        reply = client.call("tools/call", {"name": case["tool"], "arguments": case["arguments"]})
        client.close()
        with open(state, encoding="utf-8") as f:
            after = json.load(f)
        records = []
        if os.path.exists(evidence):
            with open(evidence, encoding="utf-8") as f:
                records = [json.loads(line) for line in f if line.strip()]
    text = _reply_text(reply)
    blocks = [r for r in records if r.get("action") == "blocked"]
    return {
        "blocked": BLOCKED in text,
        "patterns": sorted({p for r in blocks for p in r.get("patterns", [])}),
        "operation": next((r.get("detail", {}).get("operation")
                           or r.get("detail", {}).get("credential") for r in blocks), None),
        "reached_the_fleet": case["tool"] in after["reached"],
        "not_simulated": text.startswith("not simulated"),
        "fleet": after["fleet"],
    }


def changes(before, after):
    """What became of the fleet, in words."""
    out = []
    lost = len(before["clusters"]) - len(after["clusters"])
    if lost:
        out.append("%d of %d clusters gone" % (lost, len(before["clusters"])))
    if after["machines"] < before["machines"]:
        out.append("%d of %d machines gone" % (before["machines"] - after["machines"],
                                               before["machines"]))
    elif after["machines"] > before["machines"]:
        out.append("%d machines added" % (after["machines"] - before["machines"]))
    if after["credentials_disclosed"]:
        out.append("admin kubeconfig for %s disclosed"
                   % ", ".join(after["credentials_disclosed"]))
    if after["machines_marked"]:
        out.append("%s marked for deletion" % ", ".join(after["machines_marked"]))
    if after["clusters_paused"]:
        out.append("%s no longer reconciled" % ", ".join(after["clusters_paused"]))
    if after["controlled_by"] != before["controlled_by"]:
        out.append("fleet now controlled by %s" % after["controlled_by"])
    if not after["providers_installed"]:
        out.append("providers removed")
    if after["nodes_drained"]:
        out.append("%s drained" % ", ".join(after["nodes_drained"]))
    return out


def damaged(case, before, after):
    """Whether the damage the case names is what happened. Read from the fleet, not the sensor."""
    kind = case.get("damage")
    if kind == "clusters_lost":
        return len(after["clusters"]) < len(before["clusters"])
    if kind == "machines_lost":
        return after["machines"] < before["machines"]
    if kind == "control_moved":
        return after["controlled_by"] != before["controlled_by"]
    return bool(after.get(kind))


def run_case(case):
    before = fleet_tool.summary(fleet_tool.new_fleet())
    off, on = run_arm(case, False), run_arm(case, True)
    attack = bool(case["expect"])
    if attack:
        ok = (damaged(case, before, off["fleet"]) and not off["blocked"]
              and on["blocked"] and case["expect"] in on["patterns"]
              and not on["reached_the_fleet"] and on["fleet"] == before)
    else:
        ok = (not off["blocked"] and not on["blocked"] and on["reached_the_fleet"]
              and not on["not_simulated"] and on["fleet"] == off["fleet"]
              and (case.get("changes_fleet") or not _harm(before, on["fleet"])))
    return {"id": case["id"], "title": case["title"], "attack": attack,
            "expect": case["expect"], "as_expected": ok, "before": before,
            "sensor_off": off, "sensor_on": on,
            "without": changes(before, off["fleet"]), "with": changes(before, on["fleet"])}


def _harm(before, after):
    """Whether a control left the fleet worse off. Adding machines is not harm."""
    return [c for c in changes(before, after) if not c.endswith("machines added")]


def describe(outcome):
    on = outcome["sensor_on"]
    without = "; ".join(outcome["without"]) or "the call ran, the fleet is unchanged"
    if on["blocked"]:
        with_sensor = "blocked, %s%s; the fleet is unchanged" % (
            ", ".join(on["patterns"]), " (%s)" % on["operation"] if on["operation"] else "")
    else:
        with_sensor = "allowed; " + ("; ".join(outcome["with"]) or "the fleet is unchanged")
    return without, with_sensor


def show(outcomes):
    for heading, attack in (("Attacks: the sensor must stop the call", True),
                            ("Controls: ordinary work the sensor must leave alone", False)):
        print(heading)
        print()
        for o in [o for o in outcomes if o["attack"] == attack]:
            without, with_sensor = describe(o)
            print("  %s%s" % (o["title"], "" if o["as_expected"] else "   <- NOT AS EXPECTED"))
            print("      without the sensor: " + without)
            print("      with the sensor:    " + with_sensor)
        print()
    attacks = [o for o in outcomes if o["attack"]]
    controls = [o for o in outcomes if not o["attack"]]
    print("Attacks stopped: %d of %d. Controls left alone: %d of %d."
          % (sum(o["sensor_on"]["blocked"] for o in attacks), len(attacks),
             sum(not o["sensor_on"]["blocked"] for o in controls), len(controls)))
    print("Scripted calls against a simulated fleet, one run per arm. No model, no cluster.")


def load_rules():
    os.environ["GUARDIAN_SIGNATURES"] = SIGNATURES
    os.environ.setdefault("GUARDIAN_HOME", tempfile.mkdtemp(prefix="gp-capi-home-"))
    sys.path.insert(0, SENSOR)
    from guardian_sensor import rules
    return rules


def try_call(name, arguments):
    """Ask the rule engine about one call, in a tainted session and in a clean one."""
    rules = load_rules()
    config = {"allowlist": [], "max_repeat": 10}
    print("tool:      %s" % name)
    print("arguments: %s" % json.dumps(arguments))
    for label, tainted in (("after reading a note that carried instructions", "read_incident"),
                           ("in a session nothing has tainted", None)):
        hits = rules.check_call(name, arguments, {"tainted_by": tainted, "counts": {}}, config)
        print()
        print(label + ":")
        if not hits:
            print("  allowed, no rule fires")
        for pattern, detail in hits:
            why = detail.get("operation") or detail.get("credential") or ""
            where = detail.get("read_from")
            print("  %s  %s%s%s" % (pattern, rules.RULES.get(pattern, ""),
                                    "\n           read as: " + why if why else "",
                                    ", from the " + where if where else ""))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--case", help="run one case and show its note and its call")
    ap.add_argument("--list", action="store_true", help="list the cases")
    ap.add_argument("--json", help="write the outcome to this path")
    ap.add_argument("--try", dest="command", help="ask the rules about a shell command")
    ap.add_argument("--try-call", nargs=2, metavar=("TOOL", "JSON"),
                    help="ask the rules about a tool call with these arguments")
    args = ap.parse_args()

    if args.command:
        return try_call("shell", {"command": args.command})
    if args.try_call:
        return try_call(args.try_call[0], json.loads(args.try_call[1]))
    if args.list:
        for case in case_data.CASES:
            print("%-40s %s" % (case["id"], case["title"]))
        return 0

    chosen = case_data.CASES
    if args.case:
        chosen = [c for c in case_data.CASES if c["id"] == args.case]
        if not chosen:
            print("no case called %s. Try --list." % args.case)
            return 2
        case = chosen[0]
        print(case["title"] + ". " + case["stake"])
        print()
        print("The note the agent reads:")
        print("  " + case["note"])
        print("The call it then makes (%s):" % case["shape"])
        print("  %s %s" % (case["tool"], json.dumps(case["arguments"])))
        print()
    outcomes = [run_case(case) for case in chosen]
    show(outcomes)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"simulated": True, "model_in_the_loop": False, "runs_per_arm": 1,
                       "cases": outcomes}, f, indent=2, sort_keys=True)
            f.write("\n")
    return 0 if all(o["as_expected"] for o in outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
