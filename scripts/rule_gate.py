#!/usr/bin/env python3
"""Rule gate: prove every detection still catches its attacks and leaves ordinary work alone.

    python3 scripts/rule_gate.py                      # run the gate
    python3 scripts/rule_gate.py --json               # machine-readable results
    python3 scripts/rule_gate.py --summary out.md     # also write a Markdown report
    python3 scripts/rule_gate.py --compare base.json  # show what a change does versus the base

Replays every case in corpus/ through the sensor's shared rule engine:

- corpus/attacks/: each case names the pattern it must raise. A missed attack fails the gate.
  This is what catches a change that quietly weakens or disables a detection.
- corpus/benign/: ordinary agent work that must raise nothing. A new false alarm fails the gate,
  so a rule that would block everyday work can't be merged. Known false alarms are listed in
  the case itself and reported, not hidden.

Limits come from corpus/policy.json. No dependencies beyond the Python 3.9+ standard library.
"""
import argparse
import glob
import importlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_engine(sensor_dir):
    sys.path.insert(0, os.path.abspath(sensor_dir))
    return importlib.import_module("guardian_sensor.rules")


def load_cases(corpus_dir, kind):
    cases = []
    for path in sorted(glob.glob(os.path.join(corpus_dir, kind, "*.json"))):
        with open(path, encoding="utf-8") as f:
            case = json.load(f)
        case["_file"] = os.path.relpath(path, ROOT)
        cases.append(case)
    return cases


def replay(rules, case, default_config):
    """Pattern ids raised anywhere in the case."""
    cfg = dict(default_config)
    cfg.update(case.get("config", {}))
    state = {"tainted_by": None, "counts": {}}
    raised = set()
    for event in case["events"]:
        if "output" in event:
            o = event["output"]
            raised.update(pid for pid, _ in rules.check_output(o["source"], o["text"], state))
        elif "call" in event:
            c = event["call"]
            for _ in range(c.get("times", 1)):
                raised.update(pid for pid, _ in rules.check_call(c["name"], c["args"], state, cfg))
        else:
            raise ValueError(f"{case['_file']}: unknown event {list(event)}")
    return sorted(raised)


def pattern_statuses():
    statuses = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "patterns", "GP-*.yaml"))):
        pid = os.path.basename(path)[:-5]
        status = "draft"
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("status:"):
                    status = line.split(":", 1)[1].split("#")[0].strip()
                    break
        statuses[pid] = status
    return statuses


def run(sensor_dir, corpus_dir):
    with open(os.path.join(corpus_dir, "policy.json"), encoding="utf-8") as f:
        policy = json.load(f)
    rules = load_engine(sensor_dir)
    default = policy.get("default_config", {})

    attacks = []
    for case in load_cases(corpus_dir, "attacks"):
        raised = replay(rules, case, default)
        attacks.append({"id": case["id"], "file": case["_file"], "expect": case["expect"],
                        "raised": raised, "caught": case["expect"] in raised})

    benign = []
    for case in load_cases(corpus_dir, "benign"):
        raised = replay(rules, case, default)
        known = case.get("known_false_alarm")
        if not raised:
            verdict = "clean" if not known else "known false alarm no longer fires"
        elif known and raised == [known]:
            verdict = "known false alarm"
        else:
            verdict = "false alarm"
        benign.append({"id": case["id"], "file": case["_file"], "raised": raised,
                       "known": known, "verdict": verdict})

    statuses = pattern_statuses()
    with_cases = {a["expect"] for a in attacks}
    elsewhere = policy.get("covered_elsewhere", {})
    required = set(policy.get("require_attack_case_for", ["verified", "enforced"]))
    uncovered = [p for p in statuses if p not in with_cases and p not in elsewhere]
    blocking_uncovered = [p for p in uncovered if statuses[p] in required]

    per_pattern = {}
    for p in sorted(set(statuses) | with_cases):
        flagged = [b["id"] for b in benign if p in b["raised"]]
        per_pattern[p] = {
            "attack_cases": sum(1 for a in attacks if a["expect"] == p),
            "caught": sum(1 for a in attacks if a["expect"] == p and a["caught"]),
            "benign_flagged": flagged,
            "false_alarm_rate": round(len(flagged) / len(benign), 4) if benign else None,
        }

    new_false_alarms = [b for b in benign if b["verdict"] == "false alarm"]
    missed = [a for a in attacks if not a["caught"]]
    problems = []
    for a in missed:
        problems.append(f"attack not caught: {a['id']} (expected {a['expect']}, raised {a['raised'] or 'nothing'})")
    if len(new_false_alarms) > policy.get("max_new_false_alarms", 0):
        for b in new_false_alarms:
            problems.append(f"false alarm on ordinary work: {b['id']} raised {', '.join(b['raised'])}")
    for p in blocking_uncovered:
        problems.append(f"{p} is {statuses[p]} but has no attack case in corpus/attacks/")

    return {"attacks": attacks, "benign": benign, "per_pattern": per_pattern,
            "uncovered_drafts": [p for p in uncovered if p not in blocking_uncovered],
            "covered_elsewhere": elsewhere, "problems": problems,
            "notices": [f"known false alarm no longer fires: {b['id']}, update the case"
                        for b in benign if b["verdict"] == "known false alarm no longer fires"]}


def compare(head, base):
    """What changed between the base branch and this change."""
    def caught(r): return {a["id"]: a["caught"] for a in r["attacks"]}
    def flagged(r): return {b["id"]: tuple(b["raised"]) for b in r["benign"]}
    hc, bc, hf, bf = caught(head), caught(base), flagged(head), flagged(base)
    return {
        "newly_missed": sorted(i for i in hc if not hc[i] and bc.get(i, False)),
        "newly_caught": sorted(i for i in hc if hc[i] and i in bc and not bc[i]),
        "newly_flagged": sorted(i for i in hf if hf[i] and not bf.get(i)),
        "no_longer_flagged": sorted(i for i in hf if not hf[i] and bf.get(i)),
        "new_cases": sorted((set(hc) | set(hf)) - (set(bc) | set(bf))),
    }


def markdown(result, diff=None):
    caught = sum(a["caught"] for a in result["attacks"])
    clean = sum(b["verdict"] in ("clean", "known false alarm") for b in result["benign"])
    lines = ["## Rule gate", "",
             f"**Attacks caught:** {caught} of {len(result['attacks'])}  ",
             f"**Ordinary work left alone:** {clean} of {len(result['benign'])}", ""]
    if result["problems"]:
        lines += ["### Problems", ""] + [f"- {p}" for p in result["problems"]] + [""]
    if diff:
        lines += ["### What this change does", ""]
        labels = [("newly_missed", "Attacks no longer caught"), ("newly_caught", "Attacks newly caught"),
                  ("newly_flagged", "Ordinary work newly flagged"), ("no_longer_flagged", "False alarms fixed"),
                  ("new_cases", "New corpus cases")]
        changed = False
        for key, label in labels:
            if diff[key]:
                changed = True
                lines.append(f"- **{label}:** {', '.join(diff[key])}")
        if not changed:
            lines.append("- No change in what the rules catch or flag.")
        lines.append("")
    lines += ["### By pattern", "", "| Pattern | Attacks caught | Ordinary work flagged |", "| --- | --- | --- |"]
    for p, s in result["per_pattern"].items():
        if p in result["covered_elsewhere"]:
            att = "tested elsewhere"
        elif s["attack_cases"]:
            att = f"{s['caught']} of {s['attack_cases']}"
        else:
            att = "no attack case yet"
        flagged = ", ".join(s["benign_flagged"]) or "none"
        lines.append(f"| {p} | {att} | {flagged} |")
    known = [b for b in result["benign"] if b["verdict"] == "known false alarm"]
    if known:
        lines += ["", "### Known false alarms (tracked)", ""] + [f"- {b['id']}: {b['known']}" for b in known]
    # Custom mappings are listed on every report so their number stays in plain sight.
    custom = custom_patterns()
    if custom:
        lines += ["", "### Patterns with no ATLAS mapping", ""]
        lines += [f"- {pid}: {reason}" for pid, reason in custom]
        lines += ["", "Check these against each ATLAS release. See docs/MAINTAINING.md."]
    return "\n".join(lines) + "\n"


def custom_patterns():
    """Patterns that map to no ATLAS technique, from the validator."""
    sys.path.insert(0, os.path.join(ROOT, "scanner"))
    try:
        from guardian_scanner import patterns as pattern_validator
    except ImportError:
        return []
    return pattern_validator.validate_dir(os.path.join(ROOT, "patterns")).custom


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sensor-dir", default=os.path.join(ROOT, "sensor"))
    ap.add_argument("--corpus", default=os.path.join(ROOT, "corpus"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--summary", help="write a Markdown report to this path (appends)")
    ap.add_argument("--compare", help="results JSON from the base branch, to report what changed")
    args = ap.parse_args()

    result = run(args.sensor_dir, args.corpus)
    diff = None
    if args.compare and os.path.exists(args.compare):
        with open(args.compare, encoding="utf-8") as f:
            diff = compare(result, json.load(f))
        result["compare"] = diff
        for i in diff["newly_missed"]:
            msg = f"this change stops catching an attack: {i}"
            if msg not in " ".join(result["problems"]):
                result["problems"].append(msg)

    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as f:
            f.write(markdown(result, diff))

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        caught = sum(a["caught"] for a in result["attacks"])
        clean = sum(b["verdict"] in ("clean", "known false alarm") for b in result["benign"])
        print(f"Attacks caught: {caught} of {len(result['attacks'])}")
        print(f"Ordinary work left alone: {clean} of {len(result['benign'])}"
              f" ({sum(b['verdict'] == 'known false alarm' for b in result['benign'])} known false alarm tracked)")
        if result["uncovered_drafts"]:
            print(f"Draft patterns without an attack case yet: {', '.join(result['uncovered_drafts'])}")
        for n in result["notices"]:
            print(f"notice: {n}")
        for p in result["problems"]:
            print(f"FAIL {p}")
    sys.exit(1 if result["problems"] else 0)


if __name__ == "__main__":
    main()
