#!/usr/bin/env python3
"""Every Cluster API use case, through the real sensor, with it off and with it on.

No cluster is contacted and no model is in the loop. The fleet is the simulation in
fleet_tool.py, and the counts here are of scripted calls against it.

Run from the repository root:

    python3 lab/capi_fleet/test_lab.py
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import cases as case_data  # noqa: E402
import fleet_tool  # noqa: E402
import run as lab  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print("%s %s%s" % ("ok  " if condition else "FAIL", name,
                       "" if condition else "  <- " + str(detail)[:300]))
    if not condition:
        failures.append(name)


def test_the_cases_are_what_they_say():
    rules = lab.load_rules()
    ids = [c["id"] for c in case_data.CASES]
    check("case ids are unique", len(ids) == len(set(ids)))
    check("there are attacks and controls", case_data.ATTACKS and case_data.CONTROLS)
    for case in case_data.CASES:
        tainting = rules.has_instructions(case["note"])
        if case["id"] == "control-operator-deletes-a-cluster":
            check("the operator's note carries no instruction", not tainting)
        else:
            # A control only means something if the session was tainted when it ran.
            check("the note taints the session: " + case["id"], tainting)
    text = json.dumps(case_data.CASES)
    check("the only credential is a canary",
          re.fullmatch(r"GP\d{4}-CANARY-[a-z0-9]{4}", fleet_tool.CANARY) is not None)
    check("no case names a real destination", "http" not in text)


def test_the_simulation():
    fleet = fleet_tool.new_fleet()
    before = fleet_tool.summary(fleet)
    check("the fleet starts with two clusters and ten machines",
          len(before["clusters"]) == 2 and before["machines"] == 10, before)
    fleet_tool.run_command(fleet, "kubectl delete cluster train-east -n fleet")
    after = fleet_tool.summary(fleet)
    check("deleting a cluster takes its machines with it",
          after["clusters"] == ["serve-west"] and after["machines"] == 4, after)
    fleet = fleet_tool.new_fleet()
    out = fleet_tool.run_command(fleet, "kubectl get secret train-east-kubeconfig -n fleet")
    check("a get with no output flag discloses nothing",
          fleet_tool.CANARY not in out and not fleet["credentials_disclosed"])
    out = fleet_tool.run_command(fleet, "kubectl get secret train-east-kubeconfig -o yaml")
    check("a get with one returns the canary",
          fleet_tool.CANARY in out and fleet["credentials_disclosed"] == ["train-east"])
    for command in ("helm uninstall thing", "kubectl exec pod -- sh", "kubectl delete widget x"):
        try:
            fleet_tool.run_command(fleet_tool.new_fleet(), command)
        except fleet_tool.NotSimulated:
            check("says so when it does not simulate: " + command, True)
        else:
            check("says so when it does not simulate: " + command, False, "it answered")


def test_every_case_in_both_arms():
    before = fleet_tool.summary(fleet_tool.new_fleet())
    for case in case_data.CASES:
        outcome = lab.run_case(case)
        off, on = outcome["sensor_off"], outcome["sensor_on"]
        label = case["id"]
        check("the call is one the fleet simulates: " + label,
              not off["not_simulated"], off)
        if case["expect"]:
            check("without the sensor the damage happens: " + label,
                  lab.damaged(case, before, off["fleet"]) and not off["blocked"], off)
            check("with the sensor it is blocked as %s: %s" % (case["expect"], label),
                  on["blocked"] and case["expect"] in on["patterns"], on)
            check("the blocked call never reached the fleet: " + label,
                  not on["reached_the_fleet"] and on["fleet"] == before, on)
            check("the evidence names an operation and no object: " + label,
                  on["operation"] and not any(
                      word in on["operation"] for word in ("train-east", "serve-west", "gpu-")),
                  on["operation"])
        else:
            check("the control runs with the sensor on: " + label,
                  not on["blocked"] and on["reached_the_fleet"], on)
            check("and has the same effect either way: " + label,
                  on["fleet"] == off["fleet"], (on["fleet"], off["fleet"]))
        check("as expected overall: " + label, outcome["as_expected"])


def test_the_corpus_holds_the_same_cases():
    """The gate replays these on every pull request, so the lab and the gate cannot drift."""
    for case in case_data.CASES:
        if case["expect"]:
            path = os.path.join(ROOT, "corpus", "attacks",
                                "%s-%s.json" % (case["expect"], case["id"]))
        elif case["id"] == "control-operator-deletes-a-cluster":
            continue        # corpus/benign already has this one, written before the lab
        else:
            path = os.path.join(ROOT, "corpus", "benign",
                                "fleet-%s.json" % case["id"].replace("control-", ""))
        try:
            with open(path, encoding="utf-8") as f:
                stored = json.load(f)
        except OSError:
            check("corpus case exists: " + os.path.relpath(path, ROOT), False, "missing")
            continue
        events = stored["events"]
        check("corpus case matches the lab: " + case["id"],
              events[0]["output"]["text"] == case["note"]
              and events[1]["call"] == {"name": case["tool"], "args": case["arguments"]})


def test_the_page_lists_every_case():
    with open(os.path.join(ROOT, "docs", "KUBERNETES_CAPI.md"), encoding="utf-8") as f:
        page = f.read()
    for case in case_data.CASES:
        check("docs/KUBERNETES_CAPI.md lists: " + case["title"], case["title"] in page)
        check("and its id: " + case["id"], "`%s`" % case["id"] in page)


def main():
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print()
    if failures:
        print("FAIL (%d): %s" % (len(failures), ", ".join(failures)))
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
