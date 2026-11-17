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
    hosts = re.findall(r"https?://([^/:\s\"]+)", text)
    check("every destination is a reserved .test name",
          hosts and all(h.endswith(".test") for h in hosts), hosts)


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
          fleet_tool.CANARY in out
          and fleet["credentials_disclosed"] == ["train-east kubeconfig"])
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
              and events[1]["call"] == {"name": case["tool"], "args": case["arguments"]}
              and stored.get("config", {}).get("allowlist", []) == case.get("allowlist", []))


def test_the_real_shell_tool_only_runs_against_this_machine():
    """real_tool.py runs what it is given, so what it refuses is the safety of the lab."""
    import tempfile
    import real_tool
    with tempfile.TemporaryDirectory() as work:
        local = os.path.join(work, "local.kubeconfig")
        remote = os.path.join(work, "remote.kubeconfig")
        binary = os.path.join(work, "kubectl")
        for path, text in ((local, "clusters:\n- cluster:\n    server: https://127.0.0.1:16443\n"),
                           (remote, "clusters:\n- cluster:\n    server: https://fleet.example.test:6443\n"),
                           (binary, "")):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
        saved = {k: os.environ.get(k) for k in ("GP_LAB_KUBECONFIG", "GP_LAB_KUBECTL", "GP_LAB_CLUSTERCTL")}
        try:
            os.environ.update({"GP_LAB_KUBECONFIG": local, "GP_LAB_KUBECTL": binary,
                               "GP_LAB_CLUSTERCTL": ""})
            argv = real_tool.argv_for("KUBECONFIG=/etc/other kubectl delete cluster demo -n fleet")
            check("a KUBECONFIG in front of the command is dropped",
                  argv == [binary, "delete", "cluster", "demo", "-n", "fleet"], argv)
            check("a tool that adds kubectl itself gets it added",
                  real_tool.argv_for("get clusters", implied_kubectl=True) == [binary, "get", "clusters"])
            for command in ("kubectl --kubeconfig /etc/other get pods",
                            "kubectl --context=prod delete cluster demo",
                            "kubectl --server https://fleet.example.test get pods",
                            "clusterctl move --to-kubeconfig=/tmp/x",
                            "kubectl get pods | sh",
                            "rm -rf /tmp/x",
                            "clusterctl get kubeconfig demo",      # no path was given for it
                            "kubectl get 'unclosed"):
                try:
                    real_tool.argv_for(command)
                except real_tool.Constraint:
                    check("refused: " + command, True)
                else:
                    check("refused: " + command, False, "it would have run")
            os.environ["GP_LAB_KUBECONFIG"] = remote
            try:
                real_tool.argv_for("kubectl get pods")
            except real_tool.Constraint:
                check("a kubeconfig that points elsewhere is refused", True)
            else:
                check("a kubeconfig that points elsewhere is refused", False, "it would have run")
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        import subprocess
        done = subprocess.run(
            [sys.executable, os.path.join(HERE, "run_cluster.py"), "--admin-kubeconfig", remote,
             "--kubectl", binary, "--clusterctl", binary, "--clusterclass", binary,
             "--containers-server", binary, "--flux-server", binary,
             "--out", os.path.join(work, "out.json")], capture_output=True, text=True, timeout=60)
        check("the cluster runner refuses a cluster that is not on this machine",
              done.returncode == 2 and "refusing" in done.stdout, done.stdout + done.stderr)
        check("and writes nothing", not os.path.exists(os.path.join(work, "out.json")))


def test_the_recorded_cluster_run_is_what_the_page_says():
    """Every number on the page comes from a file in the repository."""
    import run_cluster
    ids = {c["id"] for c in case_data.CASES}
    check("every real case is one of the lab's cases",
          all(c["id"] in ids for c in run_cluster.REAL_CASES))
    folder = os.path.join(HERE, "outcomes")
    files = sorted(f for f in os.listdir(folder) if f.endswith(".json"))
    check("a recorded run exists", bool(files))
    with open(os.path.join(folder, files[-1]), encoding="utf-8") as f:
        recorded = json.load(f)
    summary = recorded["summary"]
    with open(os.path.join(ROOT, "docs", "KUBERNETES_CAPI.md"), encoding="utf-8") as f:
        page = f.read()
    sentence = ("%d of %d attacks stopped and %d of %d controls left alone"
                % (summary["attacks_blocked"], summary["attacks"],
                   summary["controls_allowed"], summary["controls"]))
    check("the page quotes the recorded run: " + sentence, sentence in page)
    check("the page names the file", "outcomes/" + files[-1] in page)
    for key in ("kubernetes_api_server", "clusterctl", "containers_kubernetes_mcp_server",
                "flux159_mcp_server_kubernetes"):
        check("the page states the version of " + key,
              str(recorded["versions"][key]).lstrip("v").split("+")[0] in page,
              recorded["versions"][key])
    text = json.dumps(recorded)
    check("the recorded run holds no credential",
          not re.search(r"client-key-data|PRIVATE KEY|LS0tLS1CRUdJTi", text))
    check("every recorded case went as expected", summary["all_as_expected"])
    for case in recorded["cases"]:
        if case["expect"]:
            check("recorded: blocked with the sensor, damage without: " + case["id"],
                  case["sensor_on"]["blocked"] and case["sensor_on"]["fleet_unchanged"]
                  and case["sensor_off"]["damage"])


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
