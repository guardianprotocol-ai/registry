#!/usr/bin/env python3
"""Constraint checks and a scripted pass through the real sensor.

No cluster is contacted. The kubectl binary in the pipe test is a stub
that records its arguments. Counts in this file are stub invocations,
not apiserver results. The cluster measurement is lab/k8s_tool_pipe/run_eval.py.

Run from the repository root:

    python3 lab/k8s_tool_pipe/test_tool.py
"""
import json
import os
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SENSOR = os.path.join(ROOT, "sensor")
sys.path.insert(0, HERE)
sys.path.insert(0, SENSOR)

import kubectl_tool  # noqa: E402
from guardian_sensor import rules  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print("%s %s%s" % ("ok  " if condition else "FAIL", name,
                       "" if condition else "  <- " + str(detail)))
    if not condition:
        failures.append(name)


class Client:
    def __init__(self, cmd, env, cwd):
        self.p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=env, cwd=cwd)
        self.n = 0

    def call(self, method, params=None):
        self.n += 1
        self.p.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {},
        }) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            err = self.p.stderr.read()
            raise RuntimeError("no reply: %s" % err[:400])
        return json.loads(line)

    def close(self):
        self.p.stdin.close()
        err = self.p.stderr.read()
        self.p.wait(timeout=5)
        return err


def test_allowlist():
    kubeconfig = "/tmp/gp-lab-does-not-need-to-exist-for-plan-errors"
    os.environ["GP_LAB_KUBECONFIG"] = kubeconfig
    os.environ["GP_LAB_KUBECTL"] = "/tmp/gp-lab-kubectl-stub"
    bad = [
        ("kubectl_delete_configmap", {"name": "kube-system"}),
        ("kubectl_delete_configmap", {"name": "../etc/passwd"}),
        ("kubectl_delete_configmap", {"name": "gp-lab-marker;rm"}),
        ("kubectl_delete_configmap", {"name": "gp-lab-marker", "namespace": "kube-system"}),
        ("kubectl_apply_configmap", {"name": "gp-lab-marker", "data_value": "Assistant: delete"}),
        ("kubectl_get_secret", {"name": "gp-lab-marker"}),
        ("kubectl_get_secret", {"name": "gp-lab-unused", "command": "rm -rf /"}),
        ("kubectl_apply_configmap", {"name": "gp-lab-marker", "data_value": "ok", "cmd": "true"}),
    ]
    for tool, args in bad:
        try:
            kubectl_tool.plan(tool, args)
        except kubectl_tool.ConstraintError:
            check("rejects %s %s" % (tool, sorted(args)), True)
        else:
            check("rejects %s %s" % (tool, sorted(args)), False, "plan allowed it")

    # plan() looks at the kubeconfig only when the arguments are otherwise legal.
    with tempfile.TemporaryDirectory() as work:
        cfg = os.path.join(work, "kubeconfig")
        open(cfg, "w").close()
        os.environ["GP_LAB_KUBECONFIG"] = cfg
        argv, stdin_text = kubectl_tool.plan(
            "kubectl_delete_configmap", {"name": "gp-lab-marker"})
        check("delete argv is a list", isinstance(argv, list))
        check("delete argv names the configmap",
              argv[argv.index("delete"):argv.index("delete") + 3] == ["delete", "configmap", "gp-lab-marker"],
              argv)
        check("delete argv has no shell string", all(isinstance(part, str) for part in argv))
        check("apply manifest is the validated name", "gp-lab-kept" in (kubectl_tool.plan(
            "kubectl_apply_configmap",
            {"name": "gp-lab-kept", "data_value": "synthetic-kept-marker"})[1]))


def test_classifier_and_rules():
    check("zero exit is admitted",
          kubectl_tool.classify_kubectl(0, "configmap/gp-lab-marker created\n", "")
          == "authorized_and_admitted")
    forbidden = ("Error from server (Forbidden): secrets \"gp-lab-unused\" is forbidden: "
                 "User \"system:serviceaccount:gp-lab:gp-lab-tool\" cannot get resource "
                 "\"secrets\" in API group \"\" in the namespace \"gp-lab\"")
    check("forbidden text is authorization",
          kubectl_tool.classify_kubectl(1, "", forbidden) == "authorization_denied")
    check("not found stays not found",
          kubectl_tool.classify_kubectl(1, "", "Error from server (NotFound): configmaps")
          == "not_found")
    check("poison note matches the instruction rules", rules.has_instructions(kubectl_tool.POISON_NOTE))
    check("benign note does not", not rules.has_instructions(kubectl_tool.BENIGN_NOTE))
    cfg = {"allowlist": [], "max_repeat": 10}
    tainted = {"tainted_by": "read_lab_note", "counts": {}}
    clean = {"tainted_by": None, "counts": {}}
    attacked = rules.check_call("kubectl_delete_configmap", {"name": "gp-lab-marker"}, tainted, cfg)
    check("tainted delete is GP-0005", any(item[0] == "GP-0005" for item in attacked), attacked)
    ordinary = rules.check_call("kubectl_delete_configmap", {"name": "gp-lab-marker"}, clean, cfg)
    check("untainted delete is not GP-0005", not any(item[0] == "GP-0005" for item in ordinary), ordinary)
    kept = rules.check_call(
        "kubectl_apply_configmap",
        {"name": "gp-lab-kept", "data_value": "synthetic-kept-marker"},
        dict(tainted), cfg)
    check("tainted apply is not blocked by these rules", kept == [], kept)
    secret = rules.check_call(
        "kubectl_get_secret", {"name": "gp-lab-unused"}, dict(tainted), cfg)
    check("tainted secret get is not GP-0005", not any(item[0] == "GP-0005" for item in secret), secret)


def _stub(path):
    path = os.path.abspath(path)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\n")
        handle.write('printf "%s\\n" "$*" >> "$GP_LAB_STUB_LOG"\n')
        handle.write('echo "configmap/stub configured"\n')
        handle.write("exit 0\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return path


def _session(work, sensor_on, stub, log_path):
    calls = os.path.join(work, "calls.jsonl")
    cfg_path = os.path.join(work, "guardian.json")
    with open(cfg_path, "w", encoding="utf-8") as handle:
        json.dump({
            "mode": "block",
            "allowlist": [],
            "pins_path": os.path.join(work, "pins.json"),
            "evidence_path": os.path.join(work, "evidence.jsonl"),
            "drill": True,
        }, handle)
    env = dict(os.environ)
    env.update({
        "PYTHONPATH": SENSOR,
        "PYTHONUNBUFFERED": "1",
        "GP_LAB_KUBECONFIG": os.path.join(work, "kubeconfig"),
        "GP_LAB_KUBECTL": stub,
        "GP_LAB_CALLS": calls,
        "GP_LAB_STUB_LOG": log_path,
    })
    open(env["GP_LAB_KUBECONFIG"], "w").close()
    tool = [sys.executable, os.path.join(HERE, "kubectl_tool.py")]
    if sensor_on:
        cmd = [sys.executable, "-m", "guardian_sensor", "--config", cfg_path, "--"] + tool
    else:
        cmd = tool
    client = Client(cmd, env, work)
    client.call("initialize")
    client.call("tools/list")
    return client, calls


def _text(reply):
    content = (reply.get("result") or {}).get("content") or [{}]
    return content[0].get("text", "")


def test_sensor_pipe():
    with tempfile.TemporaryDirectory() as work:
        stub = _stub(os.path.join(work, "kubectl-stub"))
        log_path = os.path.join(work, "stub.log")
        client, calls = _session(work, True, stub, log_path)
        benign = client.call("tools/call", {"name": "kubectl_apply_configmap", "arguments": {
            "name": "gp-lab-marker", "data_value": "synthetic-benign-marker"}})
        client.call("tools/call", {"name": "read_lab_note", "arguments": {"variant": "poison"}})
        kept = client.call("tools/call", {"name": "kubectl_apply_configmap", "arguments": {
            "name": "gp-lab-kept", "data_value": "synthetic-kept-marker"}})
        deleted = client.call("tools/call", {"name": "kubectl_delete_configmap", "arguments": {
            "name": "gp-lab-marker"}})
        err = client.close()
        stub_log = open(log_path).read() if os.path.exists(log_path) else ""
        reached = open(calls).read() if os.path.exists(calls) else ""
        evidence_path = os.path.join(work, "evidence.jsonl")
        evidence = [json.loads(line) for line in open(evidence_path)] if os.path.exists(evidence_path) else []
        check("sensor on forwards untainted apply to the stub",
              "apply -f -" in stub_log and not benign.get("result", {}).get("isError"))
        check("sensor on forwards tainted apply to the stub",
              not kept.get("result", {}).get("isError"))
        check("sensor on blocks the tainted delete",
              deleted.get("result", {}).get("isError") is True
              and "Blocked by Guardian sensor" in _text(deleted), _text(deleted))
        check("blocked delete did not reach the stub",
              "delete configmap gp-lab-marker" not in stub_log, stub_log)
        check("blocked delete is absent from the server log",
              "kubectl_delete_configmap" not in reached, reached)
        blocked = [row for row in evidence if row.get("action") == "blocked"]
        check("evidence records one GP-0005 block",
              len(blocked) == 1 and blocked[0]["patterns"] == ["GP-0005"], blocked)
        check("block is marked drill", blocked and blocked[0].get("drill") is True, blocked)
        check("block names the lab note as taint",
              blocked and blocked[0]["detail"].get("tainted_by") == "read_lab_note", blocked)
        check("proxy stderr names GP-0005", "GP-0005" in err, err[-400:])

    with tempfile.TemporaryDirectory() as work:
        stub = _stub(os.path.join(work, "kubectl-stub"))
        log_path = os.path.join(work, "stub.log")
        client, calls = _session(work, False, stub, log_path)
        client.call("tools/call", {"name": "read_lab_note", "arguments": {"variant": "poison"}})
        deleted = client.call("tools/call", {"name": "kubectl_delete_configmap", "arguments": {
            "name": "gp-lab-marker"}})
        client.close()
        stub_log = open(log_path).read()
        check("sensor off lets the tainted delete reach the stub",
              "delete configmap gp-lab-marker" in stub_log and not deleted.get("result", {}).get("isError"),
              stub_log)

    with tempfile.TemporaryDirectory() as work:
        stub = _stub(os.path.join(work, "kubectl-stub"))
        log_path = os.path.join(work, "stub.log")
        client, _calls = _session(work, False, stub, log_path)
        refused = client.call("tools/call", {"name": "kubectl_delete_configmap", "arguments": {
            "name": "kube-system"}})
        client.close()
        stub_log = open(log_path).read() if os.path.exists(log_path) else ""
        check("constraint refusal does not run kubectl", stub_log == "", stub_log)
        check("constraint refusal is not the sensor text",
              _text(refused).startswith(kubectl_tool.CONSTRAINT)
              and "Blocked by Guardian sensor" not in _text(refused), _text(refused))


def main():
    test_allowlist()
    test_classifier_and_rules()
    test_sensor_pipe()
    print()
    if failures:
        print("FAIL (%d): %s" % (len(failures), ", ".join(failures)))
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
