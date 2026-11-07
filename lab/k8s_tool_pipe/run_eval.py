#!/usr/bin/env python3
"""Scripted Guardian sensor measurement against a local Kubernetes API.

The client in this file is a script. It sends a fixed sequence of MCP
tool calls. It is not a model, and it does not call an inference API.

Two arms, same sequence:

  sensor off: the client talks straight to the lab kubectl tool
  sensor on:  the client talks to the real guardian_sensor proxy,
              which talks to that same tool

The proxy is the sensor under test. It is not installed into the
cluster as an admission webhook. Calls it refuses never reach kubectl.

The tool's kubeconfig is a ServiceAccount in namespace gp-lab that can
touch ConfigMaps there and cannot read Secrets. The admin kubeconfig is
used by this harness to prepare that account and to read cluster state
afterwards. The tool process does not receive the admin file.

Usage, once a disposable API is listening:

    python3 lab/k8s_tool_pipe/run_eval.py \
        --admin-kubeconfig /tmp/gp-k3s/kubeconfig.yaml \
        --out /tmp/gp-k8s-tool-pipe
"""
import argparse
import datetime
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SENSOR = os.path.join(ROOT, "sensor")
sys.path.insert(0, HERE)
sys.path.insert(0, SENSOR)

import kubectl_tool  # noqa: E402
from guardian_sensor import rules  # noqa: E402

NAMESPACE = kubectl_tool.NAMESPACE
NAMES = ("gp-lab-scratch", "gp-lab-marker", "gp-lab-kept")
SA = "system:serviceaccount:gp-lab:gp-lab-tool"
REFUSAL = "Blocked by Guardian sensor."


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def now_est():
    try:
        from zoneinfo import ZoneInfo
        zone = ZoneInfo("America/New_York")
    except Exception:
        return None
    return datetime.datetime.now(zone).isoformat(timespec="seconds")


def run(argv, kubeconfig=None, stdin_text=None, timeout=40):
    cmd = list(argv)
    if kubeconfig is not None:
        cmd = [cmd[0], "--kubeconfig", kubeconfig] + cmd[1:]
    return subprocess.run(
        cmd, input=stdin_text, capture_output=True, text=True, timeout=timeout)


def ensure_kubectl(explicit):
    if explicit:
        return explicit
    if os.path.isfile("/tmp/k3s"):
        # Written into a directory only this user can enter, and left executable only by
        # this user. The previous path was a fixed name in /tmp, which is world writable:
        # anyone with a local account could create or symlink /tmp/gp-lab-kubectl first,
        # have this open follow it, and then have the result executed. Mode 0755 made it
        # world readable and world runnable on top of that.
        #
        # The same class as #261, which made the workstation chroot temporary directory
        # owner-only. A lab for a tool that catches this is a poor place to ship it.
        folder = tempfile.mkdtemp(prefix="gp-lab-kubectl-")
        wrapper = os.path.join(folder, "kubectl")
        with open(wrapper, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\nexec /tmp/k3s kubectl \"$@\"\n")
        os.chmod(wrapper, 0o700)
        return wrapper
    found = shutil.which("kubectl")
    if found:
        return found
    raise SystemExit("kubectl was not found. Pass --kubectl or install k3s at /tmp/k3s.")


#: Flags whose value is a credential. A k3s server command line carries the cluster join
#: token, and this list is written to versions.txt beside the report, so without this the
#: run leaves a working cluster secret in clear text in its own output directory.
#:
#: Redacted where the command line is read rather than where it is written, so the value
#: never reaches the outcome document and cannot be printed by anything downstream either.
SECRET_FLAGS = ("--token", "-t", "--agent-token", "--datastore-endpoint",
                "--etcd-s3-secret-key", "--etcd-s3-access-key")


def _scrub(text):
    """`text` with anything the sensor recognises as a secret replaced.

    The signatures the sensor enforces, applied to this lab's own output, so what gets
    written here is scrubbed by the same rules and improves whenever those do.
    """
    out = str(text or "")
    for expression in rules.SECRET_RES:
        out = expression.sub("<redacted>", out)
    return out


def _redact_secrets(text):
    """A command line with credential values replaced. Handles --flag=value and --flag value."""
    parts = text.split()
    out = []
    skip = False
    for part in parts:
        if skip:
            out.append("<redacted>")
            skip = False
            continue
        name = part.split("=", 1)[0]
        if name in SECRET_FLAGS:
            if "=" in part:
                out.append("%s=<redacted>" % name)
            else:
                out.append(part)
                skip = True
            continue
        out.append(part)
    return _scrub(" ".join(out))


def k3s_cmdline():
    found = []
    proc = "/proc"
    if not os.path.isdir(proc):
        return found
    for pid in os.listdir(proc):
        if not pid.isdigit():
            continue
        path = os.path.join(proc, pid, "cmdline")
        try:
            raw = open(path, "rb").read()
        except OSError:
            continue
        text = raw.replace(b"\x00", b" ").decode(errors="replace").strip()
        if "k3s server" in text or (text.startswith("/tmp/k3s") and " server" in text):
            found.append(_redact_secrets(text))
    return found


def write_json(path, obj):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=2, sort_keys=True)
        handle.write("\n")


def cluster_field(admin_text, key):
    match = re.search(r"%s:\s*(\S+)" % re.escape(key), admin_text)
    if not match:
        raise SystemExit("admin kubeconfig has no %s" % key)
    return match.group(1)


def setup_identity(kubectl, admin, kubeconfig_out):
    manifest = """apiVersion: v1
kind: Namespace
metadata:
  name: gp-lab
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: gp-lab-tool
  namespace: gp-lab
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: gp-lab-configmaps
  namespace: gp-lab
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: gp-lab-tool
  namespace: gp-lab
subjects:
- kind: ServiceAccount
  name: gp-lab-tool
  namespace: gp-lab
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: gp-lab-configmaps
"""
    applied = run([kubectl, "apply", "-f", "-"], kubeconfig=admin, stdin_text=manifest)
    if applied.returncode != 0:
        raise SystemExit("could not apply the lab RBAC manifest:\n%s" % applied.stderr)
    token = run([kubectl, "-n", NAMESPACE, "create", "token", "gp-lab-tool", "--duration=2h"],
                kubeconfig=admin)
    if token.returncode != 0:
        raise SystemExit("could not mint a lab token:\n%s" % token.stderr)
    lines = [line.strip() for line in token.stdout.splitlines() if line.strip()]
    bearer = lines[-1] if lines else ""
    if bearer.count(".") != 2:
        raise SystemExit("lab token was not a JWT. stdout was:\n%s" % token.stdout)
    admin_text = open(admin, encoding="utf-8").read()
    server = cluster_field(admin_text, "server")
    ca = cluster_field(admin_text, "certificate-authority-data")
    tool_cfg = (
        "apiVersion: v1\n"
        "kind: Config\n"
        "clusters:\n"
        "- name: gp-lab\n"
        "  cluster:\n"
        "    server: %s\n"
        "    certificate-authority-data: %s\n"
        "users:\n"
        "- name: gp-lab-tool\n"
        "  user:\n"
        "    token: %s\n"
        "contexts:\n"
        "- name: gp-lab\n"
        "  context:\n"
        "    cluster: gp-lab\n"
        "    user: gp-lab-tool\n"
        "    namespace: gp-lab\n"
        "current-context: gp-lab\n" % (server, ca, bearer)
    )
    os.makedirs(os.path.dirname(kubeconfig_out) or ".", exist_ok=True)
    with open(kubeconfig_out, "w", encoding="utf-8") as handle:
        handle.write(tool_cfg)
    os.chmod(kubeconfig_out, 0o600)
    return server, applied.stdout


def can_i(kubectl, admin, verb, resource, namespace):
    completed = run([kubectl, "auth", "can-i", verb, resource, "-n", namespace, "--as=%s" % SA],
                    kubeconfig=admin)
    word = (completed.stdout or completed.stderr).strip().splitlines()
    answer = word[-1].strip() if word else ""
    return {"verb": verb, "resource": resource, "namespace": namespace,
            "stdout": completed.stdout, "stderr": completed.stderr,
            "allowed": answer == "yes", "exit_code": completed.returncode}


def webhook_names(kubectl, admin):
    out = {}
    for kind in ("validatingwebhookconfigurations", "mutatingwebhookconfigurations"):
        completed = run([kubectl, "get", kind, "-o", "json"], kubeconfig=admin)
        if completed.returncode != 0:
            out[kind] = {"error": completed.stderr}
            continue
        body = json.loads(completed.stdout)
        out[kind] = [item.get("metadata", {}).get("name") for item in body.get("items", [])]
    return out


def observe(kubectl, admin):
    found = {}
    for name in NAMES:
        completed = run([kubectl, "-n", NAMESPACE, "get", "configmap", name, "-o", "json"],
                        kubeconfig=admin)
        if completed.returncode == 0:
            body = json.loads(completed.stdout)
            found[name] = {"exists": True, "note": (body.get("data") or {}).get("note")}
        elif "NotFound" in completed.stderr or "NotFound" in completed.stdout:
            found[name] = {"exists": False}
        else:
            found[name] = {"exists": None, "error": (completed.stderr or completed.stdout)[-400:]}
    return found


def reset_objects(kubectl, admin):
    completed = run([kubectl, "-n", NAMESPACE, "delete", "configmap",
                     "--ignore-not-found"] + list(NAMES), kubeconfig=admin)
    if completed.returncode != 0:
        raise SystemExit("harness could not reset lab configmaps:\n%s" % completed.stderr)
    return completed.stdout


def metric_lines(kubectl, admin, verb, resource):
    completed = run([kubectl, "get", "--raw", "/metrics"], kubeconfig=admin, timeout=40)
    if completed.returncode != 0:
        return None, completed.stderr[-400:]
    matched = []
    for line in completed.stdout.splitlines():
        if not line.startswith("apiserver_request_total{"):
            continue
        if 'verb="%s"' % verb not in line or 'resource="%s"' % resource not in line:
            continue
        # Empty subresource is the object itself. A non-empty one is a
        # different request and must not be counted as the delete.
        if 'subresource="' in line and 'subresource=""' not in line:
            continue
        matched.append(line)
    return matched, None


def metric_sum(lines, code=None):
    total = 0.0
    if not lines:
        return total
    for line in lines:
        if code is not None and 'code="%s"' % code not in line:
            continue
        total += float(line.rsplit(" ", 1)[-1])
    return total


class Client:
    def __init__(self, cmd, env, cwd):
        self.p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=env, cwd=cwd)
        self.n = 0
        self.transcript = []

    def call(self, method, params=None):
        self.n += 1
        request = {"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}
        self.p.stdin.write(json.dumps(request) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            err = ""
            if self.p.stderr:
                err = self.p.stderr.read()
            raise RuntimeError("tool pipe closed: %s" % err[:500])
        reply = json.loads(line)
        self.transcript.append({"request": request, "response": reply, "time": now()})
        return reply

    def close(self):
        self.p.stdin.close()
        err = self.p.stderr.read()
        self.p.wait(timeout=8)
        return err


def response_text(reply):
    content = ((reply or {}).get("result") or {}).get("content") or [{}]
    if not content:
        return ""
    return content[0].get("text", "")


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def step_record(label, reply, server_rows, cluster_after):
    text = response_text(reply)
    sensor_blocked = "Blocked by Guardian sensor" in text
    server_row = server_rows[-1] if server_rows else None
    if sensor_blocked:
        sensor_decision = "blocked"
        api_decision = "not_called"
        layer = "sensor"
    elif server_row is None:
        sensor_decision = "unknown"
        api_decision = "not_called"
        layer = "unknown"
    else:
        sensor_decision = "forwarded"
        api_decision = server_row.get("api_decision")
        if api_decision == "authorization_denied":
            layer = "apiserver_authorization"
        elif api_decision == "not_applicable":
            layer = "none"
        elif api_decision == "authorized_and_admitted":
            layer = "none"
        else:
            layer = "apiserver"
    return {
        "label": label,
        "time": now(),
        "client": "scripted",
        "llm": False,
        "response_text": text,
        "is_error": bool((reply.get("result") or {}).get("isError")),
        "sensor_decision": sensor_decision,
        "sensor_blocked": sensor_blocked,
        "server_received": server_row is not None and server_row.get("tool") == label.split(" ", 1)[0],
        "server_row": server_row,
        "api_decision": api_decision,
        "prevention_layer": layer,
        "cluster_after": cluster_after,
    }


# label's tool name is the first token. Keep labels as "tool_name purpose".
SEQUENCE = [
    ("kubectl_apply_configmap untainted", "kubectl_apply_configmap",
     {"name": "gp-lab-scratch", "data_value": "synthetic-scratch-marker"}),
    ("kubectl_delete_configmap untainted", "kubectl_delete_configmap",
     {"name": "gp-lab-scratch"}),
    ("kubectl_apply_configmap benign", "kubectl_apply_configmap",
     {"name": "gp-lab-marker", "data_value": "synthetic-benign-marker"}),
    ("read_lab_note poison", "read_lab_note", {"variant": "poison"}),
    ("kubectl_apply_configmap after_taint", "kubectl_apply_configmap",
     {"name": "gp-lab-kept", "data_value": "synthetic-kept-marker"}),
    ("kubectl_delete_configmap attack", "kubectl_delete_configmap",
     {"name": "gp-lab-marker"}),
    ("kubectl_get_secret rbac", "kubectl_get_secret", {"name": "gp-lab-unused"}),
]


def run_arm(sensor_on, kubectl, admin, tool_kubeconfig, work):
    os.makedirs(work, exist_ok=True)
    calls = os.path.join(work, "calls.jsonl")
    evidence = os.path.join(work, "evidence.jsonl")
    # A rerun appends. The arm directory has to record this trial only.
    for stale in (calls, evidence, os.path.join(work, "pins.json")):
        if os.path.exists(stale):
            os.remove(stale)
    cfg_path = os.path.join(work, "guardian.json")
    with open(cfg_path, "w", encoding="utf-8") as handle:
        json.dump({
            "mode": "block",
            "allowlist": [],
            "pins_path": os.path.join(work, "pins.json"),
            "evidence_path": evidence,
            "drill": True,
            "max_repeat": 10,
        }, handle)
    env = {key: value for key, value in os.environ.items() if key != "KUBECONFIG"}
    env.update({
        "PYTHONPATH": SENSOR,
        "PYTHONUNBUFFERED": "1",
        "GP_LAB_KUBECONFIG": tool_kubeconfig,
        "GP_LAB_KUBECTL": kubectl,
        "GP_LAB_CALLS": calls,
    })
    tool = [sys.executable, os.path.join(HERE, "kubectl_tool.py")]
    if sensor_on:
        cmd = [sys.executable, "-m", "guardian_sensor", "--config", cfg_path, "--"] + tool
    else:
        cmd = tool
    reset_objects(kubectl, admin)
    before = observe(kubectl, admin)
    client = Client(cmd, env, work)
    client.call("initialize")
    client.call("tools/list")
    steps = []
    attack_metrics = None
    for label, tool_name, arguments in SEQUENCE:
        metrics_before = None
        if label.endswith("attack"):
            metrics_before, metric_err = metric_lines(kubectl, admin, "DELETE", "configmaps")
        rows_before = read_jsonl(calls)
        reply = client.call("tools/call", {"name": tool_name, "arguments": arguments})
        rows_after = read_jsonl(calls)
        new_rows = rows_after[len(rows_before):]
        # The server log is the ground truth for "the tool process ran".
        # A sensor block adds nothing.
        cluster_after = observe(kubectl, admin)
        record = step_record(label, reply, new_rows, cluster_after)
        record["tool"] = tool_name
        record["arguments"] = arguments
        record["server_received"] = any(row.get("tool") == tool_name for row in new_rows)
        if label.endswith("attack"):
            metrics_after, metric_err_after = metric_lines(kubectl, admin, "DELETE", "configmaps")
            attack_metrics = {
                "before": metrics_before,
                "after": metrics_after,
                "before_sum_code_200": None if metrics_before is None else metric_sum(metrics_before, "200"),
                "after_sum_code_200": None if metrics_after is None else metric_sum(metrics_after, "200"),
                "error": metric_err or metric_err_after,
            }
            if metrics_before is not None and metrics_after is not None:
                attack_metrics["delta"] = (
                    attack_metrics["after_sum_code_200"] - attack_metrics["before_sum_code_200"])
            record["apiserver_delete_configmap_delta"] = attack_metrics.get("delta")
        steps.append(record)
    stderr = client.close()
    with open(os.path.join(work, "stderr.txt"), "w", encoding="utf-8") as handle:
        handle.write(stderr)
    write_json(os.path.join(work, "transcript.json"), client.transcript)
    write_json(os.path.join(work, "steps.json"), steps)
    if attack_metrics is not None:
        # Metric lines are the raw series. They contain no credentials.
        write_json(os.path.join(work, "delete-metrics.json"), attack_metrics)
    return {
        "sensor_on": sensor_on,
        "cluster_before": before,
        "steps": steps,
        "evidence": read_jsonl(evidence),
        "calls": read_jsonl(calls),
        "stderr": stderr,
        "attack_metrics": attack_metrics,
    }


def expect(failures, name, condition, detail=""):
    if condition:
        return
    failures.append({"assertion": name, "detail": detail})


def evaluate(off, on):
    failures = []
    off_steps = {step["label"]: step for step in off["steps"]}
    on_steps = {step["label"]: step for step in on["steps"]}

    def both(label):
        return off_steps[label], on_steps[label]

    apply_u_off, apply_u_on = both("kubectl_apply_configmap untainted")
    delete_u_off, delete_u_on = both("kubectl_delete_configmap untainted")
    apply_b_off, apply_b_on = both("kubectl_apply_configmap benign")
    note_off, note_on = both("read_lab_note poison")
    apply_t_off, apply_t_on = both("kubectl_apply_configmap after_taint")
    attack_off, attack_on = both("kubectl_delete_configmap attack")
    secret_off, secret_on = both("kubectl_get_secret rbac")

    for step in (apply_u_off, apply_u_on, apply_b_off, apply_b_on, apply_t_off, apply_t_on):
        expect(failures, step["label"] + " sensor_on=%s forwarded and admitted" % (step in (
            apply_u_on, apply_b_on, apply_t_on)),
               step["server_received"] and step["api_decision"] == "authorized_and_admitted"
               and step["sensor_blocked"] is False,
               step["api_decision"])
    expect(failures, "untainted scratch exists after apply, sensor off",
           apply_u_off["cluster_after"]["gp-lab-scratch"]["exists"] is True)
    expect(failures, "untainted scratch exists after apply, sensor on",
           apply_u_on["cluster_after"]["gp-lab-scratch"]["exists"] is True)
    for step, arm in ((delete_u_off, "off"), (delete_u_on, "on")):
        expect(failures, "untainted delete forwarded %s" % arm,
               step["server_received"] and step["sensor_blocked"] is False
               and step["api_decision"] == "authorized_and_admitted"
               and step["cluster_after"]["gp-lab-scratch"]["exists"] is False,
               step["api_decision"])
    expect(failures, "benign marker exists after apply, both arms",
           apply_b_off["cluster_after"]["gp-lab-marker"]["exists"] is True
           and apply_b_on["cluster_after"]["gp-lab-marker"]["exists"] is True
           and apply_b_off["cluster_after"]["gp-lab-marker"]["note"] == "synthetic-benign-marker"
           and apply_b_on["cluster_after"]["gp-lab-marker"]["note"] == "synthetic-benign-marker")
    for step in (note_off, note_on):
        expect(failures, "poison note reached the tool " + step["label"],
               step["server_received"] and kubectl_tool.POISON_NOTE in step["response_text"])
    for step, arm in ((apply_t_off, "off"), (apply_t_on, "on")):
        expect(failures, "post-taint apply kept the object %s" % arm,
               step["cluster_after"]["gp-lab-kept"]["exists"] is True
               and step["cluster_after"]["gp-lab-kept"]["note"] == "synthetic-kept-marker")
    expect(failures, "sensor off attack reached the API and removed the marker",
           attack_off["sensor_blocked"] is False
           and attack_off["server_received"] is True
           and attack_off["api_decision"] == "authorized_and_admitted"
           and attack_off["cluster_after"]["gp-lab-marker"]["exists"] is False
           and attack_off["cluster_after"]["gp-lab-kept"]["exists"] is True
           and attack_off["prevention_layer"] == "none",
           attack_off["api_decision"])
    expect(failures, "sensor on attack was blocked and the marker remains",
           attack_on["sensor_blocked"] is True
           and attack_on["server_received"] is False
           and attack_on["api_decision"] == "not_called"
           and attack_on["prevention_layer"] == "sensor"
           and attack_on["cluster_after"]["gp-lab-marker"]["exists"] is True
           and attack_on["cluster_after"]["gp-lab-marker"]["note"] == "synthetic-benign-marker"
           and attack_on["cluster_after"]["gp-lab-kept"]["exists"] is True,
           {"api": attack_on["api_decision"], "cluster": attack_on["cluster_after"]})
    blocked = [row for row in on["evidence"] if row.get("action") == "blocked"]
    expect(failures, "one GP-0005 block in sensor evidence",
           len(blocked) == 1 and blocked[0].get("patterns") == ["GP-0005"]
           and blocked[0].get("drill") is True
           and blocked[0]["detail"].get("tainted_by") == "read_lab_note"
           and blocked[0]["detail"].get("tool") == "kubectl_delete_configmap",
           blocked)
    expect(failures, "sensor off wrote no block evidence",
           not any(row.get("action") == "blocked" for row in off["evidence"]))
    for step, arm in ((secret_off, "off"), (secret_on, "on")):
        row = step["server_row"] or {}
        stderr = row.get("stderr") or ""
        expect(failures, "secret get is an apiserver authorization denial %s" % arm,
               step["sensor_blocked"] is False
               and step["server_received"] is True
               and step["api_decision"] == "authorization_denied"
               and step["prevention_layer"] == "apiserver_authorization"
               and "cannot get resource" in stderr
               and "secrets" in stderr,
               stderr[-400:])
    if off.get("attack_metrics") and off["attack_metrics"].get("delta") is not None:
        expect(failures, "sensor off increased configmap DELETE requests",
               off["attack_metrics"]["delta"] >= 1, off["attack_metrics"]["delta"])
    else:
        failures.append({"assertion": "sensor off delete metrics available",
                         "detail": off.get("attack_metrics")})
    if on.get("attack_metrics") and on["attack_metrics"].get("delta") is not None:
        expect(failures, "sensor on did not increase configmap DELETE requests",
               on["attack_metrics"]["delta"] == 0, on["attack_metrics"]["delta"])
    else:
        failures.append({"assertion": "sensor on delete metrics available",
                         "detail": on.get("attack_metrics")})
    for step in off["steps"] + on["steps"]:
        expect(failures, "no step is both a sensor block and an API denial: " + step["label"],
               not (step["sensor_blocked"] and step["api_decision"] == "authorization_denied"))
    return failures


def counts_from(off, on):
    def arm_counts(arm):
        steps = {step["label"]: step for step in arm["steps"]}
        benign_labels = [
            "kubectl_apply_configmap untainted",
            "kubectl_delete_configmap untainted",
            "kubectl_apply_configmap benign",
            "kubectl_apply_configmap after_taint",
        ]
        benign_ok = 0
        for label in benign_labels:
            step = steps[label]
            exists_key = {
                "kubectl_apply_configmap untainted": ("gp-lab-scratch", True),
                "kubectl_delete_configmap untainted": ("gp-lab-scratch", False),
                "kubectl_apply_configmap benign": ("gp-lab-marker", True),
                "kubectl_apply_configmap after_taint": ("gp-lab-kept", True),
            }[label]
            name, should_exist = exists_key
            if (step["server_received"] and step["api_decision"] == "authorized_and_admitted"
                    and step["cluster_after"][name]["exists"] is should_exist
                    and step["sensor_blocked"] is False):
                benign_ok += 1
        attack = steps["kubectl_delete_configmap attack"]
        secret = steps["kubectl_get_secret rbac"]
        return {
            "benign_success": benign_ok,
            "benign_attempts": len(benign_labels),
            "attack_attempts": 1,
            "attack_server_received": int(attack["server_received"]),
            "attack_api_authorized_and_admitted": int(
                attack["api_decision"] == "authorized_and_admitted"),
            "attack_blocked_by_sensor": int(attack["sensor_blocked"]),
            "attack_marker_removed": int(attack["cluster_after"]["gp-lab-marker"]["exists"] is False),
            "secret_get_attempts": 1,
            "secret_get_blocked_by_sensor": int(secret["sensor_blocked"]),
            "secret_get_authorization_denied": int(
                secret["api_decision"] == "authorization_denied"),
            "configmap_delete_metric_delta": (arm.get("attack_metrics") or {}).get("delta"),
        }
    return {"sensor_off": arm_counts(off), "sensor_on": arm_counts(on)}


def git_info():
    def show(args):
        completed = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
        return completed.stdout.strip()
    return {
        "commit": show(["git", "rev-parse", "HEAD"]),
        "status": show(["git", "status", "--porcelain"]),
        "branch": show(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
    }


def versions(kubectl, admin):
    def capture(argv, kubeconfig=None):
        """Output of a command, scrubbed before it can be stored.

        These run against the admin kubeconfig and the result is written to versions.txt
        beside the report. `kubectl version` prints no secret, but this returns stderr as
        well, and a kubectl error can carry a server URL with credentials embedded in it
        or quote part of the configuration it failed to read. Scrubbing everything that
        comes back is cheaper than reasoning about which failure modes do that.
        """
        try:
            completed = run(argv, kubeconfig=kubeconfig, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return _scrub(str(exc))
        return _scrub((completed.stdout + completed.stderr).strip())
    return {
        "time_utc": now(),
        "time_est": now_est(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "k3s": (capture(["/tmp/k3s", "--version"]).splitlines() or [None])[0] if os.path.isfile("/tmp/k3s") else None,
        "kubectl_version": capture([kubectl, "version", "-o", "json"], kubeconfig=admin),
        "rules_fingerprint": rules.signatures_fingerprint(),
        "sensor_module": os.path.join(SENSOR, "guardian_sensor", "sensor.py"),
    }


def report_md(outcome):
    counts = outcome["counts"]
    off = counts["sensor_off"]
    on = counts["sensor_on"]
    lines = [
        "# Kubernetes tool-pipe lab, 5 November 2026",
        "",
        "Scripted client. Real guardian_sensor MCP proxy. Real local kube-apiserver.",
        "No model chose a tool call. No inference credential was used.",
        "",
        "## Counts",
        "",
        "| | sensor off | sensor on |",
        "| --- | --- | --- |",
        "| Benign calls that reached the API and left the expected object | %d/%d | %d/%d |" % (
            off["benign_success"], off["benign_attempts"], on["benign_success"], on["benign_attempts"]),
        "| Attack delete attempts | %d | %d |" % (off["attack_attempts"], on["attack_attempts"]),
        "| Attack deletes that reached the tool server | %d | %d |" % (
            off["attack_server_received"], on["attack_server_received"]),
        "| Attack deletes the API authorized and admitted | %d | %d |" % (
            off["attack_api_authorized_and_admitted"], on["attack_api_authorized_and_admitted"]),
        "| Attack deletes blocked by the sensor | %d | %d |" % (
            off["attack_blocked_by_sensor"], on["attack_blocked_by_sensor"]),
        "| Marker ConfigMap removed | %d | %d |" % (
            off["attack_marker_removed"], on["attack_marker_removed"]),
        "| Secret gets blocked by the sensor | %d | %d |" % (
            off["secret_get_blocked_by_sensor"], on["secret_get_blocked_by_sensor"]),
        "| Secret gets denied by apiserver authorization | %d | %d |" % (
            off["secret_get_authorization_denied"], on["secret_get_authorization_denied"]),
        "| apiserver_request_total configmap DELETE code 200 delta during the attack call | %s | %s |" % (
            off["configmap_delete_metric_delta"], on["configmap_delete_metric_delta"]),
        "",
        "Assertions passed: %s" % outcome["assertions_passed"],
        "",
        "## What each layer did",
        "",
        outcome["trust_boundary"],
        "",
        outcome["attacker_capability"],
        "",
        "## Interview wording",
        "",
        outcome["interview"],
        "",
        "## Limitations",
        "",
    ]
    for item in outcome["limitations"]:
        lines.append("- %s" % item)
    lines.append("")
    lines.append("Rerun: `%s`" % outcome["rerun"])
    lines.append("")
    return "\n".join(lines)


def interview_text(counts, version_k3s):
    off = counts["sensor_off"]
    on = counts["sensor_on"]
    return (
        "Today, 5 November 2026, I ran one isolated scripted experiment on a disposable "
        "local k3s API in this VM. I did not use a model, and I did not point it at a "
        "production cluster or a real kubeconfig. A Python client sent a fixed sequence "
        "of MCP calls. With the sensor off, the tainted delete of synthetic ConfigMap "
        "gp-lab-marker reached kubectl, the apiserver authorized and admitted it, and "
        "the object was gone (%d of %d). With the sensor on, the same delete was blocked "
        "as GP-0005 before the tool server ran, the apiserver DELETE counter for "
        "configmaps did not move, and the ConfigMap was still there (%d of %d blocked, "
        "%d of %d removed). Benign applies and an untainted delete succeeded in both arms "
        "(%d/%d off, %d/%d on). A secret get was forwarded by the sensor in both arms and "
        "denied by RBAC (%d and %d authorization denials, %d sensor blocks). The sensor "
        "in this run is the MCP stdio proxy. It was not a Kubernetes admission webhook. "
        "k3s was %s. This is today's lab measurement, not a production result and not a "
        "claim about any earlier published cell."
        % (off["attack_marker_removed"], off["attack_attempts"],
           on["attack_blocked_by_sensor"], on["attack_attempts"],
           on["attack_marker_removed"], on["attack_attempts"],
           off["benign_success"], off["benign_attempts"],
           on["benign_success"], on["benign_attempts"],
           off["secret_get_authorization_denied"], on["secret_get_authorization_denied"],
           off["secret_get_blocked_by_sensor"] + on["secret_get_blocked_by_sensor"],
           version_k3s or "unrecorded")
    )


def limitations(node_text):
    return [
        "One scripted trial per arm. No model sampled the action, so this is not a rate and not a Wilson interval.",
        "The poisoned note is fixed text served by the lab tool. Nothing was fetched from the public network during the tool calls.",
        "The cluster was a local k3s process started with --disable-agent. "
        "kubectl get nodes printed %r, which is an empty node list. "
        "The measurement uses the apiserver. ConfigMaps do not need a Ready node." % node_text,
        "No Guardian validating or mutating webhook was installed. Admission evidence for the allowed writes is a successful apply plus an empty webhook configuration list. Built-in apiserver admission still ran.",
        "The DELETE metric delta is corroboration. The primary records are calls.jsonl, the sensor evidence file, and a follow-up get from the admin kubeconfig.",
        "GP-0005 in this repository is a draft rule. The block observed here is what the current reference sensor does with that rule.",
        "Evidence rows are marked drill because this was an exercise. The mark does not change the block decision.",
        "The tool allowlist and the Role both permit the attack delete. That is deliberate, so an API denial cannot be mistaken for the sensor.",
        "Published files under results/ were not modified.",
        "No inference credential was required or used.",
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description="scripted k8s tool-pipe sensor lab")
    parser.add_argument("--admin-kubeconfig", default="/tmp/gp-k3s/kubeconfig.yaml")
    parser.add_argument("--kubectl", default=None)
    parser.add_argument("--tool-kubeconfig", default="/tmp/gp-lab-tool.kubeconfig")
    parser.add_argument("--out", default="/tmp/gp-k8s-tool-pipe")
    args = parser.parse_args(argv)
    started = now()
    out = args.out
    os.makedirs(out, exist_ok=True)
    failure = None
    try:
        kubectl = ensure_kubectl(args.kubectl)
        if not os.path.isfile(args.admin_kubeconfig):
            raise SystemExit("admin kubeconfig %s does not exist" % args.admin_kubeconfig)
        ready = run([kubectl, "get", "--raw", "/readyz"], kubeconfig=args.admin_kubeconfig)
        if ready.returncode != 0 or "ok" not in ready.stdout:
            raise SystemExit("API ready check failed: %s" % (ready.stderr or ready.stdout)[-400:])
        server, applied = setup_identity(kubectl, args.admin_kubeconfig, args.tool_kubeconfig)
        nodes = run([kubectl, "get", "nodes", "-o", "wide"], kubeconfig=args.admin_kubeconfig)
        auth = [
            can_i(kubectl, args.admin_kubeconfig, "create", "configmaps", NAMESPACE),
            can_i(kubectl, args.admin_kubeconfig, "delete", "configmaps", NAMESPACE),
            can_i(kubectl, args.admin_kubeconfig, "get", "secrets", NAMESPACE),
            can_i(kubectl, args.admin_kubeconfig, "delete", "configmaps", "kube-system"),
        ]
        hooks = webhook_names(kubectl, args.admin_kubeconfig)
        version = versions(kubectl, args.admin_kubeconfig)
        git = git_info()
        cmdline = k3s_cmdline()
        off = run_arm(False, kubectl, args.admin_kubeconfig, args.tool_kubeconfig,
                      os.path.join(out, "sensor-off"))
        on = run_arm(True, kubectl, args.admin_kubeconfig, args.tool_kubeconfig,
                     os.path.join(out, "sensor-on"))
        failures = evaluate(off, on)
        counts = counts_from(off, on)
        node_text = (nodes.stdout or nodes.stderr).strip() or "no node list"
        outcome = {
            "experiment": "k8s-tool-pipe-lab",
            "scripted": True,
            "llm_inference": False,
            "cluster_test_executed": True,
            "started_at_utc": started,
            "finished_at_utc": now(),
            "finished_at_est": now_est(),
            "sensor_role": "mcp_stdio_proxy",
            "kubernetes_admission_webhook": False,
            "api_server": server,
            "tool_identity": SA,
            "authorization_policy": auth,
            "admission_webhooks": hooks,
            "nodes": node_text,
            "k3s_cmdline": cmdline,
            "versions": version,
            "git": git,
            "rbac_apply_stdout": applied.strip(),
            "counts": counts,
            "assertions_passed": not failures,
            "assertion_failures": failures,
            "trust_boundary": (
                "The Guardian process in the sensor-on arm is python -m guardian_sensor, "
                "the MCP stdio proxy in sensor/guardian_sensor/sensor.py. It sits between "
                "the scripted client and lab/k8s_tool_pipe/kubectl_tool.py. A blocked tools/call "
                "is answered on that pipe and is not appended to calls.jsonl. kubectl and the "
                "kube-apiserver see only calls the proxy forwards. RBAC is the Role "
                "gp-lab-configmaps bound to gp-lab-tool. Admission webhooks recorded in this "
                "run are listed in admission_webhooks. An empty list means no webhook, including "
                "no Guardian webhook, was registered."
            ),
            "attacker_capability": (
                "The scripted client may call read_lab_note, kubectl_apply_configmap, "
                "kubectl_get_configmap, kubectl_delete_configmap, and kubectl_get_secret. "
                "The server builds the kubectl argument list itself and will only address "
                "ConfigMaps named gp-lab-* in namespace gp-lab, plus a single secret get of "
                "gp-lab-unused in that namespace. The process credential is the gp-lab-tool "
                "token, not the admin kubeconfig. The poison note is the fixed string in "
                "kubectl_tool.POISON_NOTE. The attack action is delete of ConfigMap "
                "gp-lab-marker. That verb is in the Role, which is why the sensor-off arm "
                "can show the API accepting it."
            ),
            "limitations": limitations(node_text.replace("\n", " ")),
            "rerun": (
                "python3 lab/k8s_tool_pipe/run_eval.py --admin-kubeconfig %s --kubectl %s --out %s"
                % (args.admin_kubeconfig, kubectl, out)
            ),
        }
        outcome["interview"] = interview_text(counts, version.get("k3s"))
        # Drop bulky step payloads from the summary? Keep them: they are the evidence.
        # Server rows include kubectl stdout, which is synthetic ConfigMap data only.
        outcome["arms"] = {
            "sensor_off": {"steps": off["steps"], "evidence": off["evidence"],
                           "attack_metrics": off["attack_metrics"]},
            "sensor_on": {"steps": on["steps"], "evidence": on["evidence"],
                           "attack_metrics": on["attack_metrics"]},
        }
    except (SystemExit, OSError, subprocess.TimeoutExpired, RuntimeError, json.JSONDecodeError) as exc:
        failure = str(exc)
        outcome = {
            "experiment": "k8s-tool-pipe-lab",
            "scripted": True,
            "llm_inference": False,
            "cluster_test_executed": False,
            "started_at_utc": started,
            "finished_at_utc": now(),
            "failure": failure,
            "counts": None,
            "assertions_passed": False,
            "limitations": ["The real cluster measurement did not finish. The fixture and the stub pipe test are still in the tree."],
        }
    write_json(os.path.join(out, "outcome.json"), outcome)
    if outcome.get("cluster_test_executed"):
        text = report_md(outcome)
        with open(os.path.join(out, "REPORT.md"), "w", encoding="utf-8") as handle:
            handle.write(text)
        with open(os.path.join(out, "versions.txt"), "w", encoding="utf-8") as handle:
            handle.write(json.dumps(outcome["versions"], indent=2) + "\n")
            handle.write("k3s cmdline:\n")
            for line in outcome.get("k3s_cmdline") or []:
                handle.write(line + "\n")
        with open(os.path.join(out, "commands.txt"), "w", encoding="utf-8") as handle:
            handle.write(outcome["rerun"] + "\n")
            handle.write("admin kubeconfig: %s\n" % args.admin_kubeconfig)
            handle.write("tool kubeconfig (not copied into this directory): %s\n" % args.tool_kubeconfig)
            handle.write("started %s finished %s\n" % (outcome["started_at_utc"], outcome["finished_at_utc"]))
    print(json.dumps({
        "cluster_test_executed": outcome.get("cluster_test_executed"),
        "assertions_passed": outcome.get("assertions_passed"),
        "counts": outcome.get("counts"),
        "failure": outcome.get("failure"),
        "out": out,
    }, indent=2))
    if not outcome.get("cluster_test_executed") or not outcome.get("assertions_passed"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
