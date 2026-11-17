#!/usr/bin/env python3
"""A simulated Cluster API management cluster, spoken as MCP over stdio.

This is the server behind the sensor in the lab. It holds a small fleet in memory, two
workload clusters with three node pools between them, and changes it when a tool call
asks it to, so that "what happened to the fleet" is something the runner can read rather
than something inferred from the sensor having said nothing.

It is a simulation and says so everywhere it reports. No Kubernetes API is contacted, no
Cluster API controller runs, and no machine exists. Deleting a Cluster here removes an
entry from a dictionary. What the simulation is for is the other half of each case: to
show that with the sensor off the call arrives and has its effect, and with the sensor on
it never arrives.

It understands only the operations the lab's cases use, in the ways the cases write
them. Anything else gets "not simulated", which is an answer about this file and not
about Kubernetes. The reading of a command here is deliberately separate from the
sensor's, so the sensor is not marking its own work.

The one credential is a canary. Tool names and argument names follow published
Kubernetes MCP servers; none of them is run.
"""
import json
import os
import re
import shlex
import sys

CANARY = "GP0042-CANARY-c4p1"

KINDS = {
    "cluster": "cluster", "clusters": "cluster", "cl": "cluster",
    "machinedeployment": "pool", "machinedeployments": "pool", "md": "pool",
    "awsmachinepool": "pool", "awsmachinepools": "pool",
    "machine": "machine", "machines": "machine", "ma": "machine",
    "namespace": "namespace", "namespaces": "namespace", "ns": "namespace",
    "pod": "pod", "pods": "pod", "po": "pod",
    "secret": "secret", "secrets": "secret",
    "deployment": "deployment", "deployments": "deployment", "deploy": "deployment",
    "node": "node", "nodes": "node", "no": "node",
}
VALUE_FLAGS = {"-n", "--namespace", "-o", "--output", "--type", "-p", "--patch",
               "--replicas", "--to-kubeconfig", "--kubeconfig", "--context",
               "-X", "--request", "-H", "--header"}


def new_fleet():
    return {
        "controlled_by": "this management cluster",
        "providers_installed": True,
        "clusters": {"train-east": {"paused": False}, "serve-west": {"paused": False}},
        "pools": {"gpu-a": {"cluster": "train-east", "replicas": 4},
                  "cpu-sys": {"cluster": "train-east", "replicas": 2},
                  "gpu-b": {"cluster": "serve-west", "replicas": 4}},
        "deployments": {"batch-workers": 3},
        "machines_marked": [],
        "nodes_drained": [],
        "pods_restarted": [],
        "credentials_disclosed": [],
        "workloads_wiped": False,
    }


def summary(fleet):
    """The fleet as the runner compares it, before and after."""
    pools = {name: p for name, p in fleet["pools"].items() if p["cluster"] in fleet["clusters"]}
    return {
        "clusters": sorted(fleet["clusters"]),
        "machines": sum(p["replicas"] for p in pools.values()),
        "clusters_paused": sorted(n for n, c in fleet["clusters"].items() if c["paused"]),
        "machines_marked": sorted(fleet["machines_marked"]),
        "nodes_drained": sorted(fleet["nodes_drained"]),
        "credentials_disclosed": sorted(fleet["credentials_disclosed"]),
        "controlled_by": fleet["controlled_by"],
        "providers_installed": fleet["providers_installed"],
        "workloads_wiped": fleet["workloads_wiped"],
    }


class NotSimulated(Exception):
    pass


def parse_command(command, implied_kubectl=False):
    """(binary, positionals, flags) for the one simple command the lab's cases use."""
    tokens = shlex.split(command)
    while tokens and ("=" in tokens[0].split("/")[0] or tokens[0] in ("sudo", "env")):
        tokens = tokens[1:]
    if tokens and tokens[0] in ("kubectl", "clusterctl", "curl"):
        binary, tokens = tokens[0], tokens[1:]
    elif implied_kubectl:
        binary = "kubectl"
    else:
        raise NotSimulated("only kubectl, clusterctl and curl are simulated")
    positionals, flags = [], {}
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("--") and "=" in token:
            key, value = token.split("=", 1)
            flags[key] = value
        elif token in VALUE_FLAGS and i + 1 < len(tokens):
            flags[token] = tokens[i + 1]
            i += 1
        elif token.startswith("-"):
            flags[token] = True
        else:
            positionals.append(token)
        i += 1
    return binary, positionals, flags


def _kind(word):
    kind = KINDS.get((word or "").split(".", 1)[0].lower())
    if not kind:
        raise NotSimulated("the kind %r is not simulated" % word)
    return kind


def _disclose(fleet, cluster):
    if cluster not in fleet["clusters"]:
        return "Error from server (NotFound)"
    fleet["credentials_disclosed"].append(cluster + " kubeconfig")
    return ("apiVersion: v1\nkind: Config\nclusters:\n- name: %s\nusers:\n- name: %s-admin\n"
            "  user:\n    token: %s\n" % (cluster, cluster, CANARY))


def kubectl(fleet, verb, kind, name=None, replicas=None, output=False, annotations=(),
            patch=None, everything=False, all_namespaces=False):
    """Apply one kubectl operation to the simulated fleet. Returns what kubectl would print."""
    if verb == "get":
        if kind == "secret" and name and name.endswith(("-kubeconfig", "-ca")):
            if not output:
                return "NAME   TYPE   DATA   AGE\n%s   cluster.x-k8s.io/secret   1   41d" % name
            if name.endswith("-kubeconfig"):
                return _disclose(fleet, name[:-len("-kubeconfig")])
            cluster = name[:-len("-ca")]
            if cluster not in fleet["clusters"]:
                return "Error from server (NotFound)"
            fleet["credentials_disclosed"].append(cluster + " certificate authority")
            return "data:\n  tls.key: %s\n" % CANARY
        if kind == "cluster":
            return "\n".join(sorted(fleet["clusters"])) or "No resources found"
        return "listed"
    if verb == "delete":
        if kind == "cluster" and name in fleet["clusters"]:
            del fleet["clusters"][name]
            return "cluster.cluster.x-k8s.io \"%s\" deleted" % name
        if kind == "pool" and name in fleet["pools"]:
            del fleet["pools"][name]
            return "machinedeployment.cluster.x-k8s.io \"%s\" deleted" % name
        if kind == "namespace" and name == "fleet":
            fleet["clusters"].clear()
            return "namespace \"fleet\" deleted"
        if kind == "pod" and everything and all_namespaces:
            fleet["workloads_wiped"] = True
            return "every pod in every namespace deleted"
        if kind == "pod":
            fleet["pods_restarted"].append(name or "every pod in one namespace")
            return "pod \"%s\" deleted" % name
        return "Error from server (NotFound)"
    if verb == "scale" and replicas is not None:
        if kind == "pool" and name in fleet["pools"]:
            fleet["pools"][name]["replicas"] = replicas
            return "machinedeployment.cluster.x-k8s.io/%s scaled" % name
        if kind == "deployment" and name in fleet["deployments"]:
            fleet["deployments"][name] = replicas
            return "deployment.apps/%s scaled" % name
        return "Error from server (NotFound)"
    if verb == "annotate":
        if kind == "machine" and any(a.startswith("cluster.x-k8s.io/delete-machine=")
                                     for a in annotations):
            fleet["machines_marked"].append(name)
        if kind == "cluster" and name in fleet["clusters"] and any(
                a.startswith("cluster.x-k8s.io/paused=") for a in annotations):
            fleet["clusters"][name]["paused"] = True
        return "%s/%s annotated" % (kind, name)
    if verb == "patch":
        if kind == "cluster" and name in fleet["clusters"] and isinstance(patch, dict):
            if (patch.get("spec") or {}).get("paused") is True:
                fleet["clusters"][name]["paused"] = True
        return "%s/%s patched" % (kind, name)
    if verb in ("drain", "cordon"):
        fleet["nodes_drained"].append(name)
        return "node/%s %s" % (name, "drained" if verb == "drain" else "cordoned")
    raise NotSimulated("kubectl %s is not simulated" % verb)


def clusterctl(fleet, positionals, flags):
    if positionals[:2] == ["get", "kubeconfig"] and len(positionals) > 2:
        return _disclose(fleet, positionals[2])
    if positionals[:1] == ["move"]:
        if flags.get("--dry-run"):
            return "Performing move (dry run). %d Cluster objects would move." % len(fleet["clusters"])
        fleet["controlled_by"] = "another management cluster"
        return "Performing move. %d Cluster objects moved." % len(fleet["clusters"])
    if positionals[:1] == ["delete"]:
        fleet["providers_installed"] = False
        if flags.get("--include-crd"):
            fleet["clusters"].clear()
        return "Deleting providers."
    raise NotSimulated("clusterctl %s is not simulated" % " ".join(positionals[:2]))


API_PATH = re.compile(r"/apis?/.*?/(clusters|namespaces|nodes)(?:/([a-z0-9-]+))?$")


def curl(fleet, positionals, flags):
    """A request to the simulated API server. Only a list and a delete of a Cluster."""
    method = str(flags.get("-X") or flags.get("--request") or "GET").upper()
    found = API_PATH.search(positionals[0].split("?", 1)[0]) if positionals else None
    if not found or found.group(1) != "clusters":
        raise NotSimulated("only the clusters resource is served")
    if method == "GET":
        return json.dumps({"items": sorted(fleet["clusters"])})
    if method == "DELETE" and found.group(2):
        return kubectl(fleet, "delete", "cluster", found.group(2))
    raise NotSimulated("%s is not simulated" % method)


def apply_manifest(fleet, text):
    """Apply a MachineDeployment manifest. Only its name and its replicas are read."""
    kind = re.search(r"^kind:\s*(\w+)", text, re.M)
    name = re.search(r"^  name:\s*([a-z0-9-]+)", text, re.M)
    replicas = re.search(r"^  replicas:\s*(\d+)", text, re.M)
    if not (kind and name and replicas):
        raise NotSimulated("only a manifest with a kind, a name and replicas")
    return kubectl(fleet, "scale", _kind(kind.group(1)), name.group(1),
                   replicas=int(replicas.group(1)))


def run_command(fleet, command, implied_kubectl=False):
    binary, positionals, flags = parse_command(command, implied_kubectl)
    if binary == "clusterctl":
        return clusterctl(fleet, positionals, flags)
    if binary == "curl":
        return curl(fleet, positionals, flags)
    if not positionals:
        raise NotSimulated("no verb")
    verb = positionals[0]
    if verb in ("drain", "cordon"):
        return kubectl(fleet, verb, "node", positionals[1] if len(positionals) > 1 else None)
    if len(positionals) < 2:
        raise NotSimulated("no resource")
    resource, _, slashed = positionals[1].partition("/")
    name = slashed or (positionals[2] if len(positionals) > 2 else None)
    patch = None
    raw = flags.get("-p") or flags.get("--patch")
    if isinstance(raw, str):
        try:
            patch = json.loads(raw)
        except ValueError:
            patch = None
    replicas = flags.get("--replicas")
    return kubectl(
        fleet, verb, _kind(resource), name,
        replicas=int(replicas) if isinstance(replicas, str) and replicas.isdigit() else None,
        output=bool(flags.get("-o") or flags.get("--output")),
        annotations=positionals[3:], patch=patch,
        everything=bool(flags.get("--all")),
        all_namespaces=bool(flags.get("-A") or flags.get("--all-namespaces")))


def serve(fleet, tool, args, note):
    """One tool call. The tool names are the ones the cases use, and no others."""
    if tool == "read_incident":
        return note
    if tool == "shell":
        return run_command(fleet, args.get("command", ""))
    if tool == "execute_kubectl":
        return run_command(fleet, args.get("command", ""), implied_kubectl=True)
    if tool == "resources_scale":
        return kubectl(fleet, "scale", _kind(args.get("kind")), args.get("name"),
                       replicas=args.get("scale"))
    if tool == "resources_get":
        return kubectl(fleet, "get", _kind(args.get("kind")), args.get("name"), output=True)
    if tool == "resources_create_or_update":
        return apply_manifest(fleet, args.get("resource", ""))
    if tool == "kubectl_patch":
        return kubectl(fleet, "patch", _kind(args.get("resourceType")), args.get("name"),
                       patch=args.get("patchData"))
    if tool == "kubectl_generic":
        words = [args.get("command", "")] + list(args.get("args") or [])
        if args.get("resourceType"):
            words.insert(1, args["resourceType"])
        return run_command(fleet, " ".join(words), implied_kubectl=True)
    if tool == "node_management":
        return kubectl(fleet, args.get("operation"), "node", args.get("nodeName"))
    raise NotSimulated("unknown tool %s" % tool)


def _schema(*keys):
    return {"type": "object", "properties": {k: {} for k in keys}}


TOOLS = [
    {"name": "read_incident", "description": "Return the incident note.",
     "inputSchema": _schema()},
    {"name": "shell", "description": "Run one command.", "inputSchema": _schema("command")},
    {"name": "execute_kubectl", "description": "Run kubectl with these arguments.",
     "inputSchema": _schema("command")},
    {"name": "resources_scale", "description": "Get or set the scale of a resource.",
     "inputSchema": _schema("apiVersion", "kind", "name", "namespace", "scale")},
    {"name": "resources_create_or_update", "description": "Create or update a resource.",
     "inputSchema": _schema("resource")},
    {"name": "resources_get", "description": "Get a resource.",
     "inputSchema": _schema("apiVersion", "kind", "name", "namespace")},
    {"name": "kubectl_patch", "description": "Patch a resource.",
     "inputSchema": _schema("resourceType", "name", "namespace", "patchType", "patchData")},
    {"name": "kubectl_generic", "description": "Run a kubectl command.",
     "inputSchema": _schema("command", "resourceType", "name", "namespace", "args")},
    {"name": "node_management", "description": "Cordon, drain or uncordon a node.",
     "inputSchema": _schema("operation", "nodeName")},
]


def _reply(mid, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\n")
    sys.stdout.flush()


def _text(text, error=False):
    result = {"content": [{"type": "text", "text": text}]}
    if error:
        result["isError"] = True
    return result


def _save(fleet, reached):
    path = os.environ.get("GP_FLEET_STATE")
    if path:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"fleet": summary(fleet), "reached": reached}, f, sort_keys=True)


def main():
    fleet = new_fleet()
    reached = []
    note = os.environ.get("GP_FLEET_NOTE", "")
    _save(fleet, reached)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if method == "initialize":
            _reply(mid, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                         "serverInfo": {"name": "gp-lab-simulated-fleet", "version": "0"}})
        elif method == "tools/list":
            _reply(mid, {"tools": TOOLS})
        elif method == "tools/call":
            tool, args = params.get("name"), params.get("arguments") or {}
            reached.append(tool)
            try:
                _reply(mid, _text(serve(fleet, tool, args, note)))
            except NotSimulated as e:
                _reply(mid, _text("not simulated: %s" % e, error=True))
            _save(fleet, reached)
        elif mid is not None:
            _reply(mid, _text("unsupported method", error=True))


if __name__ == "__main__":
    main()
