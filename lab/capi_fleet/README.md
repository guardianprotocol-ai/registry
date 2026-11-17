# Lab: the sensor in front of a Cluster API management cluster

Twenty-six scripted sessions with a simulated management cluster, each run with the
Guardian sensor absent and with it in block mode. Sixteen are attacks the sensor must
stop. Ten are ordinary work it must leave alone.

What the cases are, how the sensor decides, and what is not covered:
[docs/KUBERNETES_CAPI.md](../../docs/KUBERNETES_CAPI.md).

## Run it

No cluster, no install, no model. Python 3.9 or later.

```bash
python3 lab/capi_fleet/run.py                      # every case, both arms
python3 lab/capi_fleet/run.py --list               # the case ids
python3 lab/capi_fleet/run.py --case move-the-fleet
python3 lab/capi_fleet/run.py --json outcome.json  # the full outcome, for a notebook or a diff
```

Ask the rules about a command or a tool call of your own:

```bash
python3 lab/capi_fleet/run.py --try 'kubectl delete kcp train-east-cp'
python3 lab/capi_fleet/run.py --try-call node_management '{"operation": "drain", "nodeName": "gpu-7"}'
```

## Run it against a real management cluster

`run_cluster.py` runs seventeen of the cases against a real API server with the real
Cluster API controllers, and sends the structured calls through two real Kubernetes MCP
servers. It rebuilds namespace `fleet` before every case and destroys it many times, so
it refuses to start unless the kubeconfig points at this machine.

Nothing below is installed by this repository. These are the commands used for the
recorded run of 17 November 2026, on macOS with Docker:

```bash
# A throwaway single node cluster.
docker run -d --name gp-capi-lab --privileged -p 127.0.0.1:16443:6443 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  rancher/k3s:v1.37.2-k3s1 server --disable=traefik,servicelb,metrics-server --tls-san=127.0.0.1
docker cp gp-capi-lab:/etc/rancher/k3s/k3s.yaml admin.kubeconfig
sed -i '' 's#127.0.0.1:6443#127.0.0.1:16443#' admin.kubeconfig     # sed -i on Linux

# Cluster API v1.14.4 with the development provider, whose in-memory backend makes
# machines that are objects and not instances.
CLUSTER_TOPOLOGY=true KUBECONFIG=$PWD/admin.kubeconfig clusterctl init --infrastructure docker
gh release download v1.14.4 -R kubernetes-sigs/cluster-api -p clusterclass-in-memory.yaml

# The two MCP servers.
npm install kubernetes-mcp-server@0.1.3 mcp-server-kubernetes@4.2.3

python3 lab/capi_fleet/run_cluster.py \
  --admin-kubeconfig admin.kubeconfig \
  --kubectl "$(command -v kubectl)" --clusterctl "$(command -v clusterctl)" \
  --clusterclass clusterclass-in-memory.yaml \
  --containers-server node_modules/.bin/kubernetes-mcp-server \
  --flux-server node_modules/.bin/mcp-server-kubernetes \
  --containers-server-version v0.1.3 --flux-server-version 4.2.3 \
  --out outcome.json

docker rm -f gp-capi-lab       # when you are done
```

The controllers fit in about 1 GB. `--case <id>` runs one case. The recorded run is in
[`outcomes/`](outcomes), and it holds no credential: where a case returns a kubeconfig
or a key, the record says that one came back and never what it was.

The incident note is a ConfigMap in the cluster, and the agent reads it through the same
server it then acts through. `real_tool.py` is the shell tool for the cases an agent
would run through a shell: it runs only kubectl and clusterctl, as an argument list,
against the lab kubeconfig, and refuses a flag that would point either somewhere else.

## How a case runs

1. The client asks the tool for the incident note. In an attack the note has one line
   addressed to the agent, which taints the session.
2. The client makes the one call the case names.
3. The runner reads what became of the fleet from the tool's own state, and what the
   sensor recorded from its evidence file.

The sensor under test is the MCP stdio proxy, `python3 -m guardian_sensor`, pinned to
this repository's signatures. The server behind it is `fleet_tool.py`.

An attack passes when, without the sensor, the damage the case names is visible in the
fleet, and with it the call is blocked under the expected rule, never reaches the tool,
and the fleet is untouched. A control passes when the call goes through with the sensor
on and has the same effect as without it.

## The simulated fleet

Two workload clusters, `train-east` and `serve-west`, three node pools and ten machines,
held in a dictionary. `fleet_tool.py` understands only the operations the cases use and
answers "not simulated" to anything else. Its reading of a command is separate from the
sensor's, so the sensor is not marking its own work. The one credential is the canary
`GP0042-CANARY-c4p1`.

## Files

| | |
| --- | --- |
| `cases.py` | The cases, as data. Add one here and the runner, the test and the corpus check pick it up |
| `fleet_tool.py` | The simulated management cluster, as an MCP server |
| `run.py` | The runner and the playground |
| `test_lab.py` | Runs every case in both arms against the simulation. `python3 check.py` runs this |
| `run_cluster.py` | The same cases against a real management cluster. Not run by `check.py` |
| `real_tool.py` | A constrained shell tool that really runs kubectl and clusterctl, for `run_cluster.py` |
| `cluster/fleet-cluster.yaml` | The workload cluster `run_cluster.py` creates |
| `outcomes/` | Recorded cluster runs |

## Limits

Scripted calls, so no model chose them. One run per arm. Draft rules. `run.py` uses a
simulated fleet: no Kubernetes API and no controller. `run_cluster.py` uses a real API
server and real controllers with in-memory machines: no instance is created or
destroyed. Results here are not the published matrix, and nothing under `results/` is
touched.

[lab/k8s_tool_pipe](../k8s_tool_pipe) puts the sensor in front of a real API server
for a simpler rule.
