# Lab: the sensor in front of a Cluster API management cluster

Eighteen scripted sessions with a simulated management cluster, each run with the
Guardian sensor absent and with it in block mode. Eleven are attacks the sensor must
stop. Seven are ordinary work it must leave alone.

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
| `test_lab.py` | Runs every case in both arms. `python3 check.py` runs this |

## Limits

Scripted calls, so no model chose them. A simulated fleet, so no Kubernetes API was
contacted and no Cluster API controller ran. One run per arm. Draft rules. The tool and
argument names of the structured cases follow published Kubernetes MCP servers, none of
which was run. Results here are not the published matrix, and nothing under `results/`
is touched.

[lab/k8s_tool_pipe](../k8s_tool_pipe) puts the sensor in front of a real API server
for a simpler rule.
