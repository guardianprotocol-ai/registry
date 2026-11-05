# Lab: sensor on a kubectl tool pipe

A scripted check of the Guardian sensor in front of a small kubectl tool,
against a Kubernetes API you start yourself. The client sends fixed MCP
calls. No model is in the loop.

The sensor under test is the MCP stdio proxy (`python3 -m guardian_sensor`).
The same code path is described in [sensor/README.md](../../sensor/README.md).
This lab does not register a Kubernetes admission webhook.

## What the two arms show

The tool identity can apply and delete ConfigMaps in namespace `gp-lab`,
and cannot read Secrets. The sequence is the same with the proxy absent
and with the proxy in block mode.

* An untainted apply and an untainted delete are ordinary lab work. Both
  reach the API.
* A fixed note then taints the session. The note matches the instruction
  signatures. See [GP-0005](../../patterns/GP-0005.yaml).
* A later apply of a second ConfigMap still reaches the API.
* A later delete of `gp-lab-marker` is the attack. The Role allows it.
  With the sensor off, the API admits the delete and the object is gone.
  With the sensor on, the proxy blocks GP-0005 and kubectl is not run.
* A get of Secret `gp-lab-unused` is forwarded in both arms. The API
  answers Forbidden. That denial is authorization, not the sensor.

Harness resets, between arms, use the admin kubeconfig and are not tool
calls. The tool process is given only the `gp-lab-tool` kubeconfig.

## Run the stub test

This does not need a cluster. The kubectl it runs is a stub.

```bash
python3 lab/k8s_tool_pipe/test_tool.py
```

`python3 check.py` runs that file. It does not start Kubernetes.

## Run it against a local API

One disposable control plane is enough. This is the k3s invocation used
on 5 November 2026, with the agent disabled so the API could come up
without pulling workload images:

```bash
sudo /tmp/k3s server \
  --data-dir /tmp/gp-k3s \
  --write-kubeconfig /tmp/gp-k3s/kubeconfig.yaml \
  --write-kubeconfig-mode 644 \
  --disable-agent \
  --disable=traefik,servicelb,metrics-server,coredns \
  --flannel-backend=none \
  --disable-network-policy \
  --tls-san=127.0.0.1
```

Then:

```bash
python3 lab/k8s_tool_pipe/run_eval.py \
  --admin-kubeconfig /tmp/gp-k3s/kubeconfig.yaml \
  --out /tmp/gp-k8s-tool-pipe
```

The summary is `/tmp/gp-k8s-tool-pipe/outcome.json`. Raw transcripts,
`calls.jsonl`, and the sensor evidence file are under `sensor-off/` and
`sensor-on/`. The lab token stays in `/tmp/gp-lab-tool.kubeconfig` and
is not written into the output directory.

If the API is down, the script exits non-zero and writes
`cluster_test_executed: false`. It does not fill in zero counts for a
run that did not happen.

## Limits

One trial per arm. Draft rule GP-0005. Synthetic ConfigMaps only.
Results in this directory are not the published matrix. Files under
`results/` are untouched.
