# Canary benchmark

How often the reference sensor's registered-canary rule (GP-0020) sees a fake value leave
in a tool call, and how often it fires on text that does not contain one.

```bash
python3 benchmarks/canary_benchmark.py --seed 20261031 --trials 30 --e2e-trials 20 --latency-iters 2000
```

That writes `benchmarks/canary-benchmark.json` and `benchmarks/canary-benchmark.md`. The
markdown is the table to cite. Do not type numbers into it.

The regression suite is the local run that found the gaps: seven canary shapes, the
carriers that run was built for, four formatting edges, and the encodings that change the
value. A copy of the pre-fix matcher is scored on the same trials. The check
`legacy_reproduces_published_before` is true when that copy still produces 1980/2100,
0/840, 150/1260, 2130/4200 and a benign false-alarm count of 0/2100.

Held-out transforms are reported and are not a pass/fail gate. They were chosen as forms
the matcher does not attempt, and their scores were not used to add those forms.

```bash
python3 benchmarks/canary_benchmark.py --fast --check
```

The fast subset is what `python3 check.py` runs. It does not overwrite the committed
report. `--check` fails unless every regression path is fully detected and the benign
GP-0020 count is zero.

Every value is generated for the run. Destinations are `127.0.0.1` or a `.test` name. The
in-process trials do not open a socket. The end-to-end trials use
`sensor/tests/fake_server.py` through the real proxy.

What the numbers do and do not mean is in [THREAT_MODEL.md](THREAT_MODEL.md).

## Assumed breach, one host

```bash
python3 benchmarks/assumed_breach.py
```

That writes `benchmarks/assumed-breach.json` and `benchmarks/assumed-breach.md`. The
limits are in [ASSUMED_BREACH.md](ASSUMED_BREACH.md). `python3 check.py` runs
`python3 benchmarks/assumed_breach.py --fast --check`, which does not overwrite the
committed report.

## Assumed breach, four hosts

```bash
python3 benchmarks/multi_host_breach.py
```

That writes `benchmarks/multi-host-breach.json` and `benchmarks/multi-host-breach.md`.
Four network namespaces stand in for a workstation, a data server, a repo host and a
hub. The sweep is scripted. The limits, including what a late quarantine does not undo,
are in [MULTI_HOST.md](MULTI_HOST.md).

```bash
python3 benchmarks/multi_host_breach.py --fast --check
```

The fast subset is what `python3 check.py` runs. It does not overwrite the committed
report. `--check` fails if a protected host missed the workstation, if the benign phase
tripped, or if a seeded value was written into a record. It does not fail because the
next host was still unlocked when the hop connected. That race is a result, and the
table reports it.
