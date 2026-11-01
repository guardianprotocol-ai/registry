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
