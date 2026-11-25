# Detection coverage suite

`scripts/detection_coverage.py` replays fixtures the repository already has through the
MCP proxy sensor, and reports what the sensor did with each, across every pattern in the
catalog. The generated result is [DETECTION_COVERAGE.md](DETECTION_COVERAGE.md).
`python3 check.py` runs it, so CI runs it on every pull request and every push to `main`.

It is defensive regression testing. Its job is to notice when a change to the sensor, its
rules or its corpus stops a known case being caught, and to keep the gaps in the catalog
visible.

```bash
python3 scripts/detection_coverage.py           # print the summary
python3 scripts/detection_coverage.py --json    # everything, machine readable
python3 scripts/detection_coverage.py --write   # regenerate docs/DETECTION_COVERAGE.md
python3 scripts/detection_coverage.py --check   # what check.py runs
python3 scripts/tests/test_detection_coverage.py
```

## What it replays

Nothing new is written for it. The fixtures are:

- **Attack corpus cases**, at most two per pattern, the first by file name, from
  `corpus/attacks/`. Each case's events go through `Sensor.inspect_request` and
  `Sensor.inspect_response`, the same two functions the stdio pump calls. A tool output
  is a forwarded call to its source tool followed by the result coming back, which is
  where taint is set. A call is refused or forwarded by the sensor itself.
- **The two tool definition fixtures** the test server already has: its weather tool's
  description changing after approval (GP-0003), and a tool appearing after approval
  under `GUARDIAN_ADD` (GP-0019). These run through the real proxy process in front of
  `sensor/tests/fake_server.py`, and the server's own call log decides whether the call
  reached it.
- **Every benign corpus case**, through the same path, which should be forwarded with
  nothing recorded.

Each fixture's outcome is **blocked** (refused before it was forwarded, and for the server
fixtures, never seen by the server), **flagged** (recorded as evidence and forwarded), or
**missed**. Each pattern is then **blocked** if every fixture was, **detected, not always
blocked**, **missed**, or **no fixture**, with its MITRE ATLAS mapping beside it.

## What it adds to the rule gate

`scripts/rule_gate.py` calls the shared rule engine directly and checks every corpus case
raises its pattern. That stays the test for a rule. This suite does not repeat it. It
adds three things:

1. **The proxy's decision.** Which hits are refused and which are only recorded depends on
   the sensor, not on the rules: the mode, the baseline rule for canaries, the refusal
   itself, the tool pins. This measures that.
2. **Tool definition patterns.** GP-0003 and GP-0019 are checked by the sensor rather than
   the rule engine, so the gate cannot replay them (`corpus/policy.json` lists GP-0003 as
   covered elsewhere). Here they run.
3. **The catalog.** Every pattern file is a row, with its ATLAS techniques, whether the
   sensor has a rule for it, and whether anything was replayed. A pattern nobody wrote a
   fixture for reads as a gap, not as a pass.

## What fails the check

- An attack fixture that is no longer detected.
- Ordinary work blocked that is not a false alarm already tracked in its case.
- A page that no longer matches the tree. A fixture that drops from blocked to flagged,
  or a pattern that gains or loses a fixture, changes the page, so the pull request that
  caused it has to regenerate it and the change shows in the diff.

## Limits

- **Scripted cases, not a measurement of attacks.** A replayed fixture shows that the
  sensor still catches one known, scripted input. It is not a detection rate, says nothing
  about rephrasings, and is not a pentest, a red team exercise or evidence of catching
  anything in the wild. [PROGRAM.md](../PROGRAM.md) records that every sighting in the
  exchange is still `source: drill`.
- **Small by design.** Two fixtures per pattern. Patterns with more corpus cases are
  covered more fully by the rule gate.
- **In process for corpus cases.** Corpus cases call the sensor's request and response
  handlers directly rather than through a subprocess, because the corpus format has no
  server to answer the output events. The handlers are the code the pump runs. The JSON
  framing and pipes are exercised only by the two server fixtures and by
  `sensor/tests/test_sensor.py`.
- **Output side patterns are flagged by design.** GP-0006 and GP-0010 are detected in what
  a tool returns. The sensor records them and taints the session. It does not withhold
  tool output, so they never read as blocked.
- **Registered canaries have no fixture here.** GP-0020 and GP-0041 fire on values and
  paths each operator registers, which a shared corpus cannot hold. They are measured by
  `benchmarks/canary_benchmark.py` and `benchmarks/assumed_breach.py`.
- **Most of the catalog has no fixture.** Most draft patterns are documented ideas with no
  rule and no corpus case. The page counts them rather than leaving them out.
- **Nothing it does can become a sighting.** Evidence is written to a temporary directory
  and deleted, against a throwaway Guardian home, with the repository's own rules pinned.
