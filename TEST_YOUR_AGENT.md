# Test your own agent

For a founder who wants to know whether their agent falls for known attacks. No code to
write, nothing to sign up for, and nothing leaves your machine unless you choose to share it.
About twenty minutes.

## What the scan does, and does not do

It runs known attacks on AI agents against a target and reports how often each one worked,
as a rate over many runs with a 95% interval, because agents do not behave the same way
twice.

Every payload is harmless by construction. Secrets are canary tokens like
`GP0001-CANARY-7f3a`, destinations are reserved `.test` addresses that resolve nowhere, and
the "web page" and "tools" are a small lab server in this repository. It runs on your
hardware. It does not phone home, and the registry has no server to phone.

What it does not do: it does not test your production system, it does not know about
attacks that are not in the registry yet, and a clean result is not a certificate of anything.

## 1. Get it and check it (3 minutes)

```bash
git clone https://github.com/guardianprotocol-ai/registry.git
cd registry
python3 check.py
```

Python 3.9 or newer, nothing else to install. `check.py` runs every test in the repository;
if it passes, everything below will work.

## 2. See an attack land, then get stopped (1 minute)

```bash
cd demo
python3 demo.py
```

A test agent is asked to summarize a page that hides an instruction. Without the sensor the
secret leaks; with it the send is blocked and evidence is recorded. It writes
`demo/report.html` so you can look at it side by side.

## 3. Run the scan against the reference agents (2 minutes)

```bash
cd ../scanner
python3 -m guardian_scanner list
python3 -m guardian_scanner run --target scripted:vulnerable --repeat 10
python3 -m guardian_scanner run --target scripted:vulnerable --repeat 10 --sensor
```

`list` shows which patterns can be run today and which only validate. The two `run` lines
measure the same scripted agent with the sensor off and then on. The scripted agents are the
control, not the finding: the vulnerable one does what poisoned content tells it, so it
should read 100% without the sensor and 0% with it. If it does not, something is broken,
and that is worth an issue.

## 4. See what your machine can measure

```bash
python3 -m guardian_scanner targets
```

It prints every target, whether the harness is installed, whether credentials are set, and
which harnesses nobody has written a target for yet. `unknown` is an honest answer: a
harness that keeps its own session cannot be checked without spending a call.

## 5. Point it at your own agent

Today the scanner drives one real harness end to end:

```bash
python3 -m guardian_scanner run --target claude-code --repeat 5 --pattern GP-0001
```

That starts a real Claude Code session, headless, over the lab server, and costs tokens.
Nothing reaches for it unless you name it.

### Credentials

The scan never asks for an API key, never stores one and never writes one to disk. Each
harness uses whatever authentication it already has, the same as when you run it yourself:
Claude Code uses your existing session, and Gemini CLI reads `GEMINI_API_KEY` or whatever
auth you configured for it. Your key reaches the harness by being in your shell, and it
passes through nothing in this repository.

Nothing in this repository contains a key, and it never should. If you ever find one, that
is a security report, not an issue: see [SECURITY.md](SECURITY.md).

A second harness is wired and verified:

```bash
export GEMINI_API_KEY=...
python3 -m guardian_scanner run --target gemini-cli --model gemini-3.5-flash \
  --repeat 5 --pattern GP-0003
```

`gemini-cli` completed its first runs against the live API on 2026-10-08, with gemini-cli
0.26.0 and `gemini-3.5-flash`.

**You have to name a model, and the scan refuses to start without one.** Gemini CLI's own
built-in default is retired for newly issued API keys, and it fails inside Gemini's routing
before the scenario even runs: a 404 `ModelNotFoundError`, buried under a Node deprecation
warning and a stack trace. `gemini-3.5-flash` and `gemini-3.5-flash-lite` both worked on
2026-10-08; `gemini-2.5-flash` did not. Google's current models are at
[ai.google.dev/gemini-api/docs/models](https://ai.google.dev/gemini-api/docs/models).

Naming it is also the right thing for a measurement. The model is part of what you measured,
so no target here carries a default: a default would fill the matrix with a model nobody
chose, and would rot the day the vendor retires it.

A fast, cheap model is not a like-for-like comparison with whatever serves another harness.
The matrix records what you asked for, which is the honest unit: one harness, one named
model, one date. It never supports a sentence of the form "vendor A versus vendor B".

**If your harness has neither target,** writing one is the highest-value thing you can do
here, and it is two short methods:

```python
class MyHarnessTarget(CliAgentTarget):
    name = "my-harness"

    def argv(self, prompt, config_path):
        return ["my-harness", "--prompt", prompt, "--mcp-config", config_path]

    def answer_of(self, stdout):
        return json.loads(stdout or "{}").get("text", "")
```

`CliAgentTarget` in `scanner/guardian_scanner/targets.py` does the rest: it writes an MCP
config pointing your harness at the lab server, runs it once per attempt, and hands the
answer to the scenario. Add your class to `_target()` in `__main__.py` and it works with
every pattern that already runs.

Three rules the base class docstring spells out: one run is one process, restrict the
harness to the lab server and nothing else, and raise on a non-zero exit so a broken
harness is counted as errored rather than as a defended one.

Until your harness has a target, you can still run the demo and the scripted scan, and you
can read any pattern's `test` section and run it by hand.

## 6. Record what you measured

```bash
python3 -m guardian_scanner run --target claude-code --repeat 20 --record ../results
python3 -m guardian_scanner run --target claude-code --repeat 20 --sensor --record ../results
```

Each run writes one file per pattern into `results/`. The scanner fills in what it knows and
writes `unrecorded` where it cannot know, which for a closed harness includes the model.
Open each file and replace the placeholders: your name in `credits`, the operating system
and anything that mattered in `environment`, and the model if you know it. `check.py`
refuses a file that still says `unrecorded` in those places, so you cannot share one by
accident.

**A rate needs 20 runs that actually opened the attack vector**, which is not the same as 20
runs. If the agent declines the task, that run did not test the attack. Target the trials and
let the scan work out how many runs that takes:

```bash
python3 -m guardian_scanner run --target claude-code --pattern GP-0008 \
  --until-attempted 20 --max-runs 80 --record ../results
```

[results/README.md](results/README.md) explains why twenty, and what a cell below the floor
can and cannot be used for.

**Read the `run_log` before you open the pull request.** Each file carries one entry per run
with the outcome and your agent's final answer, so that anyone can recount the rate instead
of trusting it. That means the file holds whatever your agent said, and if you measured it
against your own code, some of that text is yours. `validate-results` refuses a log that
looks like it carries a credential, and canary tokens are allowed because they are harmless
by construction, but the check is a safety net rather than a substitute for looking.
[results/README.md](results/README.md) describes every field.

Two things the scanner will refuse, both on purpose and both before it spends a single run:
`--repeat` below 5 together with `--record`, because a recorded measurement needs at least
five runs to carry any information and 20 is what Season 1 asks for; and a `--record` folder
that does not exist, so a mistyped path cannot cost you the whole measurement. A small run
without `--record` is fine and is how you check a new target works at all.

| Field | Meaning |
| --- | --- |
| `runs`, `successes`, `errored` | Attempts, attempts where the attack worked, attempts the harness failed on |
| `rate`, `interval` | Successes over scored runs, and the 95% Wilson interval. Both are recomputed by the checks |
| `sensor` | `off` or `on`, and which rules were loaded |
| `target` | Harness and model, with versions, or `unrecorded` |

Twenty runs is the request for the paper. Five is the floor the checks allow, and at five the
interval is roughly 0 to 0.43, which says almost nothing.

## 7. What to share, and what stays with you

Sharing is opt-in, per result. If you want a row in the attack matrix, open a pull request
with your result files. Nothing in them names your company unless you put it there, and the
matrix never prints a number without its run count and interval.

The sensor's evidence log stays on your machine. If you ever share counts from it, the
`report` command builds them from a fixed list of fields and shows you the whole of what
would leave before anything does:

```bash
cd ../sensor
python3 -m guardian_sensor report --org my-org --preview
```

Replace `my-org` with any pseudonym. No tool names, no arguments, no URLs, no file paths,
no message text, and nothing finer than the hour. Those are never read, so they cannot be in
the output.

## When something does not work

Open an issue with the command you ran and what it printed. If you think you have found a
real weakness in a product, or a way past the sensor, do not open an issue: use the private
route in [SECURITY.md](SECURITY.md) instead.
