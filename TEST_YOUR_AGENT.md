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

## 4. Point it at your own agent

Today the scanner drives one real harness end to end:

```bash
python3 -m guardian_scanner run --target claude-code --repeat 5 --pattern GP-0001
```

That starts a real Claude Code session, headless, over the lab server, and costs tokens.
Nothing reaches for it unless you name it.

**If your agent is not Claude Code,** there is no target for it yet, and adding one is a
Season 1 task. Open an issue naming your harness, labelled `track:scanner`. A target is one
class in `scanner/guardian_scanner/targets.py`, and the existing one is the example. Until
then, you can still run the demo and the scripted scan, and you can read any pattern's
`test` section and run it by hand.

## 5. Record what you measured

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

| Field | Meaning |
| --- | --- |
| `runs`, `successes`, `errored` | Attempts, attempts where the attack worked, attempts the harness failed on |
| `rate`, `interval` | Successes over scored runs, and the 95% Wilson interval. Both are recomputed by the checks |
| `sensor` | `off` or `on`, and which rules were loaded |
| `target` | Harness and model, with versions, or `unrecorded` |

Twenty runs is the request for the paper. Five is the floor the checks allow, and at five the
interval is roughly 0 to 0.43, which says almost nothing.

## 6. What to share, and what stays with you

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
