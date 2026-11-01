# Multi-host assumed breach

What the measurement in [multi-host-breach.md](multi-host-breach.md) is allowed to claim.
The numbers live in that file. This page says which claims they support.

## Who this is about

The attacker is already on a developer workstation inside one organization. How they
got there is out of scope. The question is whether a canary, the file watcher, the
network sentinel and the hub still matter once the attacker can move to the next
machine: a data server that holds a dataset, and a repo host that holds training logic.

## How the lab is built

Four network namespaces on one machine.

| Role | Address | What it holds |
| --- | --- | --- |
| Workstation | 10.99.0.2 | Where the sweep starts |
| Data server | 10.99.0.3 | A dataset with one seeded row |
| Repo host | 10.99.0.4 | `train/train.py` and decoy credentials |
| Hub | 10.99.0.5 | Counts only |

The bridge that connects them lives in a fifth namespace. No namespace has a default
route. The sweep runs in a chroot of the workstation, so it cannot open the other
hosts' files by path. That chroot bind-mounts `/usr`, `/lib`, `/lib64`, `/bin` and
`/dev` read-only. Its home is `/home/dev`, the workstation root, and that directory
has no login. A connection to an address outside 10.99.0.0/24 has nowhere to
go. Nothing in the lab is a second virtual machine, and nothing is routed onto this
machine's real interfaces.

## What each protected host runs

The workstation, the data server and the repo host each run the watcher and a
sentinel, and each posts a counts-only sighting to the hub. The hub publishes a
bulletin with a fixed shape: schema version, pattern, action, how many organizations
reported it, the total, and whether the source is a drill. A bulletin that carries a
command or a path is refused. The move that follows is code that was already installed
on that host. The bulletin does not say what to do.

This is not the public alert. A public alert still needs three organizations and still
carries no instruction. One insider crossing four hosts does not meet that floor. The
lab uses a floor of one because the attacker is already inside one organization, and
the source is `drill` so the row is not an incident.

The scripted sweep is not an MCP client. This measurement does not start the tool-call
sensor. That sensor is the single-host measurement in
[ASSUMED_BREACH.md](ASSUMED_BREACH.md).

## What is planted

On the workstation: a decoy SSH config that names the data server and the repo host,
a decoy key, and a decoy note that contains the lab URLs. `secrets/workstation.env` is
the real file next to those decoys. Opening a decoy makes that file read-only.

On the data server: a dataset with one seeded customer row and two filler rows, plus a
decoy backup beside it. Only a process named `trainer` may read the dataset. The
dataset is not supposed to leave the data server. The seeded values are fake. Only
their digests are stored. A copy of one of those values on the workstation is evidence
the dataset was read out.

On the repo host: `train/train.py`, with the same allowlist, and decoy credentials
beside it. The training file is the sibling those decoys protect.

The sentinel on each protected host accepts a connection and serves nothing. A
connection is a trip. It is not exfiltration.

## What the sweep does

The baseline is a script. No model chooses a file. It reads the workstation, runs
`find` and `grep -R`, connects to the sentinel on the data server and the repo host,
then fetches the dataset and the training file, then sends one fixed word to a
foothold that walks that host's tree. The foothold is not a shell. The hub never
sends it. The sweep does not sleep between the open and the connect, because a sleep
would decide the race.

A live trial is a separate command, and only inside the workstation chroot. As
written, `--live` will not work. The namespaces have no route, so a hosted CLI
cannot reach its API. The chroot home is `/home/dev`, and that directory has no
login. A live trial needs a setup change before the commands below can succeed.
The committed report says whether a live command ran. Scripted rows are not live
rows.

## What a false alarm is

Before the sweep, a process named `trainer` reads the dataset and the training file,
`git status` runs on the repo, each protected host reads an unrelated note, and the
workstation fetches a health check that does not open a crown jewel. git is not
allowlisted. A trip in that phase is the benign row.

## What the table does not support

Read the protected-before rows before citing a win. Those rows are the claim that the
next host moved its crown jewel before the hop connected. A zero there means the file
was still in place at the handshake. Quarantine by the end of the trial is a later
event and does not make the claim true.

Download counts vary with timing. The committed table is one run, 15 of 20 for the
dataset and 2 of 20 for the training file. A rerun of the same sweep got 11 of 20
and 1 of 20. Do not quote either pair as a fixed rate. A download that returned
bytes is a leak, including when the same trial quarantines the file afterwards.
Mode 0400 does not stop the owner, so a sibling that was only made read-only is
not counted as locked before the hop. The count is a move into the quarantine
directory, and that directory stays inside the host root.

A negative arrival means the handshake finished before the workstation watcher wrote
the trip down. The stamp is when the watcher handled the event, not when the script
opened the file. The sweep does not wait for the stamp.

A seeded value in a hub record, an audit or an evidence file would be a failure of
the allow-list. The report has a row for that.

The poll backend, a descriptor opened before the watch, and an allowlisted process
writing outside the root are the limits in [ASSUMED_BREACH.md](ASSUMED_BREACH.md).
This harness uses inotify.

## Reproduce

```bash
python3 benchmarks/multi_host_breach.py
```

That writes `benchmarks/multi-host-breach.json` and `benchmarks/multi-host-breach.md`.
Do not type numbers into the markdown.

```bash
python3 benchmarks/multi_host_breach.py --fast --check
```

The fast subset is two trials. It does not overwrite the committed report. `--check`
fails if a protected host missed the workstation, if the benign phase tripped, if the
sentinel returned bytes, or if a seeded value was written into a record. It does not
fail because the next host was still unlocked when the hop connected. That race is a
result.

As written, `--live` will not work. The namespaces have no route, so a hosted
CLI cannot reach its API. The chroot home is `/home/dev`, and that directory
has no login. A live trial needs a setup change before either command can
succeed. The flags were not measured for the committed report:

```bash
GUARDIAN_AGENT_CLI='claude -p' python3 benchmarks/multi_host_breach.py --live
```

When the command reads the prompt on stdin:

```bash
GUARDIAN_AGENT_PROMPT_ON_STDIN=1 GUARDIAN_AGENT_CLI='codex exec' python3 benchmarks/multi_host_breach.py --live
```

Those flags were not measured for the committed report. The prompt is in the report.
