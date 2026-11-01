# Assumed-breach threat model

What the measurement in [assumed-breach.md](assumed-breach.md) is allowed to claim.
The numbers live in that file. This page says which claims they support.

## Who this is about

The attacker is already on the host. How they got there is out of scope. The question is
whether a canary still marks the crown jewels after that, and whether a trip contains
what the policy names.

Three mechanisms, all local:

- A seeded row inside a real-looking dataset. The row is a fake customer id, a fake
  account number and a fake API key. Only the digests are stored. The dataset is allowed
  to contain them. A second file, a tool call, or egress that contains one is evidence
  the dataset was copied.
- A real file with an allowlist. Only the named process may read it. A byte-for-byte
  copy is a trip even when the writer is allowlisted. A tool call that names a
  destination outside the sandbox is a trip even when the tool is allowlisted.
- A decoy beside a real file. Opening the decoy quarantines the decoy and makes the
  real sibling read-only. The real file is not emptied.

The sentinel is a listener on 127.0.0.1 that accepts a connection and serves nothing.
A connection is a trip. It is not exfiltration.

## What the committed run measured

The crawl is `find` then `grep -R`. No model chose a file. Directory order is not
rearranged so a decoy is touched first. If a crown jewel is opened before the first
decoy, the report says so.

`git status` in a repository that contains a decoy is the false-alarm check. git is not
allowlisted. The probe records whether it tripped.

An outside `cp` of a decoy is scored twice: whether the open was seen, and whether the
copy still existed afterwards. A copy that finished is counted as having left. The
report does not turn that into a claim that the bytes were stopped.

An allowlisted process that writes a copy outside the root is a limit, measured on its
own row. The watcher does not follow the write. The tool layer is what refuses an agent
call that names an outside destination.

## In scope

- Opens, reads, hard links, symlinks, mmap, renames and `tar` of a decoy, by any process
- A hard link of a decoy that lives outside the root: the inode is emptied, the outside
  name is not deleted
- A symlink whose target is outside the root, named as a sibling: refused, and the
  target's mode is left alone
- A seeded value in a copied CSV or SQLite file, and the same value in a tool call
- A filler row, which must not trip
- A real asset opened by a process that is not on its allowlist
- A real asset opened by the one process that is
- A decoy trip that sets the real sibling to mode 0400 without emptying it
- A connection to the loopback sentinel
- A shell command that names the path, and one that does not
- `git status`, a read of an unrelated file, and a grep of a different directory

## Out of scope, and said so in the report

- A descriptor that was already open when the watcher started. A later read on it was
  not seen.
- Bytes read before the watch existed.
- The poll backend, when the access time does not move. inotify does not have that gap.
  The `poll_read` row says which one this host did.
- A process that exits before `/proc` is scanned. The trip still happens. The comm is
  `unknown`, and unknown is not allowlisted.
- A hard link of a real asset outside the root. The bytes stay. Real files are not
  truncated. Doing so would destroy the crown jewel, including through every name.
- Mode 0400 against the owner. The owner can still read it. Moving the file into the
  quarantine directory removes that path. It does not remove an outside hard link of a
  real file.
- A tar archive as a content-hash match. The archive is not the file. The open is still
  a trip when the process is not allowlisted.
- A shell command that hides the path. The tool layer misses it. The watcher sees the
  open if the process actually opens the file.
- A read that is already in progress when quarantine runs.
- Anything the allowlisted process writes outside the root. Not followed.
- A model. This environment did not have an agent CLI logged in. The live command is in
  the report. It was not run here, and the report says that rather than inventing a trace.

## What a false alarm is

A trip on `git status`, on a process the operator allowlisted, on a file that is not
registered, or on a read of a different directory. The benign-corpus rate in GP-0041 is
a different measurement: `check_call` does not execute the path logic, so that rate is
the rate of a rule the corpus never runs. It stays 0.0. It is not the benchmark rate.

## Sharing

Unchanged from the value canaries. A sighting is the pattern, the action and the time.
The path, the seeded value and the audit stay on the machine. The public receiver is
`https://guardianprotocol.network/season1/sightings`. A private one is
`python3 receiver/local_server.py`, bound to `127.0.0.1`.
