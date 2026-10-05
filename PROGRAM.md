# Season 1: October 5 to October 29, 2026

One page: what the group is doing, what you can pick up without asking anyone, and where to
see how far along we are.

**The goal.** By October 29 we publish protocol v0.1 and the full co-authored paper as
preprint v1, with members' own agents measured and numbers to show for it.

**The paper's scope is measurement:** which attacks land, against which models, inside which
harnesses, with the sensor off and on. The distributed work, fire drills and the immune
response exercise, is Season 2 and the second paper.

**The rule on scope.** Whatever is done by **October 25** goes in the paper. Results from
short measurement windows are labelled preliminary in the limitations section. We cut scope,
never the date. Season 2 publishes v2 with longer-window data and picks up whatever did not
fit.

The paper is written in parallel from week 1. It is not written at the end.

## The schedule

| Week | Dates | What is happening |
| --- | --- | --- |
| 1 | Oct 5 to 11 | Kickoff. **Map** the 63 techniques |
| 2 | Oct 12 to 18 | **Prove** and **Measure**. **Deploy** is optional: the sensor in monitor mode on your own machine |
| 3 | Oct 19 to 25 | **Measure** continues: more harnesses, more model families, 20 runs per cell, sensor off and on. Results in by Oct 25 |
| 4 | Oct 26 to 29 | Finish the paper and every author approves it. **Publish** v0.1 and preprint v1 on Oct 29 |

## The four phases, and one optional

### 1. Map

Finish the triage of the **63 MITRE ATLAS techniques that happen while an agent is
running**. For each one: confirm where a defense can act, link an existing pattern, or write
a new draft pattern.

**Done when** every one of the 63 is resolved: covered by a pattern, or marked
`not_testable_at_runtime` in `coverage/atlas-coverage.csv` with a reason saying what a
sensor or a scan would have to see and why it cannot.

**How to help.** Every open technique has an issue. Many are already covered by an existing
pattern and only need the triage confirmed, which is a good first task and needs no security
background.

### 2. Prove

Make patterns runnable and back them with evidence: a scanner scenario so the attack can be
run, and an attack case in `corpus/attacks/`. The benign corpus is shared by every rule, so
adding ordinary work that must never be flagged helps all of them at once.

**Done when** the patterns chosen for the paper are runnable and have corpus cases.

### 3. Measure

Run the runnable patterns against popular models and agent tools and record the results in
the attack matrix, **at least 20 runs per result, sensor off and on**. See
[results/README.md](results/README.md). The scanner writes the files for you with
`--record`; you fill in what it could not know. If you have never run it, start with
[TEST_YOUR_AGENT.md](TEST_YOUR_AGENT.md), which goes from a fresh clone to a recorded
result in about twenty minutes.

Members test their own agents and share what they choose. A result is yours until you open
the pull request, and nothing in it names your company unless you put it there.

**Done when** the matrix has rows from more than one harness and more than one model family.

### 4. Publish, October 29

Protocol v0.1 and the full co-authored paper as **preprint v1**, scoped to measurement. Authorship follows
[docs/RESEARCH.md](docs/RESEARCH.md): a substantive contribution, approval of the final
draft, and accountability for it. Contributing a measurement the paper relies on counts.

Short-window results are labelled preliminary. **v2**, with longer-window data, follows in
Season 2, and the paper can then go to a workshop or a conference.

### Deploy, optional

Run the sensor in **monitor mode** on a development agent on your own machine. It flags and
records, blocks nothing, and uses no network and no hub: nothing leaves your machine unless
you choose to share numbers. What it earns is a local false-alarm observation on real work,
which a corpus cannot give, and every false alarm you report becomes a benign corpus case so
it stops happening to everyone else.

Opt-in, per person, on development or staging agents, never on customer production systems.

## How to take part

**Claim work by commenting on its issue.** Nobody assigns anything. If an issue has been
claimed and quiet for a while, it gets freed up again, kindly.

**See where we are: [docs/STATUS.md](docs/STATUS.md).** Generated from the repository, so it
is never out of date and nobody has to be asked. It shows, for all 63 techniques, how many
are resolved, runnable, backed by corpus cases and measured.

**New here?** [START_HERE.md](START_HERE.md) gets you set up in about fifteen minutes.

**The weekly rhythm.** A Monday post with what shipped, where we are, and the three tasks
that most need an owner. A Thursday call: demos first from whoever shipped, then the week's
one decision, then claims for the following week.

**Deploy is optional and local.** Monitor mode only, on development or staging agents, on
your own machine. Nothing leaves it unless you share numbers, and anything you have shared
can be withdrawn before publication.

## What stays private

Members' raw evidence logs, results they have not chosen to share, anything specific to a
named company, and findings awaiting coordinated disclosure never go in this repository. See
[SECURITY.md](SECURITY.md).

## Season 2: the distributed work

Fire drills and the immune response exercise on the open reference hub, if three or more
companies opt in, and the second paper. The hub is already in this repository as the reference
implementation those experiments will run on; see `sensor/README.md`.
