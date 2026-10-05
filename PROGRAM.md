# Season 1: October 5 to October 29, 2026

One page: what the group is doing, what you can pick up without asking anyone, and where to
see how far along we are.

**The goal.** By October 29 we publish protocol v0.1 and the full co-authored paper as
preprint v1, with sensors running across member companies and numbers to show for it.

**The rule on scope.** Whatever is done by **October 25** goes in the paper. Results from
short measurement windows are labelled preliminary in the limitations section. We cut scope,
never the date. Season 2 publishes v2 with longer-window data and picks up whatever did not
fit.

The paper is written in parallel from week 1. It is not written at the end.

## The schedule

| Week | Dates | What is happening |
| --- | --- | --- |
| 1 | Oct 5 to 11 | Kickoff. **Map** the 63 techniques. Companies start seeking approval for the trial |
| 2 | Oct 12 to 18 | **Prove** and **Measure**. **Deploy** sensors in monitor mode |
| 3 | Oct 19 to 25 | **Drill**, around Oct 21. **Immune response exercise**, around Oct 23, if at least three companies are ready; otherwise it opens Season 2 |
| 4 | Oct 26 to 29 | Finish the paper and every author approves it. **Publish** v0.1 and preprint v1 on Oct 29 |

## The six phases

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

**Done when** the matrix has rows from more than one harness and more than one model family.

### 4. Deploy

Participating companies install the sensor in **monitor mode** on development agents and
send anonymized sightings through the hub. Opt-in per company, with that company's own
written approval.

### 5. Drill

Coordinated fire drills: a new harmless pattern is released, and we measure **time to
protection** across every participating sensor. That number is the headline result of the
trial.

### 6. Immune response exercise

A **simulated adversarial campaign**. A scripted attacker agent runs existing registry
attacks against participating companies' development agents, inside a scheduled window, with
each company's written consent and a kill switch any participant can pull.

Harmless by construction: it reuses scenarios already in the registry, canary tokens and
reserved `.test` destinations only. No new attack techniques are written for it, no evasion
and no self-propagation. We measure what each sensor detects, how fast sightings reach the
hub, and how fast protection spreads to everyone else.

This is the closing experiment of the paper. If fewer than three companies are ready by
October 23, it opens Season 2 instead.

## Publishing, October 29

Protocol v0.1 and the full co-authored paper as **preprint v1**. Authorship follows
[docs/RESEARCH.md](docs/RESEARCH.md): a substantive contribution, approval of the final
draft, and accountability for it. Contributing a measurement the paper relies on counts.

Short-window results are labelled preliminary. **v2**, with longer-window data, follows in
Season 2, and the paper can then go to a workshop or a conference.

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

**Phases 4, 5 and 6 are opt-in per company**, each with its own written approval, monitor
mode only, on development or staging agents. A company can withdraw at any time and have its
data removed before publication.

## What stays private

Members' raw trial data, anything specific to a named company, and findings awaiting
coordinated disclosure never go in this repository. See [SECURITY.md](SECURITY.md).
