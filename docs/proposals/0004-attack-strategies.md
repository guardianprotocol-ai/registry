# 0004: How an attack is delivered, and saying so

**Status:** draft, for the working group to decide
**Author:** Frank Albanese

## The unstated choice

Every measurement in this registry is **single-shot**: one prompt, one agent, one process,
judge the outcome, done. Nothing says so. The field does not exist, the method section of
the paper would have to add it in prose, and a reader comparing our numbers to someone
else's has no way to know the comparison is unfair.

That is a gap in the convention, not in the code. It is cheap to close now and expensive to
close after a paper has shipped without it.

## What a strategy is

The registry already treats three things as separate and pluggable:

| Axis | Question it answers | Pluggable today |
| --- | --- | --- |
| **Target** | What is being attacked, which model inside which harness | Yes, `CliAgentTarget` |
| **Judge** | How we decide the attack worked | Yes, `succeeded` and `from_answer` |
| **Strategy** | How the attack is delivered | **No, hardcoded** |

A **strategy** is the shape of the attempt. Not the attack, which is the pattern. Not the
agent, which is the target. How many turns, how many actors, and whether the attacker gets
to react to what happened.

It belongs in a result because it bounds what the number means. **"10 percent" measured
single-shot and "10 percent" measured by an adaptive attacker over ten turns are not the
same claim**, and nothing in a result file currently distinguishes them.

## The strategies worth naming

Ordered by how far each is from what exists today.

### 1. `single_shot`

One prompt, one agent, one process. Everything measured so far. Answers: does this land on
first contact, against an agent doing an ordinary task.

**Status: this is what the scanner does.** The proposal is to say so in the data.

### 2. `multi_turn`

The attack persists across turns. Poisoned content is read in turn one and the payoff lands
in turn four, or the instruction is repeated until it takes.

Answers: does taint decay, and does a refusal hold under repetition. The sensor already
tracks taint across a session, so the detection half of this exists and only the measurement
half is missing. Cheapest of the five to build.

### 3. `human_driven`

A person runs the attack by hand against their own agent and records the result.

**Half supported already.** `results/README.md` requires that a result for a pattern the
scanner cannot drive explains in `environment` how it was actually run. The data format
accepts it; the runner has no concept of it, and nothing marks such a row as manual.

This is the on-ramp for anyone whose system the scanner will never drive: a robotics stack,
a lab instrument, an internal framework nobody will open source. Those contributors can
produce a real measurement today and the matrix cannot label it honestly.

### 4. `swarm`

Several agents, coordinated, attacking or being attacked together.

The lab already serves two agents, and patterns already carry a `topology` field. GP-0013 to
GP-0018 describe attacks that need this and have no way to be measured. This is the strategy
those six patterns are waiting on.

### 5. `adaptive`

An attacker agent that observes a refusal and tries something else.

**This one is different in kind and the group should decide it explicitly.** An attacker
that optimises against a defense is writing evasion, and evasion is forbidden by
`CONTRIBUTING.md` and by the trial design: the Season 2 campaign runner is deliberately a
scheduler over a fixed list rather than a planner, for exactly this reason.

It is also the most scientifically interesting, because a defense that only holds against a
fixed script is not a defense. Both of those things are true at once, which is why it is a
decision and not a task.

If the group ever says yes, it needs its own rules: no new techniques derived, results held
under coordinated disclosure, and a stated reason why the knowledge helps defenders more
than attackers. The honest default for now is no.

## What this proposes

**1. Add an optional `strategy` to the result format.** One of `single_shot`, `multi_turn`,
`human_driven`, `swarm`, `adaptive`. Omitted means `single_shot`, so every result recorded
so far stays valid and correctly described. Additive, in the same way `topology` was
additive for patterns.

**2. Show it in the matrix**, so two rows measured differently never sit in a column as if
they were comparable.

**3. Mark `human_driven` rows as such in the matrix.** A measurement someone took by hand is
a real measurement and should be published, and a reader deserves to know a script did not
take it.

**4. Decide `adaptive` separately,** and write the answer down here rather than leaving it to
whoever opens the next pull request.

## What this does not propose

- Building strategies 2 to 5. This is the convention, not the implementation.
- Changing anything about how the scanner runs today.
- A new taxonomy. One optional field, same as `topology`.

## Why now rather than later

The first paper publishes on October 29. A convention added before the first publication is
a convention; the same field added afterwards is an erratum, and every row published without
it has to be explained.

The cost of being wrong here is small: if the group decides the field is unnecessary, we
delete five lines. The cost of omitting it is a method section that has to apologise.

## Open questions for the group

- Is `strategy` the right word? `delivery` and `protocol` were both considered and both are
  already overloaded in this repository.
- Should `human_driven` require anything extra in `environment`, or is the existing
  requirement enough?
- Does `adaptive` belong in the enum at all before the group has decided whether it is
  allowed? Naming a thing can read as planning it.
- Is a conformance run, where the corpus is replayed against a detection engine with no model
  involved, a strategy or a different program entirely? This proposal assumes the latter: it
  measures an engine, not an agent, and calling it a strategy would suggest it produces a
  comparable rate. It does not.
