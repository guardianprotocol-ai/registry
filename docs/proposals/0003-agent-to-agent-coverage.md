# 0003: Seeing traffic between agents

**Status:** draft, for the working group to decide
**Author:** Frank Albanese

## The problem

Six of the eighteen patterns describe attacks that need more than one agent, and the sensor
cannot see most of them.

The sensor is an MCP proxy. It sees what an agent sends to a tool and what comes back. When
two agents talk through a tool, as in the lab's `send_to_agent`, the sensor sees it, which is
why GP-0008 is measurable today. When they talk any other way, over a framework's internal
queue, a shared database, a message bus, or the A2A protocol, the sensor sees nothing at all.

That gap is not a detail. Every pattern from GP-0013 to GP-0018 assumes something is watching
the path between agents, and for most real deployments nothing is.

Worse, two of those patterns need information the sensor does not carry even when it can see
the message. GP-0014 needs the requesting agent's permissions to tell a delegation from a
confused deputy. GP-0015 needs a verified sender to tell a real orchestrator from a message
that merely says it is one.

## What the registry needs from any answer

1. **See the message.** Something observes agent-to-agent traffic and can refuse it.
2. **Know who sent it,** independently of what the message says about itself.
3. **Know what the sender was allowed to do,** so a privilege boundary can be checked.
4. **Say all of that in a corpus case,** so a detection can be tested offline like every other.

No option below gives all four. That is the honest state of it.

## Option A: an A2A transport for the sensor

[A2A](https://a2a-protocol.org/specification/) is the open agent-to-agent protocol, originally
developed by Google and donated to the Linux Foundation, maintained by a technical steering
committee with members from several large vendors. Current specification: v1.0.

The sensor already proxies one protocol. A second transport that proxies A2A the same way
would see messages between agents that use it, and A2A has a notion of agent identity, which
is directly what GP-0015 needs.

**For.** Reuses the architecture we have. Open standard, neutral home, which matches where
this project is going. Identity is part of the protocol rather than something we invent.

**Against.** It only covers deployments that actually use A2A. Most multi-agent systems today
are a framework's own function calls, with no protocol between them at all. It is also real
work: a second transport is not a small addition to a prototype sensor.

**Open question.** How much of the protocol has to be understood to be useful? Reading the
envelope may be enough for most patterns, without parsing every message type.

## Option B: hooks in multi-agent frameworks

The same approach as the Claude Code hook already in `hooks/`: run at the framework's own
boundary, where handoffs are ordinary function calls.

**For.** Covers what people actually run today. The hook pattern is proven here, and it sees
the framework's own notion of which agent is which, which no proxy can recover from the wire.

**Against.** One integration per framework, each maintained separately, each breaking on its
own schedule. This is the long tail, and the registry does not have the people for it yet.

**Open question.** Is there a small interface a framework could implement once, so we maintain
one contract instead of N integrations? That is worth asking the frameworks before building
anything.

## Option C: signed messages and agent identity

Independent of transport: agents sign what they send, and receivers refuse what is not signed
or is signed by the wrong agent.

**For.** It is the only option that actually fixes GP-0015 rather than detecting it after the
fact. It also gives GP-0014 the caller identity it needs. A2A already specifies signed agent
cards, so part of this may be adoption rather than invention.

**Against.** Key distribution, rotation and revocation between agents is its own project. A
registry that ships a half-designed identity scheme would do real damage.

**Open question.** Can this be scoped to verifying a claim rather than establishing identity?
Detecting that a message's claimed sender does not match its signed sender is a much smaller
problem than deciding who an agent is.

## What the corpus format needs either way

Corpus cases today are a flat list of events: a tool call, or a tool output. A multi-agent
case has to say which agent did what, or a detection cannot be tested offline.

The smallest change: an optional `agent` on each event, and an optional `from` and `to` on a
message event. Additive, so every existing case stays valid, in the same way `topology` was
additive for patterns.

```json
{
  "id": "GP-0013-instruction-travels",
  "expect": "GP-0013",
  "events": [
    {"agent": "planner", "output": {"source": "fetch_brief", "text": "..."}},
    {"agent": "planner", "message": {"to": "researcher", "text": "..."}},
    {"agent": "researcher", "call": {"name": "send_message", "args": {}}}
  ]
}
```

This is the part worth deciding first, because it is cheap, it is needed by all three options,
and without it the six new patterns have no way to carry attack and benign cases. Today they
carry none, and their detections are written down as ideas rather than shipped as rules.

## Recommendation

Decide the corpus format now. Treat A and B as experiments someone can try, not as a commitment.
Do not design identity in this project; follow A2A and adopt what it settles on.

## Open questions for the group

- Is the corpus change above enough, or does a multi-agent case need a notion of session?
- Should a sighting say which agent saw something, or does that leak structure a member would
  rather not share?
- Who, realistically, maintains a framework integration once it exists?
- Is there a deployment among the member companies that uses A2A today, which would make
  Option A testable rather than theoretical?
