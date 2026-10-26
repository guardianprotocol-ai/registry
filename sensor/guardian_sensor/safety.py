"""Whether a rule bundle is safe to run, which a manifest cannot tell you.

A manifest proves a bundle came from the publisher and arrived unaltered. It says nothing
about what the patterns inside it do. A regular expression with nested quantifiers can take
longer than the life of the machine to fail on a short string: one such pattern, measured
while writing this, ran for over ten minutes against thirty three characters before it was
killed. The sensor inspects every tool call, so a bundle carrying one would not slow a
member down. It would stop them, and stop every member who adopted it.

That matters more now that bundles are adopted automatically. The protection against a
hostile publisher was always that a bundle is data and nothing in it executes. That is
still true, and it turns out not to be enough: a pattern does not have to execute to take
a machine out.

So a bundle is checked before it is adopted, not while it is being used. Every pattern is
compiled and run against inputs built to make a backtracking engine work, under a time
budget. Anything that exceeds it fails the whole bundle, because a partly adopted rule set
is a state nobody can reason about.

Python 3.9+ standard library only.
"""
import re
import signal
import threading
import time

# Per pattern, across every probe. Generous next to the microseconds a sound pattern takes,
# and far below the point where a member notices. A pattern needing more than this against
# a few hundred characters is pathological whatever it was meant to match.
BUDGET_SECONDS = 0.25

# Short, because catastrophic backtracking grows exponentially: a pattern that is going to
# fail will fail on these, and a sound one costs nothing to check.
PROBES = (
    "a" * 64 + "!",
    "ab" * 32 + "!",
    " " * 64 + "x",
    "0" * 64 + "!",
    "/" * 32 + "a" * 32,
    ("the contents of notes.txt " * 8) + "!",
    "​" * 32 + "a" * 32,
)

# There is no static check here on purpose. The obvious one, a quantified group inside a
# quantified group, refuses `(?:\.[\w-]+)+`, which is how this project already matches a
# domain and is perfectly sound: each repetition is anchored by the literal dot, so there
# is nothing to backtrack over. A check that refuses the bundle the project ships is worse
# than no check, because it would be switched off.
#
# What is left is empirical and has no opinion about shape: run the pattern and see. A
# pattern that backtracks catastrophically does so within a few dozen characters, and one
# that does not costs microseconds to clear.


class Unsafe(Exception):
    """The bundle was refused. The message names the pattern and why."""


def _can_interrupt():
    return (hasattr(signal, "SIGALRM")
            and threading.current_thread() is threading.main_thread())


class _TookTooLong(Exception):
    pass


def _timed(compiled, text, budget):
    """Run one match under a wall clock budget. Returns the seconds it took."""
    if not _can_interrupt():
        start = time.time()
        compiled.search(text)
        return time.time() - start

    def ring(signum, frame):
        raise _TookTooLong()

    previous = signal.signal(signal.SIGALRM, ring)
    signal.setitimer(signal.ITIMER_REAL, budget)
    start = time.time()
    try:
        compiled.search(text)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    return time.time() - start


def check_pattern(pattern, flags=0, budget=BUDGET_SECONDS):
    """Raise Unsafe if this pattern should not be run against untrusted input."""
    try:
        compiled = re.compile(pattern, flags)
    except re.error as e:
        raise Unsafe("the pattern %r does not compile: %s" % (pattern[:80], e))
    spent = 0.0
    for probe in PROBES:
        try:
            spent += _timed(compiled, probe, max(budget - spent, 0.01))
        except _TookTooLong:
            raise Unsafe("the pattern %r did not finish within %.2f seconds against %d "
                         "characters. A sensor runs this against every tool call."
                         % (pattern[:80], budget, len(probe)))
        if spent > budget:
            raise Unsafe("the pattern %r took %.2f seconds across the probes, over the "
                         "%.2f second budget" % (pattern[:80], spent, budget))
    return True


_FLAGS = {"i": re.I, "s": re.S}


def _flags_of(entry):
    out = 0
    for ch in entry.get("flags", "") or "":
        out |= _FLAGS.get(ch, 0)
    return out


def _walk(node):
    """Every pattern in a signatures document, wherever it is nested."""
    if isinstance(node, dict):
        if isinstance(node.get("pattern"), str):
            yield node["pattern"], _flags_of(node)
        for value in node.values():
            for found in _walk(value):
                yield found
    elif isinstance(node, list):
        for value in node:
            for found in _walk(value):
                yield found


def check_signatures(document, budget=BUDGET_SECONDS):
    """Check every pattern in a bundle. Returns how many were checked, or raises Unsafe.

    The whole bundle fails on one bad pattern. Adopting the sound half of a rule set would
    leave a member running something nobody has a name for.
    """
    checked = 0
    for pattern, flags in _walk(document):
        check_pattern(pattern, flags, budget=budget)
        checked += 1
    if not checked:
        raise Unsafe("the bundle contains no patterns, so adopting it would quietly "
                     "replace a working rule set with nothing")
    return checked
