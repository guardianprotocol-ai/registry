"""Skip a pattern that cannot match, by looking for the words it needs first.

The instruction patterns are most of what the sensor costs, and nearly all of that cost
is spent proving that ordinary text matches nothing. Almost every one of them cannot
match unless one of a few plain words is present: `\\b(send|email|post|upload|forward) ...`
needs one of five. Finding out whether any of those words is in the text is a substring
search, which is far cheaper than running the pattern, so the pattern only runs on text
where it stands a chance.

This is the most dangerous optimisation the sensor could have. If the words derived for
one pattern are wrong, that pattern silently stops running on text it would have matched,
nothing errors, and every measurement taken afterwards is of a weaker sensor than the one
it names. So everything here fails in one direction:

- The words come from the parsed pattern, never from reading its text. A word is only
  required if every way through the parse tree passes through it.
- Anything the derivation does not recognise, it does not reason about. An unknown node
  contributes nothing, and a pattern with nothing provable always runs.
- If the parser cannot be imported or raises, every pattern always runs.
- GUARDIAN_PRESCAN=off runs every pattern on everything, which is the engine as it was.

`scripts/prescan_gate.py` holds the two paths to the same verdict on every corpus case and
on thousands of mutations of them, on every pull request.

Python 3.9+ standard library only.
"""
import os

try:                                    # Python 3.11 and later
    from re import _parser as _sre
except ImportError:                     # 3.9 and 3.10
    try:
        import sre_parse as _sre
    except ImportError:                 # no parser, so nothing can be proved
        _sre = None

# Past this many alternatives a run of literals is cut rather than multiplied out. The
# cut is safe: each side of it is still required, there are just two shorter candidates
# where there might have been one longer one.
MAX_WORDS = 64

# Under re.IGNORECASE four characters outside ASCII match an ASCII letter: a dotted
# capital I and a dotless small i match `i`, the long s matches `s`, and the Kelvin sign
# matches `k`. str.lower() alone gets three of them wrong, and turns the dotted I into
# two characters, which would split a word in half. So a pattern can match text that
# lowercases to something not containing its own words, unless these are folded first.
# The table is checked against every code point by the tests, on the Python running
# them, because it is a fact about the regex engine and not about this file.
FOLD = {0x0130: "i", 0x0131: "i", 0x017F: "s", 0x212A: "k"}


def enabled():
    return os.environ.get("GUARDIAN_PRESCAN", "").strip().lower() not in ("off", "0", "no")


def fold(text):
    """The text as the word check reads it: lowercase, in the regex engine's sense."""
    if text.isascii():
        return text.lower()
    return text.translate(FOLD).lower()


def _name(op):
    return str(op).rsplit(".", 1)[-1]


def _usable(strings):
    """Lowercased, or None if any of it is outside what fold() is proven for."""
    out = set()
    for s in strings:
        if not s.isascii():
            return None
        out.add(s.lower())
    return out


def _exact(node):
    """Every string this node can match, if that is a small finite set. Else None."""
    op, arg = node
    kind = _name(op)
    if kind == "LITERAL":
        return _usable({chr(arg)})
    if kind == "IN":
        chars = set()
        for item_op, item_arg in arg:
            if _name(item_op) != "LITERAL":
                return None             # a range, a class or a negation
            chars.add(chr(item_arg))
        return _usable(chars)
    if kind == "SUBPATTERN":
        _group, add_flags, del_flags, inner = arg
        if add_flags or del_flags:
            return None                 # flags scoped to a group: not reasoned about
        return _exact_sequence(inner)
    if kind == "BRANCH":
        out = set()
        for alternative in arg[1]:
            strings = _exact_sequence(alternative)
            if strings is None:
                return None
            out |= strings
            if len(out) > MAX_WORDS:
                return None
        return out
    return None


def _exact_sequence(sequence):
    out = {""}
    for node in sequence:
        strings = _exact(node)
        if strings is None:
            return None
        out = {a + b for a in out for b in strings}
        if len(out) > MAX_WORDS:
            return None
    return out


# Roughly how often a word with this many letters turns up in a large piece of ordinary
# text, and what running a pattern costs next to looking for one word. Both are rough and
# neither has to be right: they only choose between candidates that are all correct.
_PRESENT = {0: 1.0, 1: 1.0, 2: 0.9, 3: 0.6, 4: 0.3, 5: 0.15, 6: 0.08}
_RARE = 0.04
_PATTERN_COST = 40


def _cost(words):
    """What checking these words is expected to cost, in units of one word looked for."""
    letters = min(sum(ch.isalnum() for ch in w) for w in words)
    return len(words) + _PRESENT.get(letters, _RARE) * _PATTERN_COST


def _better(a, b):
    """The cheaper of two candidate word sets to check. Either is correct.

    Measured on 200 KB, looking for one word costs about a fortieth of running one
    pattern. So there are two ways to waste time: a word so short it is always present,
    which runs the pattern anyway, and a long list of words where a few would do.
    """
    if a is None:
        return b
    if b is None:
        return a
    return a if (_cost(a), sorted(a)) <= (_cost(b), sorted(b)) else b


def _required_sequence(sequence):
    """Words such that any match of this sequence contains at least one. Or None.

    A sequence matches its items one after another, so whatever one item requires, the
    whole requires. Neighbouring items that each match a small finite set of strings are
    joined, because the parser splits `(assistant|ai|agent)` into an `a` and a branch of
    endings, and the words wanted are the whole ones.
    """
    best = None
    run = {""}

    def usable(words):
        return words if "" not in words else None

    for node in sequence:
        strings = _exact(node)
        if strings is None:
            best = _better(best, usable(run))
            run = {""}
            best = _better(best, _required(node))
            continue
        # The item on its own is a candidate too: `(send|email|post) (its|the|all)` is
        # proved by five words as surely as by fifteen pairs, and five is cheaper.
        best = _better(best, usable(strings))
        joined = {a + b for a in run for b in strings}
        if len(joined) > MAX_WORDS:
            best = _better(best, usable(run))
            joined = strings
        run = joined
    return _better(best, usable(run))


def _required(node):
    """Words a node that is not a finite set of strings still cannot match without."""
    op, arg = node
    kind = _name(op)
    if kind == "SUBPATTERN":
        _group, add_flags, del_flags, inner = arg
        if add_flags or del_flags:
            return None
        return _required_sequence(inner)
    if kind == "BRANCH":
        out = set()
        for alternative in arg[1]:
            words = _required_sequence(alternative)
            if words is None:
                return None             # one way through needs nothing, so nothing is needed
            out |= words
        return out if len(out) <= MAX_WORDS else None
    if kind in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
        least, _most, inner = arg
        return _required_sequence(inner) if least >= 1 else None
    if kind == "ATOMIC_GROUP":
        return _required_sequence(arg)
    # Lookarounds, anchors, classes, back references, conditionals and anything a later
    # Python adds: not reasoned about, so they require nothing.
    return None


def required_words(pattern, flags=0):
    """The words one of which must appear, folded, in any text this pattern matches.

    None means nothing could be proved and the pattern must always run. Never raises:
    a pattern this cannot parse is a pattern it knows nothing about.
    """
    if _sre is None:
        return None
    try:
        words = _required_sequence(_sre.parse(pattern, flags))
    except Exception:
        return None
    if not words or any(not w for w in words):
        return None
    return frozenset(words)


ALWAYS = "always"


def plan(entries, compiled):
    """Pair each compiled pattern with its required words, or None to always run it.

    An entry may carry `"prescan": "always"`, which is how a bundle says a pattern is
    known to have no required words rather than having been forgotten. The gate refuses
    a shipped pattern that is neither derivable nor marked.
    """
    out = []
    for entry, regex in zip(entries, compiled):
        words = None
        if entry.get("prescan") != ALWAYS:
            words = required_words(regex.pattern, regex.flags)
        out.append((regex, words))
    return out


def admits(words, folded):
    """Whether a pattern with these required words could match the folded text."""
    if words is None:
        return True
    for word in words:
        if word in folded:
            return True
    return False


def any_match(planned, text, use_prescan=None):
    """Whether any planned pattern matches. The same answer with the prescan on or off."""
    if use_prescan is None:
        use_prescan = enabled()
    if not use_prescan:
        return any(regex.search(text) for regex, _ in planned)
    folded = fold(text)
    for regex, words in planned:
        if admits(words, folded) and regex.search(text):
            return True
    return False
