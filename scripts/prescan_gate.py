#!/usr/bin/env python3
"""Prescan gate: prove the word prescan never hides a match from a pattern.

    python3 scripts/prescan_gate.py            # run the gate
    python3 scripts/prescan_gate.py --time     # also time both paths, which is not a check

The sensor skips a pattern when none of the words it needs is in the text
(sensor/guardian_sensor/prescan.py). If the words for one pattern are wrong, that pattern
quietly stops catching something and nothing errors. This gate is the reason that
optimisation is allowed to exist. It checks, against this repository's signatures:

1. Every shipped pattern either has derivable words or says `"prescan": "always"`. One
   that is neither was forgotten, not decided.
2. Every corpus case raises exactly the same patterns with the prescan on and off.
3. On every text the engine scanned while replaying the corpus, no pattern matches text
   its words would have skipped.
4. The same on seeded mutations of those texts: changed case, the four characters that
   match ASCII letters only under IGNORECASE, changed whitespace, cuts and splices.
5. The gate can fail. A plan with one pattern's words deliberately wrong must be caught,
   because a gate that passes whatever it is given proves nothing.

A shipped pattern that no text here ever matched fails the gate, because nothing would
have checked its words.

What it does not show: that the derivation is right for a pattern nobody has written
yet, a member's own included. Those rest on the derivation being conservative, which
sensor/tests/test_prescan.py tests directly.

No dependencies beyond the Python 3.9+ standard library.
"""
import argparse
import os
import random
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import rule_gate  # noqa: E402

SEED = 20261117
MUTANTS_PER_TEXT = 150

# One plain phrase for each pattern the corpus does not reach, so every shipped pattern is
# exercised and a new one with no phrase and no corpus case fails the gate. These are the
# trigger wording the rule tests already use, not attacks.
SEEDS = {
    "remember-this": "Please remember this for later sessions.",
    "tell-other-agents": "Kindly tell all agents about the schedule.",
    "delete-everything": "The script will delete all temporary files.",
    "system-prompt-reference": "It asked about your system prompt twice.",
    "call-repeatedly": "Then call fetch again until it answers.",
}

# What a letter can be swapped for and still match the same pattern under IGNORECASE.
# Written as escapes: this repository refuses live invisible or confusable bytes.
LOOKALIKES = {"s": "ſ", "S": "ſ", "k": "K", "K": "K",
              "i": "ı", "I": "İ"}


def mutate(text, others, rng):
    """One altered copy of the text. Most stop matching, and the ones that still do are the test."""
    kind = rng.randrange(8)
    if not text:
        return text
    a = rng.randrange(len(text))
    b = min(len(text), a + rng.randrange(1, 40))
    if kind == 0:
        return text.upper()
    if kind == 1:
        return "".join(c.swapcase() if rng.random() < 0.3 else c for c in text)
    if kind == 2:
        return "".join(LOOKALIKES.get(c, c) if rng.random() < 0.5 else c for c in text)
    if kind == 3:
        return "".join(rng.choice(["\n", "\t", "  ", " "]) if c == " " and rng.random() < 0.3
                       else c for c in text)
    if kind == 4:
        return text[:a] + text[b:]
    if kind == 5:
        return text[:b] + text[a:]
    if kind == 6:
        other = rng.choice(others)
        return text[:a] + other[rng.randrange(len(other) + 1):]
    return text.title()


def hidden_matches(prescan, planned, text):
    """Indexes of patterns that match the text although their words would skip it."""
    folded = prescan.fold(text)
    return [i for i, (regex, words) in enumerate(planned)
            if not prescan.admits(words, folded) and regex.search(text)]


def scanned_texts(rules, prescan, cases, default):
    """Replay the corpus and keep every text the engine handed to a planned pattern set."""
    seen = []
    real = prescan.any_match

    def recording(planned, text, use_prescan=None):
        seen.append(text)
        return real(planned, text, use_prescan)

    prescan.any_match = recording
    try:
        for case in cases:
            rule_gate.replay(rules, case, default)
    finally:
        prescan.any_match = real
    return sorted(set(seen))


def verdicts(rules, cases, default, setting):
    previous = os.environ.get("GUARDIAN_PRESCAN")
    os.environ["GUARDIAN_PRESCAN"] = setting
    try:
        return {case["id"]: rule_gate.replay(rules, case, default) for case in cases}
    finally:
        if previous is None:
            del os.environ["GUARDIAN_PRESCAN"]
        else:
            os.environ["GUARDIAN_PRESCAN"] = previous


def run(sensor_dir, corpus_dir):
    import json
    rules = rule_gate.load_engine(sensor_dir)
    from guardian_sensor import prescan
    with open(os.path.join(corpus_dir, "policy.json"), encoding="utf-8") as f:
        default = json.load(f).get("default_config", {})
    cases = rule_gate.load_cases(corpus_dir, "attacks") + rule_gate.load_cases(corpus_dir, "benign")
    entries = rules.SIGNATURES["instruction"]
    planned = rules.INSTRUCTION_PLAN
    ids = [e["id"] for e in entries]
    problems, lines = [], []

    # 1. Derivable, or marked.
    always = [e["id"] for e, (_, words) in zip(entries, planned) if words is None]
    for entry, (_, words) in zip(entries, planned):
        if words is None and entry.get("prescan") != prescan.ALWAYS:
            problems.append(
                "%s has no words the prescan can prove it needs, and is not marked "
                "\"prescan\": \"always\". Mark it if that is intended." % entry["id"])
    lines.append("Patterns with required words: %d of %d%s"
                 % (len(ids) - len(always), len(ids),
                    " (always run: %s)" % ", ".join(always) if always else ""))

    # 2. Same verdict on every case.
    on, off = verdicts(rules, cases, default, "on"), verdicts(rules, cases, default, "off")
    differing = sorted(i for i in on if on[i] != off[i])
    for i in differing:
        problems.append("%s raises %s with the prescan and %s without it"
                        % (i, on[i] or "nothing", off[i] or "nothing"))
    lines.append("Corpus cases with the same verdict on both paths: %d of %d"
                 % (len(cases) - len(differing), len(cases)))

    # 3 and 4. No pattern matches text its words would skip.
    texts = sorted(set(scanned_texts(rules, prescan, cases, default)) | set(SEEDS.values()))
    rng = random.Random(SEED)
    matched = dict.fromkeys(ids, 0)
    checked = 0
    for text in texts:
        candidates = [text] + [mutate(text, texts, rng) for _ in range(MUTANTS_PER_TEXT)]
        for candidate in candidates:
            checked += 1
            for i, (regex, _) in enumerate(planned):
                if regex.search(candidate):
                    matched[ids[i]] += 1
            for i in hidden_matches(prescan, planned, candidate):
                problems.append("%s matches text the prescan would skip: %r"
                                % (ids[i], candidate[:120]))
    total = sum(matched.values())
    lines.append("Texts checked: %d (%d from the corpus and the seed phrases, the rest "
                 "seeded mutations)" % (checked, len(texts)))
    lines.append("Pattern matches the prescan had to let through: %d" % total)
    if not total:
        problems.append("no pattern matched any text, so the gate tested nothing")
    for i in ids:
        if not matched[i]:
            problems.append("%s never matched any text here, so nothing checked its words. "
                            "Add a corpus case, or a phrase to SEEDS in this file." % i)

    # 5. A wrong plan must be caught.
    target = max(range(len(ids)), key=lambda i: matched[ids[i]])
    sabotaged = list(planned)
    sabotaged[target] = (planned[target][0], frozenset(["gp-prescan-gate-absent-word"]))
    caught = any(hidden_matches(prescan, sabotaged, text) for text in texts)
    if not caught:
        problems.append("the gate passed a plan with deliberately wrong words for %s, "
                        "so it cannot be trusted to fail" % ids[target])
    lines.append("A deliberately wrong plan for %s is %s"
                 % (ids[target], "caught" if caught else "NOT caught"))
    return rules, prescan, texts, lines, problems


def timing_inputs(rules, texts):
    """Three kinds of ordinary text, named, because the speedup depends on which."""
    import argparse as a_stdlib_module
    with open(a_stdlib_module.__file__, encoding="utf-8") as f:
        source = f.read()
    rng = random.Random(SEED)
    log = "\n".join(
        '2026-11-%02d %02d:%02d:%02d 10.0.%d.%d "GET /api/v1/items/%d HTTP/1.1" %d %d rt=%.3f'
        % (rng.randint(1, 28), rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59),
           rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 99999),
           rng.choice([200, 200, 200, 304, 404, 500]), rng.randint(100, 90000), rng.random())
        for _ in range(3000))
    clean = "\n".join(t for t in texts if not rules.has_instructions(t)
                      and not rules.hidden_content(t))
    return (("access log lines", log),
            ("Python source (this interpreter's argparse.py)", source),
            ("benign corpus text, written to sit close to the rules", clean))


def timing(rules, texts):
    """Both paths over tiled ordinary text. Machine dependent, so never a check."""
    out = []
    for name, base in timing_inputs(rules, texts):
        out.append(name)
        for size, label in ((20000, "20 KB"), (200000, "200 KB"), (2000000, "2 MB")):
            text = (base * (size // len(base) + 1))[:size]
            row = {}
            for setting in ("off", "on"):
                os.environ["GUARDIAN_PRESCAN"] = setting
                best = None
                for _ in range(5):
                    start = time.perf_counter()
                    rules.check_output("timing", text, {"tainted_by": None})
                    spent = time.perf_counter() - start
                    best = spent if best is None else min(best, spent)
                row[setting] = best * 1000
            del os.environ["GUARDIAN_PRESCAN"]
            out.append("  %-7s every pattern %8.2f ms   with the prescan %8.2f ms   %.1fx"
                       % (label, row["off"], row["on"], row["off"] / row["on"]))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sensor-dir", default=os.path.join(ROOT, "sensor"))
    ap.add_argument("--corpus", default=os.path.join(ROOT, "corpus"))
    ap.add_argument("--time", action="store_true",
                    help="also time check_output on three kinds of ordinary text")
    args = ap.parse_args()
    rules, _prescan, texts, lines, problems = run(args.sensor_dir, args.corpus)
    for line in lines:
        print(line)
    if args.time:
        print()
        for line in timing(rules, texts):
            print(line)
    for p in problems[:40]:
        print("FAIL " + p)
    if len(problems) > 40:
        print("FAIL and %d more" % (len(problems) - 40))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
