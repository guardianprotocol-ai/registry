#!/usr/bin/env python3
"""Rule lint: catch dangerous signatures before anyone has to review them.

    python3 scripts/lint_rules.py

Checks every signature in sensor/guardian_sensor/signatures.json:

1. The file is plain ASCII. Invisible or look-alike characters must be written as escapes
   (\\u200b), so a reviewer can see every character a rule matches.
2. Every signature has a unique id and compiles.
3. No signature matches empty text. A pattern that matches nothing at all matches everywhere.
4. No signature matches ordinary prose. A pattern that fires on plain sentences would block
   everyday work for everyone who runs the sensor.
5. No nested repetition such as (a+)+, the usual shape of a pattern that can be made to run
   for minutes on a crafted input and hang the sensor.
6. Every signature finishes quickly on large adversarial inputs.

No dependencies beyond the Python 3.9+ standard library. Exits non-zero on any problem.
"""
import json
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGNATURES = os.path.join(ROOT, "sensor", "guardian_sensor", "signatures.json")
FLAGS = {"i": re.I, "s": re.S}

# Plain sentences no detection should ever match.
ORDINARY = [
    "Shipping times improved 12% this quarter.",
    "Thanks for the update, see you at the meeting on Thursday.",
    "The portal launches in November, and the team is ready.",
    "Please review the attached report when you have a moment.",
    "We moved the standup to 10am because of the holiday.",
    "Our customers in Ohio asked for faster delivery windows.",
    "The build passed and the release notes are in the wiki.",
    "Lunch is on the fourth floor today.",
    "I updated the spreadsheet with the latest numbers.",
    "Can you summarize this article for me?",
    "The function returns a list of strings sorted by length.",
    "Run the tests before you commit, then open a pull request.",
    "hello",
    "OK",
    "1234567890",
]

# Large inputs built to make a badly written pattern backtrack.
ADVERSARIAL = [
    "a" * 20000 + "!",
    " " * 20000 + "x",
    "assistant " * 2000,
    "send the " * 2000,
    "A" * 20000,
    "<!--" * 5000,
    ("ab" * 10000) + "=",
]
TIME_LIMIT = 0.5  # seconds per signature across all adversarial inputs

# A repeated group that itself repeats. Groups that start with an escaped separator such as
# (?:\.[a-z]+)+ are exempt: the separator makes every split unambiguous, so they can't blow up.
NESTED = re.compile(r"\((?:\?:|(?!\?))(?!\\[^\w\s])(?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")


def entries(data):
    """Every signature entry, with a readable location."""
    out = []
    for key, value in data.items():
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and "pattern" in item:
                    out.append((f"{key}/{item.get('id')}", item))
        elif isinstance(value, dict):
            if "pattern" in value:
                out.append((f"{key}/{value.get('id')}", value))
            else:
                for sub, item in value.items():
                    if isinstance(item, dict) and "pattern" in item:
                        out.append((f"{key}.{sub}/{item.get('id')}", item))
    return out


def lint(path=SIGNATURES):
    problems = []
    raw = open(path, "rb").read()
    try:
        raw.decode("ascii")
    except UnicodeDecodeError as e:
        problems.append(f"signatures.json has a non-ASCII byte at offset {e.start}: write it as a \\u escape")
    data = json.loads(raw.decode("utf-8"))
    found = entries(data)

    ids = [item.get("id") for _, item in found]
    for i in sorted({i for i in ids if ids.count(i) > 1}):
        problems.append(f"duplicate id: {i}")
    for where, item in found:
        if not item.get("id"):
            problems.append(f"{where}: missing id")

    ids_in_instruction = {e.get("id") for e in data.get("instruction", [])}
    for ref in data.get("bias", []):
        if ref not in ids_in_instruction:
            problems.append(f"bias/{ref}: refers to no instruction signature")

    for where, item in found:
        flags = 0
        for ch in item.get("flags", ""):
            if ch not in FLAGS:
                problems.append(f"{where}: unknown flag {ch!r}")
                continue
            flags |= FLAGS[ch]
        try:
            rx = re.compile(item["pattern"], flags)
        except re.error as e:
            problems.append(f"{where}: does not compile: {e}")
            continue
        if rx.search(""):
            problems.append(f"{where}: matches empty text, so it matches everything")
        hits = [s for s in ORDINARY if rx.search(s)]
        if hits:
            problems.append(f"{where}: matches ordinary prose, e.g. {hits[0]!r}")
        if NESTED.search(item["pattern"]):
            problems.append(f"{where}: nested repetition, which can hang the sensor on crafted input")
        start = time.perf_counter()
        for text in ADVERSARIAL:
            rx.search(text)
        took = time.perf_counter() - start
        if took > TIME_LIMIT:
            problems.append(f"{where}: took {took:.2f}s on adversarial input (limit {TIME_LIMIT}s)")
    return found, problems


def main():
    found, problems = lint()
    if problems:
        for p in problems:
            print(f"FAIL {p}")
        print(f"\n{len(problems)} problem(s) in {len(found)} signatures.")
        sys.exit(1)
    print(f"All {len(found)} signatures pass the rule lint.")


if __name__ == "__main__":
    main()
