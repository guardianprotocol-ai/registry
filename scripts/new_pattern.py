#!/usr/bin/env python3
"""Create the next pattern file from the template.

    python3 check.py new-pattern "Title of the attack"

Fills in the next free ID, the title, the status, the version and today's date, so nobody
types an ID or boilerplate by hand and nobody reuses an ID by accident. Everything else is
left as the template wrote it, for the author to replace.
"""
import datetime
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATTERNS = os.path.join(ROOT, "patterns")
TEMPLATE = os.path.join(ROOT, "docs", "pattern-template.yaml")
PATTERN_FILE = re.compile(r"^GP-(\d{4})\.yaml$")


def next_id(patterns_dir=PATTERNS):
    """One past the highest ID ever used. IDs are never reused, so this only goes up."""
    highest = 0
    for name in os.listdir(patterns_dir):
        match = PATTERN_FILE.match(name)
        if match:
            highest = max(highest, int(match.group(1)))
    return f"GP-{highest + 1:04d}"


# The template's opening lines tell a human how to copy it by hand. The scaffold has just
# done that, so they are replaced rather than left behind as a stale instruction.
TEMPLATE_HEADER = ("# Pattern template. Copy this file to patterns/GP-NNNN.yaml, using the next free ID,\n"
                   "# then replace every value and delete these comments. The full format is in schema.yaml,\n"
                   "# and patterns/GP-0001.yaml is a complete example.")


def fill(template_text, pattern_id, title, today):
    scaffold_header = (f"# {pattern_id}, scaffolded by `python3 check.py new-pattern`.\n"
                       "# Replace every value below and delete these comments. The full format is in\n"
                       "# schema.yaml, and patterns/GP-0001.yaml is a complete example.")
    template_text = template_text.replace(TEMPLATE_HEADER, scaffold_header)
    out = []
    for line in template_text.splitlines():
        if line.startswith("id:"):
            out.append(f"id: {pattern_id}")
        elif line.startswith("title:"):
            out.append(f"title: {title}")
        elif line.startswith("status:"):
            out.append("status: draft")
        elif line.startswith("version:"):
            out.append("version: 1")
        elif line.startswith("created:"):
            out.append(f"created: {today}")
        else:
            out.append(line)
    return "\n".join(out) + "\n"


PLACEHOLDERS = ("Short name", "one-line reason", "Your Name", "Your Organization",
                "What the", "Where to", "NNNN", "YYYY", "One to three sentences",
                "in plain language", "e.g.", "Link to", "What a team")


def _indent(line):
    return len(line) - len(line.lstrip())


def _looks_unfilled(value):
    return value in ("", ">", '""', "[]") or any(w in value for w in PLACEHOLDERS)


def todo_fields(text):
    """The fields still holding template text, in the order they appear.

    A block is reported by its own name rather than by each line inside it, so the list
    stays short enough to act on. A container whose contents are all filled in is not
    reported at all.
    """
    lines = [l for l in text.splitlines() if not l.strip().startswith("#")]
    left, seen = [], set()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or ":" not in stripped or stripped.startswith("- "):
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.split("#")[0].strip()
        block = []
        for nxt in lines[i + 1:]:
            if not nxt.strip():
                continue
            if _indent(nxt) <= _indent(line):
                break
            block.append(nxt.strip())
        has_block = bool(block)
        # A nested mapping is reported through its children, not by itself.
        if has_block and value == "" and any(":" in b and not b.startswith("- ") for b in block):
            continue
        unfilled = _looks_unfilled(value) if not has_block else any(
            _looks_unfilled(b.lstrip("- ").strip()) or any(w in b for w in PLACEHOLDERS)
            for b in block)
        if unfilled and key not in seen:
            seen.add(key)
            left.append(key)
    return left


def create(title, patterns_dir=PATTERNS, template=TEMPLATE, today=None):
    title = title.strip()
    if not title:
        raise ValueError("give the pattern a title")
    pattern_id = next_id(patterns_dir)
    path = os.path.join(patterns_dir, f"{pattern_id}.yaml")
    if os.path.exists(path):
        raise FileExistsError(path)
    with open(template, encoding="utf-8") as f:
        text = fill(f.read(), pattern_id, title,
                    today or datetime.date.today().isoformat())
    # "x" so a race or a stale listing can never overwrite someone's work.
    with open(path, "x", encoding="utf-8") as f:
        f.write(text)
    return path, text


def main(argv):
    if len(argv) < 2 or not argv[1].strip():
        print(__doc__.strip())
        return 2
    try:
        path, text = create(" ".join(argv[1:]))
    except FileExistsError as exists:
        print(f"{exists} already exists. Pattern IDs are never reused.")
        return 1
    except ValueError as bad:
        print(bad)
        return 2
    rel = os.path.relpath(path, ROOT)
    print(f"Created {rel}\n")
    left = todo_fields(text)
    if left:
        print("Still to fill in:")
        for field in left:
            print(f"  - {field}")
        print()
    print("Then run:  python3 check.py")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
