"""Tests for the small YAML reader.

The registry has no third-party dependencies, so the scanner reads pattern files with a
reader that covers only the subset `schema.yaml` uses. It is deliberately strict: anything
outside that subset raises rather than being guessed at, so a pattern file that drifts is
caught here and not misread somewhere downstream.

Run from the scanner folder:  python3 tests/test_yamlish.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_scanner import yamlish  # noqa: E402

PATTERNS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "patterns")

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def test_scalars():
    got = yamlish.loads('a: one\nb: "two"\nc: 3\nd: null\n')
    check("plain, quoted, integer and null scalars",
          got == {"a": "one", "b": "two", "c": 3, "d": None}, str(got))


def test_a_colon_inside_a_value_is_not_a_key():
    got = yamlish.loads('id: AML.T0051.001 LLM Prompt Injection: Indirect\n')
    check("a colon inside a value does not split the value",
          got == {"id": "AML.T0051.001 LLM Prompt Injection: Indirect"}, str(got))


def test_inline_list():
    got = yamlish.loads('surfaces: [mcp_tool_output, retrieved_document]\n')
    check("inline list", got == {"surfaces": ["mcp_tool_output", "retrieved_document"]}, str(got))


def test_inline_list_of_quoted_strings_with_commas():
    got = yamlish.loads('atlas: ["AML.T0080 Context Poisoning", "AML.T0101 Destruction"]\n')
    check("inline list keeps quoted items whole",
          got == {"atlas": ["AML.T0080 Context Poisoning", "AML.T0101 Destruction"]}, str(got))


def test_block_list():
    got = yamlish.loads('preconditions:\n  - first thing\n  - second thing\n')
    check("block list", got == {"preconditions": ["first thing", "second thing"]}, str(got))


def test_nested_map():
    got = yamlish.loads('maps_to:\n  owasp: [A]\n  atlas: [B]\n')
    check("nested map", got == {"maps_to": {"owasp": ["A"], "atlas": ["B"]}}, str(got))


def test_folded_block_scalar():
    got = yamlish.loads('summary: >\n  one line\n  and another\nid: X\n')
    check("folded scalar joins its lines and keeps one trailing newline",
          got == {"summary": "one line and another\n", "id": "X"}, str(got))


def test_folded_block_scalar_then_a_sibling_at_depth():
    text = 'test:\n  payload: >\n    hidden text here\n    over two lines\n  success_when: it fired\n'
    got = yamlish.loads(text)
    check("a folded scalar ends at the next key of its own depth",
          got == {"test": {"payload": "hidden text here over two lines\n",
                           "success_when": "it fired"}}, str(got))


def test_a_list_item_can_wrap_onto_the_next_line():
    text = 'setup:\n  - hide it by a rule that removes it\n    from display, and more\n  - second item\n'
    got = yamlish.loads(text)
    check("a wrapped list item is joined into one string",
          got == {"setup": ["hide it by a rule that removes it from display, and more",
                            "second item"]}, str(got))


def test_a_list_item_that_reads_as_a_map_is_refused():
    """YAML reads "- some words: more" as a map, which is never what a pattern means.

    GP-0006 shipped with exactly this and was not valid YAML at all. Refusing it here is
    what stops a pattern file being read one way by this reader and another way, or not at
    all, by anything else.
    """
    try:
        yamlish.loads('setup:\n  - hide it by a means: a rule that removes it\n')
        check("a list item that reads as a map is refused", False, "no error raised")
    except yamlish.YamlishError as e:
        check("a list item that reads as a map is refused", "quote" in str(e).lower(), str(e))


def test_a_plain_value_can_wrap_onto_the_next_line():
    text = 'severity: high (a reason that runs on\n  to a second line)\nid: X\n'
    got = yamlish.loads(text)
    check("a wrapped plain value is joined into one string",
          got == {"severity": "high (a reason that runs on to a second line)", "id": "X"}, str(got))


def test_inline_map_in_a_list():
    got = yamlish.loads('credits:\n  - {name: Ada Lovelace, organization: Analytical Engines}\n')
    check("inline map inside a block list",
          got == {"credits": [{"name": "Ada Lovelace", "organization": "Analytical Engines"}]}, str(got))


def test_comments_and_blank_lines_are_ignored():
    got = yamlish.loads('# a comment\n\na: one\n\n# another\nb: two\n')
    check("comments and blank lines ignored", got == {"a": "one", "b": "two"}, str(got))


def test_a_url_keeps_its_scheme():
    got = yamlish.loads('references:\n  - https://atlas.mitre.org/techniques/AML.T0080\n')
    check("a url in a list is not split on its colon",
          got == {"references": ["https://atlas.mitre.org/techniques/AML.T0080"]}, str(got))


def test_tabs_are_refused():
    try:
        yamlish.loads("a:\n\t- one\n")
        check("a tab raises rather than being guessed at", False, "no error raised")
    except yamlish.YamlishError:
        check("a tab raises rather than being guessed at", True)


def test_unsupported_construct_is_refused():
    try:
        yamlish.loads("a: &anchor one\nb: *anchor\n")
        check("an anchor raises rather than being guessed at", False, "no error raised")
    except yamlish.YamlishError:
        check("an anchor raises rather than being guessed at", True)


def test_every_pattern_file_loads():
    names = sorted(f for f in os.listdir(PATTERNS) if f.endswith(".yaml"))
    check("there are pattern files to read", len(names) >= 12, f"found {len(names)}")
    for n in names:
        try:
            got = yamlish.load_file(os.path.join(PATTERNS, n))
        except Exception as e:
            check(f"{n} loads", False, f"{type(e).__name__}: {e}")
            continue
        check(f"{n} loads with its id and nested blocks",
              got.get("id") == n[:-5] and isinstance(got.get("test"), dict)
              and isinstance(got.get("maps_to"), dict)
              and isinstance(got.get("test", {}).get("steps"), list),
              str(got)[:160])


def main():
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print()
    if failures:
        print(f"FAIL ({len(failures)}): {', '.join(failures)}")
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
