"""Tests for the custom-mapping detector used by the labeler.

Run from the repository root:  python3 scripts/tests/test_detect_custom_mapping.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from detect_custom_mapping import adds_custom_mapping  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def case(name, diff, expected):
    check(name, adds_custom_mapping(diff) is expected, repr(diff[:70]))


def test_an_added_reason_counts():
    case("a real custom_reason is detected",
         '+  custom_reason: "The closest is AML.T0051.001, which covers instructions "\n'
         '+    "reaching the model rather than the tool registry."', True)


def test_an_empty_reason_does_not_count():
    case("an empty string is not a custom mapping", '+  custom_reason: ""', False)
    case("a bare key is not a custom mapping", '+  custom_reason:', False)
    case("a key with only a comment is not a custom mapping",
         '+  custom_reason:   # say why here', False)


def test_only_added_lines_count():
    case("a removed line does not count", '-  custom_reason: "was here"', False)
    case("an unchanged context line does not count",
         '   custom_reason: "unchanged"', False)


def test_other_fields_do_not_trigger_it():
    case("an atlas mapping does not trigger it", '+  atlas: ["AML.T0080 Context Poisoning"]', False)
    case("an empty diff does not trigger it", "", False)


def test_a_real_looking_diff():
    diff = """diff --git a/patterns/GP-0013.yaml b/patterns/GP-0013.yaml
new file mode 100644
--- /dev/null
+++ b/patterns/GP-0013.yaml
@@ -0,0 +1,8 @@
+schema_version: "0.1"
+id: GP-0013
+maps_to:
+  owasp: ["LLM01:2025 Prompt Injection"]
+  atlas: []
+  custom_reason: "The closest is AML.T0051.001, but that covers instructions reaching
+    the model, not an attack on the tool registry itself."
"""
    case("a whole added pattern with a custom mapping is detected", diff, True)


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
