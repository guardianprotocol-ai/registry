#!/usr/bin/env python3
"""On a pull request, require proof alongside any change to what the sensor detects.

    python3 scripts/require_rule_tests.py [BASE] [HEAD]

Compares BASE and HEAD (by default HEAD^1 and HEAD, which on a pull request's merge commit
are the base branch and the merged result). If the change touches the detection engine or
its signatures, it must also add or change a test or a corpus case. A rule change with no
new evidence fails.

It also warns when a pattern is promoted to `enforced`: that needs approval from two
maintainers at different organizations (GOVERNANCE.md), which reviewers must confirm.
"""
import subprocess
import sys

RULE_FILES = ("sensor/guardian_sensor/rules.py", "sensor/guardian_sensor/signatures.json")
EVIDENCE_PREFIXES = ("sensor/tests/", "hooks/claude_code/tests/", "corpus/")


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "HEAD^1"
    head = sys.argv[2] if len(sys.argv) > 2 else "HEAD"
    changed = [f for f in git("diff", "--name-only", base, head).splitlines() if f]

    rule_changes = [f for f in changed if f in RULE_FILES]
    evidence = [f for f in changed if f.startswith(EVIDENCE_PREFIXES)]

    promoted = []
    for f in changed:
        if f.startswith("patterns/") and f.endswith(".yaml"):
            diff = git("diff", base, head, "--", f)
            if any(line.startswith("+status:") and "enforced" in line for line in diff.splitlines()):
                promoted.append(f)
    for f in promoted:
        print(f"::warning file={f}::Promoted to enforced. Needs approval from two maintainers "
              f"at different organizations (GOVERNANCE.md).")

    if rule_changes and not evidence:
        print("FAIL this change edits what the sensor detects but adds no evidence.")
        print("     Changed: " + ", ".join(rule_changes))
        print("     Add or update a test in sensor/tests/ or a case in corpus/attacks/ or corpus/benign/")
        print("     that shows what the change catches, and what ordinary work it leaves alone.")
        sys.exit(1)
    if rule_changes:
        print("Rule change comes with evidence: " + ", ".join(evidence))
    else:
        print("No change to detection rules.")


if __name__ == "__main__":
    main()
