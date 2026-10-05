#!/usr/bin/env python3
"""Run every check a pull request must pass, in one command.

    python3 check.py                      run every check
    python3 check.py new-pattern "Title"  scaffold the next pattern file

This validates every pattern file and runs every test suite. The same script runs on
every pull request, so if it passes on your machine, the automatic checks should pass too.
No dependencies beyond the Python 3.9+ standard library.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
# The whole suite takes a few seconds. A check still running after five minutes
# is stuck, not slow.
TIMEOUT_SECONDS = 300

# (label, working directory, command)
CHECKS = [
    ("Pattern files are valid", "scanner", ["-m", "guardian_scanner", "validate"]),
    ("Recorded results are valid", "scanner", ["-m", "guardian_scanner", "validate-results"]),
    ("Coverage triage is valid", ".", ["scripts/check_coverage.py"]),
    ("The attack matrix is up to date", ".", ["scripts/build_matrix.py", "--check"]),
    ("The status page is up to date", ".", ["scripts/build_status.py", "--check"]),
    ("Docs link to things that exist", ".", ["scripts/check_docs.py"]),
    ("No live invisible characters", ".", ["scripts/check_invisible.py"]),
    ("Sensor rule tests", "sensor", ["tests/test_rules.py"]),
    ("Sensor end to end test", "sensor", ["tests/test_sensor.py"]),
    ("Sharing hub tests", "sensor", ["tests/test_hub.py"]),
    ("Scanner parser tests", "scanner", ["tests/test_yamlish.py"]),
    ("Scanner tests", "scanner", ["tests/test_scanner.py"]),
    ("Result file tests", "scanner", ["tests/test_results.py"]),
    ("Claude Code hook tests", ".", ["hooks/claude_code/tests/test_hook.py"]),
    ("Pattern scaffold tests", ".", ["scripts/tests/test_new_pattern.py"]),
    ("Status guard tests", ".", ["scripts/tests/test_check_status_changes.py"]),
    ("Contributor data tests", ".", ["scripts/tests/test_build_contributors.py"]),
    ("Meeting summary tests", ".", ["scripts/tests/test_shipped.py"]),
    ("Custom mapping detector tests", ".", ["scripts/tests/test_detect_custom_mapping.py"]),
    ("Attack matrix tests", ".", ["scripts/tests/test_build_matrix.py"]),
    ("Season 1 status tests", ".", ["scripts/tests/test_build_status.py"]),
    ("Season 1 issue tests", ".", ["scripts/tests/test_season_one_issues.py"]),
    ("Sightings aggregation tests", ".", ["scripts/tests/test_aggregate_sightings.py"]),
    ("Rule lint", ".", ["scripts/lint_rules.py"]),
    ("Rule gate: attacks caught, ordinary work left alone", ".", ["scripts/rule_gate.py"]),
]


def new_pattern(argv):
    """python3 check.py new-pattern "Title" scaffolds the next pattern file."""
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import new_pattern as scaffold
    return scaffold.main(["new-pattern"] + argv)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "new-pattern":
        return new_pattern(sys.argv[2:])
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    failed = []
    for label, folder, args in CHECKS:
        # Output is captured, so a check that hangs would print nothing and stall until
        # the CI job's own timeout. Bound it here, where the partial output still exists.
        try:
            result = subprocess.run(
                [sys.executable] + args,
                cwd=os.path.join(ROOT, folder),
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
            )
            ok = result.returncode == 0
            output = (result.stdout + result.stderr).strip()
        except subprocess.TimeoutExpired as expired:
            ok = False
            parts = [part for part in (expired.stdout, expired.stderr) if part]
            output = "".join(
                part.decode(errors="replace") if isinstance(part, bytes) else part
                for part in parts
            ).strip()
            output = f"timed out after {TIMEOUT_SECONDS} seconds\n{output}".strip()
        print(f"{'pass' if ok else 'FAIL'}  {label}")
        if (verbose or not ok) and output:
            print("      " + output.replace("\n", "\n      "))
        if not ok:
            failed.append(label)
    print()
    if failed:
        print(f"{len(failed)} of {len(CHECKS)} checks failed: {', '.join(failed)}")
        return 1
    print(f"All {len(CHECKS)} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
