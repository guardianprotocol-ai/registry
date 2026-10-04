#!/usr/bin/env python3
"""Run every check a pull request must pass, in one command.

    python3 check.py

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
    ("Sensor rule tests", "sensor", ["tests/test_rules.py"]),
    ("Sensor end to end test", "sensor", ["tests/test_sensor.py"]),
    ("Scanner parser tests", "scanner", ["tests/test_yamlish.py"]),
    ("Scanner tests", "scanner", ["tests/test_scanner.py"]),
    ("Claude Code hook tests", ".", ["hooks/claude_code/tests/test_hook.py"]),
]


def main():
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
        sys.exit(1)
    print(f"All {len(CHECKS)} checks passed.")


if __name__ == "__main__":
    main()
