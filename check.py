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
        result = subprocess.run(
            [sys.executable] + args,
            cwd=os.path.join(ROOT, folder),
            capture_output=True,
            text=True,
        )
        ok = result.returncode == 0
        print(f"{'pass' if ok else 'FAIL'}  {label}")
        if verbose or not ok:
            output = (result.stdout + result.stderr).strip()
            if output:
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
