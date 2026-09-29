"""Command line for the scan.

  python3 -m guardian_scanner validate
  python3 -m guardian_scanner run --target scripted:vulnerable --repeat 10
  python3 -m guardian_scanner run --target claude-code --repeat 5 --pattern GP-0001
"""
import argparse
import sys

from . import patterns, report, runner, scenarios, targets


def _target(name):
    if name.startswith("scripted:"):
        return targets.scripted(name.split(":", 1)[1])
    if name == "claude-code":
        return targets.claude_code()
    raise SystemExit(f"unknown target {name!r}. Use scripted:vulnerable, scripted:hardened "
                     "or claude-code.")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardian_scanner", description="Guardian Protocol scan v0")
    sub = ap.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="check every pattern file against the schema")
    v.add_argument("--patterns", default=None)

    ls = sub.add_parser("list", help="show which patterns the scan can run")
    ls.add_argument("--patterns", default=None)

    r = sub.add_parser("run", help="run each pattern's test many times and report a success rate")
    r.add_argument("--target", default="scripted:vulnerable")
    r.add_argument("--repeat", type=int, default=10)
    r.add_argument("--pattern", action="append", dest="only")
    r.add_argument("--sensor", action="store_true", help="put the reference sensor in front")
    r.add_argument("--json", action="store_true")
    r.add_argument("--patterns", default=None)

    a = ap.parse_args(argv)
    directory = a.patterns or patterns.registry_dir()
    validation = patterns.validate_dir(directory)

    if a.command == "validate":
        print(report.validation_text(validation))
        return 0 if validation.ok else 1

    if a.command == "list":
        runnable = set(scenarios.available())
        for pid in sorted(validation.patterns):
            doc = validation.patterns[pid]
            mark = "runnable" if pid in runnable else "validated only"
            print(f"{pid:<9} {doc.get('status', '?'):<9} {mark:<15} {doc.get('title', '')}")
        return 0

    if not validation.ok:
        print(report.validation_text(validation))
        print("\nRefusing to run: fix the pattern files first.")
        return 1

    runnable = scenarios.available()
    only = a.only or runnable
    unknown = [p for p in only if p not in runnable]
    if unknown:
        raise SystemExit(f"no scenario in scanner v0 for {', '.join(unknown)}")
    skipped = [p for p in sorted(validation.patterns) if p not in only]

    results = runner.run_all(_target(a.target), repeat=a.repeat, sensor=a.sensor, only=only)
    print(report.results_json(results) if a.json
          else report.results_text(results, a.repeat, skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
