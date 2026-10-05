"""Command line for the scan.

  python3 -m guardian_scanner validate
  python3 -m guardian_scanner validate-results
  python3 -m guardian_scanner run --target scripted:vulnerable --repeat 10
  python3 -m guardian_scanner run --target claude-code --repeat 5 --pattern GP-0001
  python3 -m guardian_scanner run --target claude-code --repeat 10 --record ../results
"""
import argparse
import sys

from . import patterns, report, results, runner, scenarios, targets


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

    vr = sub.add_parser("validate-results",
                        help="check every recorded result in results/")
    vr.add_argument("--results", default=None)
    vr.add_argument("--patterns", default=None)

    ls = sub.add_parser("list", help="show which patterns the scan can run")
    ls.add_argument("--patterns", default=None)

    r = sub.add_parser("run", help="run each pattern's test many times and report a success rate")
    r.add_argument("--target", default="scripted:vulnerable")
    r.add_argument("--repeat", type=int, default=10)
    r.add_argument("--pattern", action="append", dest="only")
    r.add_argument("--sensor", action="store_true", help="put the reference sensor in front")
    r.add_argument("--json", action="store_true")
    r.add_argument("--record", default=None, metavar="DIR",
                   help="write a result file per pattern into DIR, usually ../results")
    r.add_argument("--patterns", default=None)

    a = ap.parse_args(argv)
    directory = a.patterns or patterns.registry_dir()
    validation = patterns.validate_dir(directory)

    if a.command == "validate":
        print(report.validation_text(validation))
        return 0 if validation.ok else 1

    if a.command == "validate-results":
        if not validation.ok:
            print(report.validation_text(validation))
            print("\nRefusing to check results: fix the pattern files first.")
            return 1
        found = results.validate_dir(a.results, known_patterns=set(validation.patterns),
                                     runnable=set(scenarios.available()))
        print(report.results_validation_text(found))
        return 0 if found.ok else 1

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

    # Named 'measured', not 'results': the module of that name is imported above, and a
    # local would shadow it for the whole function, including the branch that uses it.
    measured = runner.run_all(_target(a.target), repeat=a.repeat, sensor=a.sensor, only=only)
    print(report.results_json(measured) if a.json
          else report.results_text(measured, a.repeat, skipped))

    if a.record:
        written = results.record(measured, a.record, sensor_on=a.sensor)
        print("")
        for path in written:
            print(f"recorded {path}")
        print("Each file has placeholders the scan could not fill: your name in credits, "
              "the real environment, and the model if you know it. Fill them in, then "
              "run python3 check.py before opening a pull request.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
