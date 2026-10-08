"""Command line for the scan.

  python3 -m guardian_scanner validate
  python3 -m guardian_scanner targets
  python3 -m guardian_scanner validate-results
  python3 -m guardian_scanner run --target scripted:vulnerable --repeat 10
  python3 -m guardian_scanner run --target claude-code --repeat 5 --pattern GP-0001
  python3 -m guardian_scanner run --target claude-code --repeat 10 --record ../results
"""
import argparse
import os
import sys

from . import patterns, report, results, runner, scenarios, targets


def _target_class(name):
    """The class behind a REGISTRY entry. The registry holds factories, not classes."""
    return targets.CLASSES.get(name)


def _model_example(name):
    return getattr(_target_class(name), "model_example", "") or "a current model"


def _model_verified_on(name):
    return getattr(_target_class(name), "model_verified_on", "") or "an earlier date"


def _target(name, model=None):
    make = targets.REGISTRY.get(name)
    if make:
        return make(model=model) if model else make()
    raise SystemExit(f"unknown target {name!r}. Run 'python3 -m guardian_scanner targets' "
                     "to see what this machine can run.")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardian_scanner", description="Guardian Protocol scan v0")
    sub = ap.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="check every pattern file against the schema")
    v.add_argument("--patterns", default=None)

    vr = sub.add_parser("validate-results",
                        help="check every recorded result in results/")
    vr.add_argument("--results", default=None)
    vr.add_argument("--patterns", default=None)

    sub.add_parser("targets", help="show which harnesses this machine can measure")

    ls = sub.add_parser("list", help="show which patterns the scan can run")
    ls.add_argument("--patterns", default=None)

    r = sub.add_parser("run", help="run each pattern's test many times and report a success rate")
    r.add_argument("--target", default="scripted:vulnerable")
    r.add_argument("--repeat", type=int, default=10)
    r.add_argument("--pattern", action="append", dest="only")
    r.add_argument("--sensor", action="store_true", help="put the reference sensor in front")
    r.add_argument("--model", default=None,
                   help="pin the harness to one model, for example opus or claude-opus-5. "
                        "Recorded as the model in the result file")
    r.add_argument("--json", action="store_true")
    r.add_argument("--record", default=None, metavar="DIR",
                   help="write a result file per pattern into DIR, usually ../results")
    r.add_argument("--patterns", default=None)

    a = ap.parse_args(argv)
    # Answered before anything reads a pattern file: this command is about the machine,
    # not the registry, and it has to work in a half set up checkout.
    if a.command == "targets":
        print(report.targets_text(targets.available(), targets.WANTED))
        return 0

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

    # Checked before a single run, because every run after this costs real model calls and a
    # late failure throws all of them away.
    if a.command == "run":
        if a.repeat < 1:
            raise SystemExit(f"--repeat {a.repeat} runs nothing. Use 1 or more.")
        # The floor belongs on recording, not on exploring. A single run is how anyone checks
        # that a new target works at all, and banning it would make writing a target harder.
        if a.record and a.repeat < results.MIN_RUNS:
            raise SystemExit(
                f"--repeat {a.repeat} is below {results.MIN_RUNS}, and --record would write a "
                f"result file that validate-results refuses. A measurement needs at least "
                f"{results.MIN_RUNS} runs to carry any information, and 20 is the figure Season 1 "
                "asks for. Drop --record to try a smaller run without recording it.")
        if getattr(_target_class(a.target), "requires_model", False) and not getattr(a, "model", None):
            raise SystemExit(
                f"{a.target} needs --model. Its own built-in default is retired for newly "
                "issued API keys and fails inside the vendor's routing before the scenario "
                "starts, with a 404 under a stack trace. Naming the model is also the honest "
                f"thing for a measurement: --model {_model_example(a.target)} worked on "
                f"{_model_verified_on(a.target)}. Current models are listed at "
                "https://ai.google.dev/gemini-api/docs/models")
        if a.record and not os.path.isdir(a.record):
            raise SystemExit(
                f"--record {a.record!r} is not a folder that exists. Create it first, or point at "
                "the registry's results folder with --record ../results. Checked now rather than "
                "after the runs, so a typo does not cost you the whole measurement.")

    runnable = scenarios.available()
    only = a.only or runnable
    unknown = [p for p in only if p not in runnable]
    if unknown:
        # A typo and a genuinely unimplemented pattern deserve different messages. Compare
        # case insensitively so 'gp-0001' is named as the typo it is.
        folded = {p.upper(): p for p in runnable}
        hints = []
        for p in unknown:
            match = folded.get(p.strip().upper())
            hints.append(f"{p!r} (did you mean {match!r}?)" if match else repr(p))
        raise SystemExit(
            f"no scenario in scanner v0 for {', '.join(hints)}. Run "
            "'python3 -m guardian_scanner list' to see which patterns the scan can run.")
    # Two different reasons a pattern was not run, and saying the wrong one misleads anyone
    # measuring a single pattern: no scenario exists, or --pattern left it out.
    skipped = [p for p in sorted(validation.patterns) if p not in only]
    no_scenario = [p for p in skipped if p not in runnable]
    left_out = [p for p in skipped if p in runnable]

    # Named 'measured', not 'results': the module of that name is imported above, and a
    # local would shadow it for the whole function, including the branch that uses it.
    target = _target(a.target, getattr(a, "model", None))
    measured = runner.run_all(target, repeat=a.repeat, sensor=a.sensor, only=only)
    print(report.results_json(measured) if a.json
          else report.results_text(measured, a.repeat, no_scenario, left_out))

    if a.record:
        written = results.record(measured, a.record, sensor_on=a.sensor, target=target)
        print("")
        for path in written:
            print(f"recorded {path}")
        print("Each file has placeholders the scan could not fill: your name in credits, "
              "the real environment, and the model if you know it. Fill them in, then "
              "run python3 check.py before opening a pull request.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
