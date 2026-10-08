"""Turn scan results into something a person can act on."""
import json


def _bar(rate, width=20):
    filled = int(round(rate * width))
    return "#" * filled + "." * (width - filled)


def validation_text(report):
    lines = [f"Validated {len(report.patterns)} pattern files."]
    if report.ok:
        lines.append("All valid: every required field present, every mapping real, "
                     "canaries well formed, no destination a test could really reach.")
    else:
        lines.append(f"{len(report.problems)} problem(s):")
        lines += [f"  - {p}" for p in report.problems]
    # Printed every run, pass or fail, so custom mappings never quietly become the norm.
    if report.custom:
        lines.append("")
        lines.append(f"{len(report.custom)} pattern(s) map to no ATLAS technique:")
        lines += [f"  - {pid}: {reason}" for pid, reason in report.custom]
        lines.append("Check these against each ATLAS release and remap when one fits. "
                     "See docs/MAINTAINING.md.")
    else:
        lines.append("Every pattern maps to a MITRE ATLAS technique.")
    return "\n".join(lines)


def targets_text(rows, wanted=()):
    """What this machine can measure, and what nobody has written a target for yet."""
    def mark(value):
        return {True: "yes", False: "no", None: "unknown"}[value]

    lines = [f"{'TARGET':<22}{'INSTALLED':<11}{'CREDENTIALS':<13}NOTES",
             "-" * 78]
    ready = 0
    for name, installed, credentials, note in rows:
        if installed and credentials is not False:
            ready += 1
        lines.append(f"{name:<22}{mark(installed):<11}{mark(credentials):<13}{note}")

    lines.append("")
    lines.append(f"{ready} of {len(rows)} ready on this machine.")
    measures_a_model = [n for n, i, c, _ in rows
                        if not n.startswith("scripted:") and i and c is not False]
    if measures_a_model:
        lines.append("Measures a real model: " + ", ".join(measures_a_model) +
                     ". The scripted targets are the control, not the finding.")
    else:
        lines.append("Nothing here measures a real model yet. The scripted targets are the "
                     "control, not the finding.")
    lines.append("'unknown' means the harness keeps its own session and cannot be checked "
                 "from here without spending a call.")

    if wanted:
        lines.append("")
        lines.append("No target written yet, and each one is two short methods:")
        for key, description in wanted:
            lines.append(f"  {key:<20}{description}")
        lines.append("See TEST_YOUR_AGENT.md. This is the highest value thing to contribute.")
    return "\n".join(lines)


def results_validation_text(report):
    """What check.py prints for results/."""
    count = len(report.results)
    if count == 0:
        return ("No recorded results yet. Measure a target and record one: see "
                "results/README.md.")
    lines = [f"Validated {count} recorded result(s)."]
    if report.ok:
        targets = sorted({
            "%s %s" % (d.get("target", {}).get("harness", "?"),
                       d.get("target", {}).get("harness_version", "?"))
            for d in report.results.values()})
        lines.append("Every rate and interval recomputes from its own counts.")
        lines.append("Targets measured so far: " + ", ".join(targets) + ".")
    else:
        lines.append(f"{len(report.problems)} problem(s):")
        lines += [f"  - {p}" for p in report.problems]
    return "\n".join(lines)


def results_text(results, repeat, skipped=()):
    head = (f"{'Pattern':<9} {'Target':<20} {'Runs':>4} {'ASR':>7} {'95% interval':>16}  "
            f"{'':<20} Errors")
    lines = ["", head, "-" * len(head)]
    for r in results:
        low, high = r.interval
        lines.append(f"{r.pattern_id:<9} {r.target_name:<20} {r.runs:>4} {r.rate:>6.0%} "
                     f"{'[' + format(low, '.2f') + ', ' + format(high, '.2f') + ']':>16}  "
                     f"{_bar(r.rate):<20} {r.errors}")
    lines.append("")
    lines.append(f"ASR is the attack success rate over {repeat} runs per pattern. The interval is a "
                 "95% Wilson score interval.")
    lines.append("A rate is a measurement, not a verdict: agents do not behave the same way twice, "
                 "and a narrow interval needs many runs.")
    if skipped:
        lines.append("")
        lines.append(f"Not run, because scanner v0 has no scenario for them yet: {', '.join(skipped)}. "
                     "They were validated only.")
    return "\n".join(lines)


def results_json(results):
    return json.dumps([r.as_dict() for r in results], indent=2)
