"""Validate recorded measurements.

Patterns describe attacks. Results describe targets. A pattern is never forked per model:
when the same attack lands on one model and not another, that variation lives here.

A result is a claim with numbers attached, so every one of them is checked: the pattern
exists, the run count is not too small to mean anything, and the rate and interval are
recomputed from the counts rather than trusted. A file whose arithmetic does not reproduce
is refused, because a wrong number published under this project's name is worse than no
number at all.
"""
import datetime
import json
import math
import os
import re
import subprocess

SCHEMA_VERSION = "0.1"

# Five is the smallest run count that says anything at all, and even then the interval is
# roughly 0 to 0.43. The matrix prints the interval next to every rate for this reason.
MIN_RUNS = 5

# How closely a stored number has to reproduce. Files store four decimal places.
TOLERANCE = 1e-4

REQUIRED = ("schema_version", "pattern", "target", "sensor", "runs", "successes",
            "errored", "rate", "interval", "date", "scanner_commit", "environment",
            "credits")
TARGET_FIELDS = ("model", "model_version", "harness", "harness_version")

# Enough of an explanation to be worth reading, for a pattern the scanner cannot drive.
MIN_MANUAL_ENVIRONMENT = 40

# What --record writes where the scan cannot know. Refused by the checks, so it has to be
# replaced before a measurement can be merged.
PLACEHOLDER = "unrecorded"

Z = 1.959963985  # 95 per cent


def wilson(successes, scored):
    """95% Wilson score interval. With nothing scored it is the whole range, which is true."""
    if scored <= 0:
        return (0.0, 1.0)
    p = successes / scored
    denom = 1 + Z * Z / scored
    centre = (p + Z * Z / (2 * scored)) / denom
    half = Z * math.sqrt(p * (1 - p) / scored + Z * Z / (4 * scored * scored)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def rate_of(successes, scored):
    return successes / scored if scored else 0.0


def slug(value):
    """Lowercase, safe for a filename, and stable across platforms."""
    return re.sub(r"[^a-z0-9.]+", "-", str(value).lower()).strip("-")


def filename_for(doc):
    target = doc.get("target") or {}
    sensor = (doc.get("sensor") or {}).get("state", "")
    return "__".join([
        slug(doc.get("pattern", "")),
        slug(target.get("harness", "")),
        slug(target.get("model", "")),
        slug(doc.get("date", "")),
        "sensor-" + slug(sensor),
    ]) + ".json"


class Report:
    def __init__(self):
        self.results = {}
        self.problems = []

    @property
    def ok(self):
        return not self.problems

    def fail(self, name, message):
        self.problems.append(f"{name}: {message}")


def _is_text(value):
    return isinstance(value, str) and value.strip() != ""


def _check_target(name, doc, report):
    target = doc.get("target")
    if not isinstance(target, dict):
        report.fail(name, "target must be a mapping with model, model_version, harness "
                          "and harness_version")
        return
    for field in TARGET_FIELDS:
        if not _is_text(target.get(field)):
            report.fail(name, f"target.{field} is required. Write 'unrecorded' if the "
                              "harness does not expose it, rather than leaving it out")


def _check_sensor(name, doc, report):
    sensor = doc.get("sensor")
    if not isinstance(sensor, dict):
        report.fail(name, "sensor must be a mapping with state 'off' or 'on'")
        return
    state = sensor.get("state")
    if state not in ("off", "on"):
        report.fail(name, f"sensor.state must be 'off' or 'on', not {state!r}")
    if state == "on" and not _is_text(sensor.get("bundle")):
        report.fail(name, "sensor.state is 'on', so sensor.bundle must name the rule bundle "
                          "or the commit the rules came from")


def _check_counts(name, doc, report):
    numbers = {}
    for field in ("runs", "successes", "errored"):
        value = doc.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            report.fail(name, f"{field} must be a whole number that is not negative")
            return None
        numbers[field] = value
    if numbers["runs"] < MIN_RUNS:
        report.fail(name, f"runs is {numbers['runs']}. A measurement needs at least "
                          f"{MIN_RUNS} runs to carry any information")
    if numbers["successes"] + numbers["errored"] > numbers["runs"]:
        report.fail(name, "successes plus errored is more than runs")
        return None
    return numbers


def _check_arithmetic(name, doc, report, numbers):
    """Recompute the rate and interval instead of trusting them."""
    scored = numbers["runs"] - numbers["errored"]
    expected_rate = rate_of(numbers["successes"], scored)
    rate = doc.get("rate")
    if not isinstance(rate, (int, float)) or isinstance(rate, bool):
        report.fail(name, "rate must be a number")
    elif abs(float(rate) - expected_rate) > TOLERANCE:
        report.fail(name, f"rate is {rate}, but {numbers['successes']} of {scored} scored "
                          f"runs is {round(expected_rate, 4)}. Errored runs are excluded "
                          "from the rate")
    interval = doc.get("interval")
    if (not isinstance(interval, list) or len(interval) != 2
            or not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in interval)):
        report.fail(name, "interval must be a list of two numbers, the 95% Wilson bounds")
        return
    low, high = wilson(numbers["successes"], scored)
    if abs(float(interval[0]) - low) > TOLERANCE or abs(float(interval[1]) - high) > TOLERANCE:
        report.fail(name, f"interval is {interval}, but the 95% Wilson interval for "
                          f"{numbers['successes']} of {scored} is "
                          f"[{round(low, 4)}, {round(high, 4)}]")


def _check_date(name, doc, report):
    value = doc.get("date")
    if not _is_text(value):
        report.fail(name, "date is required, as YYYY-MM-DD")
        return
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        report.fail(name, f"date {value!r} is not a valid YYYY-MM-DD date")


def _check_credits(name, doc, report):
    credits = doc.get("credits")
    if not isinstance(credits, list) or not credits:
        report.fail(name, "credits must list at least one person, so the measurement has "
                          "someone's name on it")
        return
    for entry in credits:
        if not isinstance(entry, dict) or not _is_text(entry.get("name")):
            report.fail(name, "every credit needs a name")
            return
        # --record writes this placeholder on purpose. It must not survive to a merge.
        if entry["name"].strip().lower() == PLACEHOLDER:
            report.fail(name, "credits still says 'unrecorded'. Put your name on the "
                              "measurement before opening a pull request")
            return


def validate_one(name, doc, report, known_patterns=None, runnable=None):
    if not isinstance(doc, dict):
        report.fail(name, "a result file must contain one JSON object")
        return
    missing = [f for f in REQUIRED if f not in doc]
    if missing:
        report.fail(name, "missing field(s): " + ", ".join(missing))
        return
    if doc.get("schema_version") != SCHEMA_VERSION:
        report.fail(name, f"schema_version must be {SCHEMA_VERSION!r} for now")
    pattern = doc.get("pattern")
    if known_patterns is not None and pattern not in known_patterns:
        report.fail(name, f"pattern {pattern!r} is not in patterns/")
    _check_target(name, doc, report)
    _check_sensor(name, doc, report)
    numbers = _check_counts(name, doc, report)
    if numbers:
        _check_arithmetic(name, doc, report, numbers)
    _check_date(name, doc, report)
    _check_credits(name, doc, report)
    if not _is_text(doc.get("scanner_commit")):
        report.fail(name, "scanner_commit is required. Write 'unrecorded' rather than "
                          "leaving it out")
    environment = doc.get("environment")
    if _is_text(environment) and environment.strip().lower().startswith(PLACEHOLDER):
        report.fail(name, "environment still has the placeholder the scan wrote. Replace it "
                          "with the operating system, the settings that mattered, and "
                          "anything that was not captured")
    elif not _is_text(environment):
        report.fail(name, "environment is required: operating system, settings that matter, "
                          "and anything that was not recorded")
    elif runnable is not None and pattern not in runnable and len(environment.strip()) < MIN_MANUAL_ENVIRONMENT:
        report.fail(name, f"the scanner has no scenario for {pattern}, so environment must "
                          "say how the test was actually run")
    expected = filename_for(doc)
    if name != expected:
        report.fail(name, f"filename should be {expected}, built from the pattern, harness, "
                          "model, date and sensor state")


def results_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "..", "results"))


def load_dir(path=None):
    """Every result file, newest first, as (filename, document) pairs."""
    path = path or results_dir()
    if not os.path.isdir(path):
        return []
    out = []
    for name in sorted(os.listdir(path)):
        if not name.endswith(".json") or name == "schema.json":
            continue
        with open(os.path.join(path, name), encoding="utf-8") as f:
            out.append((name, json.load(f)))
    return out


def validate_dir(path=None, known_patterns=None, runnable=None):
    path = path or results_dir()
    report = Report()
    if not os.path.isdir(path):
        return report
    for name in sorted(os.listdir(path)):
        if not name.endswith(".json") or name == "schema.json":
            continue
        full = os.path.join(path, name)
        try:
            with open(full, encoding="utf-8") as f:
                doc = json.load(f)
        except (ValueError, OSError) as e:
            report.fail(name, f"could not be read as JSON: {e}")
            continue
        report.results[name] = doc
        validate_one(name, doc, report, known_patterns=known_patterns, runnable=runnable)
    return report


# --------------------------------------------------------------------------
# Recording a scan
# --------------------------------------------------------------------------

def scanner_commit():
    """The commit the scan ran from, or 'unrecorded' outside a checkout."""
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=here,
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return PLACEHOLDER
    value = out.stdout.strip()
    return value if out.returncode == 0 and value else PLACEHOLDER


def target_of(target_name, harness_version=None, model=None):
    """What the scan can honestly say about what it ran against.

    A closed harness does not tell us which model served the session, so that stays
    'unrecorded' rather than being guessed. The scripted agents are not a model at all.
    """
    if target_name.startswith("scripted:"):
        kind = target_name.split(":", 1)[1]
        return {"model": "none", "model_version": "none",
                "harness": "scripted-" + slug(kind),
                "harness_version": harness_version or SCHEMA_VERSION}
    # The model is whatever the operator pinned. A harness asked for nothing in particular
    # does not report which model answered, so it stays unrecorded rather than guessed.
    return {"model": model or PLACEHOLDER, "model_version": model or PLACEHOLDER,
            "harness": slug(target_name), "harness_version": harness_version or PLACEHOLDER}


def document_for(result, sensor_on, date=None, commit=None, harness_version=None,
                 model=None):
    """Turn a scan Result into a result document, with placeholders where it cannot know."""
    scored = result.runs
    total = scored + result.errors
    low, high = wilson(result.successes, scored)
    return {
        "schema_version": SCHEMA_VERSION,
        "pattern": result.pattern_id,
        "target": target_of(result.target_name, harness_version, model),
        "sensor": {"state": "on", "bundle": commit or scanner_commit()} if sensor_on
                  else {"state": "off"},
        "runs": total,
        "successes": result.successes,
        "errored": result.errors,
        "rate": round(rate_of(result.successes, scored), 4),
        "interval": [round(low, 4), round(high, 4)],
        "date": date or datetime.date.today().isoformat(),
        "scanner_commit": commit or scanner_commit(),
        "environment": PLACEHOLDER + ". Replace this with the operating system, the "
                       "settings that mattered, and anything the scan could not capture.",
        "credits": [{"name": PLACEHOLDER, "organization": PLACEHOLDER}],
        "notes": PLACEHOLDER,
    }


def record(scan_results, directory, sensor_on, date=None, commit=None, target=None):
    """Write one file per measured pattern. Returns the paths written."""
    os.makedirs(directory, exist_ok=True)
    # Asked once, not per result: a version check costs a process start.
    harness_version = target.version() if target is not None and hasattr(target, "version") else None
    model = target.model_requested() if target is not None and hasattr(target, "model_requested") else None
    written = []
    for result in scan_results:
        doc = document_for(result, sensor_on, date=date, commit=commit,
                           harness_version=harness_version, model=model)
        path = os.path.join(directory, filename_for(doc))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
        written.append(path)
    return written
