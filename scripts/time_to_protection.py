#!/usr/bin/env python3
"""How long between a rule being published and members running it.

    python3 scripts/time_to_protection.py trial/sightings site/season1/releases.jsonl

This is the number the project exists to report. Everything else it measures, that an
attack is caught, that a sighting travels, that a threshold holds, is already true of
systems that existed before it. The claim that is new is that a detection found at one
organization becomes a working defence at others faster than any human process, and that
is an interval, not a yes.

It needs no new collection. Every sighting already carries the rules version the member
was running and the hour they ran it, so the first hour a member reports under a new
version is the hour they adopted it. Granularity is the hour, because that is what the
format allows, and an honest hour beats a dishonest second.

Three ways to report this flatteringly, all refused here.

**A member who never adopted is the result, not missing data.** They are counted and
named as not adopted. Dropping them turns a bad distribution into a good one, and they
are the members an attacker reaches.

**The clock starts when the rule was published**, not when a member first polled.
Polling delay is part of how long somebody was exposed. Subtracting it measures our
software instead of their safety.

**A member who was switched off is still a member.** Said out loud rather than quietly
excluded, because an experiment that reports only the machines that were awake is
reporting on attentiveness.

Python 3.9+ standard library only, and it reads files, so anybody holding the exported
sightings can recompute every number here without our infrastructure.
"""
import argparse
import datetime
import glob
import json
import os
import sys

HOUR = "%Y-%m-%dT%H"


def releases(path):
    """rules_version -> when it was published."""
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                version, published = record.get("rules_version"), record.get("published")
                if isinstance(version, str) and isinstance(published, str):
                    out[version] = published
    except OSError:
        return {}
    return out


def adoptions(folder):
    """(org, rules_version) -> the earliest hour that member reported under it."""
    first = {}
    for path in sorted(glob.glob(os.path.join(folder, "*", "*.json"))):
        try:
            with open(path, encoding="utf-8") as f:
                document = json.load(f)
        except (OSError, ValueError):
            continue
        for entry in document.get("sightings") or []:
            org = entry.get("org")
            version = entry.get("rules_version")
            hour = entry.get("hour")
            if not (isinstance(org, str) and isinstance(version, str)
                    and isinstance(hour, str)):
                continue
            key = (org, version)
            if key not in first or hour < first[key]:
                first[key] = hour
    return first


def _parse_hour(text):
    try:
        return datetime.datetime.strptime(text[:13], HOUR).replace(
            tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError):
        return None


def _parse_time(text):
    try:
        when = datetime.datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None
    return when if when.tzinfo else when.replace(tzinfo=datetime.timezone.utc)


def intervals(folder, releases_path, version=None):
    """For one release: how long each member took, and who never arrived.

    Returns (version, published, [(org, hours)], [orgs that never adopted]).
    """
    published_at = releases(releases_path)
    if not published_at:
        return None
    first = adoptions(folder)
    members = sorted({org for org, _ in first})
    version = version or sorted(published_at)[-1]
    published = _parse_time(published_at.get(version))
    if published is None:
        return None

    took, never = [], []
    for org in members:
        hour = first.get((org, version))
        when = _parse_hour(hour) if hour else None
        if when is None:
            never.append(org)
            continue
        # Negative means a member reported under this version before it was published,
        # which cannot happen and means a clock is wrong somewhere. Reported as zero and
        # named, rather than pulling the median down.
        hours = (when - published).total_seconds() / 3600.0
        took.append((org, max(hours, 0.0)))
    return version, published, sorted(took, key=lambda r: r[1]), never


def _median(values):
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def text(result):
    if result is None:
        return ("No release history, or none for that version. Nothing can be said about "
                "how long\nprotection took without knowing when the rule was published.\n")
    version, published, took, never = result
    total = len(took) + len(never)
    if not total:
        return ("No member has reported under any version, so there is nothing to "
                "measure yet.\n")
    lines = ["Time to protection for %s, published %s" % (version, published.isoformat()),
             ""]
    if took:
        hours = [h for _, h in took]
        lines.append("  members protected   %d of %d" % (len(took), total))
        lines.append("  median              %.1f hours" % _median(hours))
        lines.append("  fastest             %.1f hours" % min(hours))
        lines.append("  slowest             %.1f hours" % max(hours))
    else:
        lines.append("  members protected   0 of %d" % total)
    if never:
        lines.append("  never adopted       %d (%s)"
                     % (len(never), ", ".join(never[:6])
                        + (", ..." if len(never) > 6 else "")))
    lines.append("")
    lines.append("Measured in whole hours, because a sighting carries no finer time. The")
    lines.append("clock starts when the rule was published, not when a member first")
    lines.append("looked, because the wait is part of how long they were exposed.")
    if never:
        lines.append("")
        lines.append("Members who never adopted are counted above and not dropped. They")
        lines.append("are the ones an attacker still reaches, so leaving them out would")
        lines.append("turn this result into a better one than it is.")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("folder", help="a folder of <org>/ directories holding sightings")
    ap.add_argument("releases", help="the published releases.jsonl")
    ap.add_argument("--rules-version", default=None,
                    help="which release to measure. Defaults to the most recent")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    result = intervals(a.folder, a.releases, a.rules_version)
    if a.json:
        if result is None:
            json.dump({"error": "no release history"}, sys.stdout)
        else:
            version, published, took, never = result
            json.dump({"rules_version": version,
                       "published": published.isoformat(),
                       "adopted": [{"org": o, "hours": round(h, 2)} for o, h in took],
                       "never_adopted": never,
                       "median_hours": round(_median([h for _, h in took]), 2)
                       if took else None}, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    sys.stdout.write(text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
