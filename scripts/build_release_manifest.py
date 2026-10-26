#!/usr/bin/env python3
"""Build the release manifest a sensor checks an update against.

    python3 scripts/build_release_manifest.py --out dist/

Writes the rule set and a manifest of SHA-256 hashes beside it. Upload the whole folder to
the GitHub release; `python3 -m guardian_sensor update --base <release url>` fetches the
manifest first and refuses anything that does not match it.

This is not signing. v0 relies on the integrity of the GitHub release plus these hashes,
which protects against a corrupted or truncated download and against a file swapped after
the manifest was made, but not against someone who can publish the release itself. Sigstore
and TUF are on the roadmap; `THREAT_MODEL.md` says so plainly.

Python 3.9+ standard library only.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "sensor"))

from guardian_sensor import hub  # noqa: E402

SIGNATURES = os.path.join(ROOT, "sensor", "guardian_sensor", "signatures.json")
PATTERNS = os.path.join(ROOT, "patterns")
STATUS_NAME = "pattern-status.json"
MANIFEST_NAME = "manifest.json"
RELEASES_NAME = "releases.jsonl"
# What a release is made of. Named rather than discovered, so nothing else in the
# directory can end up inside the thing members verify.
RELEASE_FILES = ("signatures.json", "pattern-status.json")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def pattern_status(folder=None):
    """pattern id -> status, from the pattern files."""
    folder = folder or PATTERNS
    out = {}
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".yaml"):
            continue
        with open(os.path.join(folder, name), encoding="utf-8") as f:
            text = f.read()
        pid = re.search(r"^id:\s*(\S+)", text, re.M)
        status = re.search(r"^status:\s*(\S+)", text, re.M)
        if pid and status:
            out[pid.group(1)] = status.group(1)
    return out


def build(out_dir, rules_version, signatures=None, patterns=None):
    os.makedirs(out_dir, exist_ok=True)
    shutil.copyfile(signatures or SIGNATURES, os.path.join(out_dir, "signatures.json"))
    with open(os.path.join(out_dir, STATUS_NAME), "w", encoding="utf-8") as f:
        json.dump(pattern_status(patterns), f, indent=2, sort_keys=True)
        f.write("\n")

    files = {}
    for name in sorted(os.listdir(out_dir)):
        # Only the files this release is made of. Hashing whatever else happens to be in
        # the directory swept up the agenda once, which would have broken verification
        # every time the schedule changed.
        if name in (MANIFEST_NAME, RELEASES_NAME) or name not in RELEASE_FILES:
            continue
        files[name] = hub.sha256_of(os.path.join(out_dir, name))

    manifest = {"schema_version": hub.SCHEMA_VERSION,
                "rules_version": rules_version,
                # When this was published. Without it the interval between a rule being
                # published and a member running it, which is the number this research
                # exists to report, cannot be computed from anything.
                "published": _now(),
                "files": files}
    path = os.path.join(out_dir, MANIFEST_NAME)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    # The manifest only ever describes the current release. Time to protection is asked
    # about releases that are no longer current, so each one is appended to a log that
    # is published beside it and never rewritten.
    note_release(out_dir, rules_version, manifest["published"])
    return manifest


def note_release(out_dir, rules_version, published):
    """Append this release to the published history, once."""
    path = os.path.join(out_dir, RELEASES_NAME)
    seen = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    seen.append(json.loads(line))
    except (OSError, ValueError):
        seen = []
    if any(r.get("rules_version") == rules_version for r in seen):
        return False
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"rules_version": rules_version,
                            "published": published}, sort_keys=True) + "\n")
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build a release manifest for the rule set")
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    ap.add_argument("--rules-version", default=None,
                    help="defaults to today, as rYYYY.MM.DD")
    a = ap.parse_args(argv)
    version = a.rules_version or datetime.date.today().strftime("r%Y.%m.%d")
    manifest = build(a.out, version)
    print(f"wrote {os.path.join(a.out, MANIFEST_NAME)}")
    print(f"rules version {manifest['rules_version']}, {len(manifest['files'])} file(s):")
    for name, digest in sorted(manifest["files"].items()):
        print(f"  {name}  {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
