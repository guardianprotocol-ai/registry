#!/usr/bin/env python3
"""Generate docs/STATUS.md: how far Season 1 has got, from the repository alone.

    python3 scripts/build_status.py            write docs/STATUS.md
    python3 scripts/build_status.py --check    fail if docs/STATUS.md is out of date

No API calls and no network: everything here is read from the triage file, the pattern
files, the scanner's scenarios, the corpus and the recorded results. That is deliberate.
Progress nobody has to ask about is the point, and a page that needs a token to rebuild
would quietly stop being rebuilt. Python 3.9+ standard library only.
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "scanner"))

import coverage  # noqa: E402
from guardian_scanner import results as result_files  # noqa: E402
from guardian_scanner import scenarios  # noqa: E402

OUT = os.path.join(ROOT, "docs", "STATUS.md")

HEADER = """# Season 1 status

Generated from the repository by `python3 scripts/build_status.py`. Do not edit by hand:
`python3 check.py` fails if this file and the repository disagree.

Season 1 runs **October 5 to October 29, 2026**. What this page tracks is the Map phase and
what follows from it: the {total} MITRE ATLAS techniques that happen while an agent is
running. See [../PROGRAM.md](../PROGRAM.md) for the phases and how to pick something up.

A technique is **resolved** when a pattern covers it, or when it is marked not testable at
runtime with a reason. Everything else is open work, and every one of them has an issue.
"""

LEGEND = """
## What the columns mean

| Column | Meaning |
| --- | --- |
| Patterns | Registry patterns that map to this technique |
| Runnable | At least one of those patterns has a scanner scenario, so the attack can be run |
| Corpus | At least one of those patterns has an attack case in `corpus/attacks/` |
| Measured | At least one of those patterns has a recorded result in `results/` |
| State | `covered`, `not testable at runtime`, or `open` |
"""


def patterns_by_technique(folder=None):
    """ATLAS technique id -> sorted pattern ids that claim it."""
    folder = folder or os.path.join(ROOT, "patterns")
    out = {}
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".yaml"):
            continue
        with open(os.path.join(folder, name), encoding="utf-8") as f:
            text = f.read()
        pid = re.search(r"^id:\s*(\S+)", text, re.M)
        atlas = re.search(r"^\s*atlas:\s*\[(.*?)\]", text, re.M | re.S)
        if not pid or not atlas:
            continue
        for quoted in re.findall(r'"([^"]+)"', atlas.group(1)):
            out.setdefault(quoted.split(" ", 1)[0], set()).add(pid.group(1))
    return {k: sorted(v) for k, v in out.items()}


def attack_cases(folder=None):
    """pattern id -> how many attack cases in the corpus name it.

    Benign cases are deliberately not keyed to a pattern: the benign corpus is ordinary
    work that no rule may flag, so it applies to every rule at once rather than belonging
    to one. Counting it per technique would be inventing a relationship that is not there.
    """
    folder = folder or os.path.join(ROOT, "corpus", "attacks")
    counts = {}
    if not os.path.isdir(folder):
        return counts
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(folder, name), encoding="utf-8") as f:
                doc = json.load(f)
        except (ValueError, OSError):
            continue
        expect = doc.get("expect")
        for pid in ([expect] if isinstance(expect, str) else list(expect or [])):
            counts[pid] = counts.get(pid, 0) + 1
    return counts


def benign_cases(folder=None):
    """How many benign cases the whole corpus holds. Shared by every rule."""
    folder = folder or os.path.join(ROOT, "corpus", "benign")
    if not os.path.isdir(folder):
        return 0
    return len([n for n in os.listdir(folder) if n.endswith(".json")])


def measured_patterns(results_dir=None):
    return {doc["pattern"] for _, doc in result_files.load_dir(results_dir)}


def collect(coverage_path=None, results_dir=None):
    rows = coverage.agent_runtime(coverage.load(coverage_path))
    links = patterns_by_technique()
    corpus = attack_cases()
    measured = measured_patterns(results_dir)
    runnable = set(scenarios.available())
    out = []
    for row in rows:
        pats = links.get(row["id"], [])
        has_corpus = any(corpus.get(p, 0) > 0 for p in pats)
        if pats:
            state = "covered"
        elif row.get("status") == coverage.NOT_TESTABLE:
            state = "not testable at runtime"
        else:
            state = "open"
        out.append({
            "id": row["id"],
            "name": row["name"],
            "patterns": pats,
            "runnable": any(p in runnable for p in pats),
            "corpus": has_corpus,
            "measured": any(p in measured for p in pats),
            "state": state,
            "reason": (row.get("reason") or "").strip(),
        })
    return out


def summary(items):
    return {
        "total": len(items),
        "covered": sum(1 for i in items if i["state"] == "covered"),
        "not_testable": sum(1 for i in items if i["state"] == "not testable at runtime"),
        "open": sum(1 for i in items if i["state"] == "open"),
        "runnable": sum(1 for i in items if i["runnable"]),
        "corpus": sum(1 for i in items if i["corpus"]),
        "measured": sum(1 for i in items if i["measured"]),
        "benign": benign_cases(),
    }


def tick(value):
    return "yes" if value else "no"


def render(items):
    n = summary(items)
    resolved = n["covered"] + n["not_testable"]
    lines = [HEADER.format(total=n["total"])]
    lines.append("## Where Season 1 is\n")
    lines.append("| Phase | Measure | Count |")
    lines.append("| --- | --- | --- |")
    lines.append(f"| Map | Resolved, out of {n['total']} | **{resolved}** |")
    lines.append(f"| Map | Covered by a pattern | {n['covered']} |")
    lines.append(f"| Map | Marked not testable at runtime | {n['not_testable']} |")
    lines.append(f"| Map | Still open | {n['open']} |")
    lines.append(f"| Prove | With a runnable test | {n['runnable']} |")
    lines.append(f"| Prove | With an attack case in the corpus | {n['corpus']} |")
    lines.append(f"| Measure | With a recorded result | {n['measured']} |")
    lines.append(f"\nThe benign corpus holds {n['benign']} cases of ordinary work that no rule "
                 "may flag. It is shared by every rule rather than owned by one technique, so it "
                 "is counted once here and not per row.")
    lines.append(LEGEND)
    lines.append("## Every technique\n")
    lines.append("| Technique | Name | Patterns | Runnable | Corpus | Measured | State |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for i in sorted(items, key=lambda x: x["id"]):
        pats = ", ".join(i["patterns"]) if i["patterns"] else ""
        state = i["state"]
        if state == "not testable at runtime" and i["reason"]:
            state = f"not testable at runtime: {i['reason']}"
        lines.append(f"| `{i['id']}` | {i['name']} | {pats} | {tick(i['runnable'])} | "
                     f"{tick(i['corpus'])} | {tick(i['measured'])} | {state} |")
    lines.append("")
    lines.append("Open a technique's issue to claim it. If none of the {0} open ones look "
                 "right, [PROGRAM.md](../PROGRAM.md) lists the other phases."
                 .format(n["open"]))
    return "\n".join(lines) + "\n"


def _pair(detected, trials, interval):
    lo, hi = interval
    return "%d/%d, Wilson 95%% [%.4f, %.4f]" % (detected, trials, lo, hi)


def canary_benchmark_section():
    """The measured canary numbers, read from the benchmark file so this page cannot drift.

    Absent file, absent section content beyond the fact that it has not been recorded.
    The technique table above is unchanged: this is not a results/ scanner file.
    """
    path = os.path.join(ROOT, "benchmarks", "canary-benchmark.json")
    lines = ["", "## Canary benchmark", ""]
    if not os.path.exists(path):
        lines.append("No `benchmarks/canary-benchmark.json` is in the tree. "
                     "Generate it with `python3 benchmarks/canary_benchmark.py`.")
        return "\n".join(lines)
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    summary = doc["summary"]
    meta = doc["meta"]
    attack = summary["all_attack"]
    benign = summary["benign"]
    held = doc["held_out_summary"]["all"]
    lines.append("Generated from `benchmarks/canary-benchmark.json`, seed %s, %s trials "
                 "per scenario, Python %s. The full table is "
                 "[../benchmarks/canary-benchmark.md](../benchmarks/canary-benchmark.md). "
                 "GP-0020 only. The value is not stored. The tool calls are scripted: "
                 "no model chose them. The regression suite is the set of forms the "
                 "matcher was fixed against, so a full score there is a regression "
                 "result, not a general detection rate." % (
                     meta["seed"], meta["trials_per_scenario"], meta["python"]))
    lines.append("")
    lines.append("| Slice | Sensor | Pre-fix matcher | Naive exact text |")
    lines.append("| --- | --- | --- | --- |")
    for label, key in (
            ("Designed carriers", "plain_designed_carriers"),
            ("Formatting edges", "boundary_formatting"),
            ("Encodings and a split across two calls", "encoded"),
            ("All regression attacks", "all_attack")):
        block = summary[key]
        lines.append("| %s | %s | %s | %s |" % (
            label,
            _pair(block["gp0020_detected"], block["trials"], block["gp0020_wilson95"]),
            _pair(block["legacy_detected"], block["trials"], block["legacy_wilson95"]),
            _pair(block["baseline_detected"], block["trials"], block["baseline_wilson95"])))
    lines.append("| Benign false alarms | %s | %s | %s |" % (
        _pair(benign["gp0020_false_alarms"], benign["trials"], benign["gp0020_fp_wilson95"]),
        _pair(benign["legacy_false_alarms"], benign["trials"], benign["legacy_fp_wilson95"]),
        _pair(benign["baseline_false_alarms"], benign["trials"], benign["baseline_fp_wilson95"])))
    lines.append("")
    reproduced = "yes" if meta.get("legacy_reproduces_published_before") else "no"
    lines.append("Held-out transforms (rot13, base32, gzip then base64, reverse-order "
                 "halves, a zero-width character, ends only): %s. "
                 "A value that never appears in the arguments is not detected. "
                 "The pre-fix column reproduces the local run that found the gaps: %s. "
                 "Evidence contained the value in %d of %d regression trials." % (
                     _pair(held["gp0020_detected"], held["trials"], held["gp0020_wilson95"]),
                     reproduced,
                     attack["value_in_evidence"], attack["trials"]))
    lines.append("")
    return "\n".join(lines) + "\n"


def assumed_breach_section():
    """The assumed-breach numbers, read from the benchmark file so this page cannot drift."""
    path = os.path.join(ROOT, "benchmarks", "assumed-breach.json")
    lines = ["", "## Assumed-breach canaries", ""]
    if not os.path.exists(path):
        lines.append("No `benchmarks/assumed-breach.json` is in the tree. "
                     "Generate it with `python3 benchmarks/assumed_breach.py`.")
        return "\n".join(lines) + "\n"
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    meta = doc["meta"]
    sweep = doc["slices"]["scripted_sweep"]
    live = meta.get("live") or {}
    lines.append("Generated from `benchmarks/assumed-breach.json`, %d trials, Python %s. "
                 "The full table is [../benchmarks/assumed-breach.md](../benchmarks/assumed-breach.md). "
                 "The crawl is scripted. Live trial ran: %s."
                 % (meta["trials"], meta["python"], "yes" if live.get("ran") else "no"))
    lines.append("")
    lines.append("| Slice | Result | Wilson 95% |")
    lines.append("| --- | --- | --- |")
    n = sweep["trials"]
    for label, key in (
            ("Scripted crawl touched a decoy", "decoy_tripped"),
            ("Quarantine ran", "quarantined"),
            ("A crown jewel was touched before the first decoy", "crown_before"),
            ("Something new appeared outside the sandbox", "left_sandbox")):
        k = sweep[key]
        lo, hi = sweep[key + "_wilson95"]
        lines.append("| %s | %d/%d | [%.4f, %.4f] |" % (label, k, n, lo, hi))
    for label, key in (
            ("Seeded copy of the dataset", "seed_copy"),
            ("Seeded value in a tool call", "seed_tool_call"),
            ("Real asset allowlist", "asset_allow"),
            ("Decoy trip locks the real sibling", "sibling_quarantine"),
            ("Loopback sentinel", "sentinel"),
            ("Byte-for-byte copy of a real asset", "never_leaves_copy"),
            ("Allowlisted tool naming an outside URL", "never_leaves_tool"),
            ("git status false alarm", "git_status"),
            ("Copy of a decoy outside the root, observed", "exfil_copy"),
            ("Allowlisted write outside the root, not followed", "allowlisted_exfil")):
        block = doc["slices"][key]
        lo, hi = block["ok_wilson95"]
        lines.append("| %s | %d/%d | [%.4f, %.4f] |" % (
            label, block["ok"], block["trials"], lo, hi))
    lines.append("")
    lines.append("A descriptor opened before the watch is not seen. The poll backend misses a "
                 "read when the access time does not move, and the `poll_read` probe depends "
                 "on access-time updates being on. Timing medians depend on the machine. "
                 "An allowlisted process can write bytes outside the root, and the watcher "
                 "does not follow them. The limits are in "
                 "[../benchmarks/ASSUMED_BREACH.md](../benchmarks/ASSUMED_BREACH.md).")
    lines.append("")
    return "\n".join(lines) + "\n"


def multi_host_section():
    """The multi-host numbers, read from the benchmark file so this page cannot drift."""
    path = os.path.join(ROOT, "benchmarks", "multi-host-breach.json")
    lines = ["", "## Multi-host assumed breach", ""]
    if not os.path.exists(path):
        lines.append("No `benchmarks/multi-host-breach.json` is in the tree. "
                     "Generate it with `python3 benchmarks/multi_host_breach.py`.")
        return "\n".join(lines) + "\n"
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    meta = doc["meta"]
    summary = doc["summary"]
    live = meta.get("live") or {}
    n = summary["trials"]
    lines.append("Generated from `benchmarks/multi-host-breach.json`, %d trials, Python %s. "
                 "The full table is [../benchmarks/multi-host-breach.md](../benchmarks/multi-host-breach.md). "
                 "The sweep is scripted. Live trial ran: %s. "
                 "The hosts are network namespaces with no default route."
                 % (n, meta["python"], "yes" if live.get("ran") else "no"))
    lines.append("")
    lines.append("| Slice | Result | Wilson 95% |")
    lines.append("| --- | --- | --- |")
    rows = (
        ("Workstation decoy tripped", "workstation_tripped"),
        ("Workstation sibling quarantined", "workstation_sibling"),
        ("Data sentinel saw the workstation", "data_reached"),
        ("Repo sentinel saw the workstation", "repo_reached"),
        ("Data crown jewel quarantined by the end", "data_contained"),
        ("Repo crown jewel quarantined by the end", "repo_contained"),
        ("Hub stored a counts-only drill sighting", "hub_counts_only"),
        ("Seeded value written into a record", "token_in_records"),
        ("Data jewel moved before the hop connected", "protected_before_data"),
        ("Repo jewel moved before the hop connected", "protected_before_repo"),
        ("Seeded value arrived on the workstation", "seed_in_download"),
        ("Dataset download returned bytes", "dataset_downloaded"),
        ("Training file download returned bytes", "train_downloaded"),
        ("Data foothold recorded the crawl", "data_crawled"),
        ("Repo foothold recorded the crawl", "repo_crawled"),
        ("A route or connection left the lab", "escape"),
        ("Benign workload tripped", "benign_trip"),
        ("Trainer read the dataset and it stayed", "trainer_allowed"),
        ("Sentinel connections received no bytes", "payload_empty"),
    )
    for label, key in rows:
        k = summary[key]
        lo, hi = summary[key + "_wilson95"]
        lines.append("| %s | %d/%d | [%.4f, %.4f] |" % (label, k, n, lo, hi))
    lines.append("")

    def _fmt(value):
        return "not recorded" if value is None else "%.4f" % value

    lines.append("Median seconds to the first workstation decoy: %s. "
                 "Median seconds from that stamp to the data handshake: %s. "
                 "A negative arrival means the handshake finished before the stamp. "
                 "Protected-before counts a move that finished before the handshake, and "
                 "that claim did not hold: both rows are 0. Download counts vary with "
                 "timing. This table is one run (dataset 15/20, training file 2/20). "
                 "A rerun of the same sweep got 11/20 and 1/20. A download that returned "
                 "bytes is a leak. The limits are in "
                 "[../benchmarks/MULTI_HOST.md](../benchmarks/MULTI_HOST.md)." % (
                     _fmt(summary.get("median_detect_s")),
                     _fmt(summary.get("median_arrival_data_s"))))
    lines.append("")
    return "\n".join(lines) + "\n"


def build(coverage_path=None, results_dir=None):
    return (render(collect(coverage_path, results_dir))
            + canary_benchmark_section()
            + assumed_breach_section()
            + multi_host_section())


def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate the Season 1 status page")
    ap.add_argument("--check", action="store_true",
                    help="fail if docs/STATUS.md is out of date instead of writing it")
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--coverage", default=None)
    ap.add_argument("--results", default=None)
    a = ap.parse_args(argv)

    text = build(a.coverage, a.results)
    if a.check:
        current = ""
        if os.path.exists(a.out):
            with open(a.out, encoding="utf-8") as f:
                current = f.read()
        if current != text:
            print("docs/STATUS.md is out of date. Regenerate it:")
            print("  python3 scripts/build_status.py")
            return 1
        n = summary(collect(a.coverage, a.results))
        print(f"The status page is current: {n['covered'] + n['not_testable']} of "
              f"{n['total']} techniques resolved.")
        return 0

    with open(a.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
