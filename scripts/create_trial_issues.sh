#!/usr/bin/env bash
# Create the issues for the distributed trial. Run once, from the repository root:
#
#   bash scripts/create_trial_issues.sh
#
# Running it twice creates duplicates.
set -euo pipefail

REPO="${1:-guardianprotocol-ai/registry}"
command -v gh >/dev/null || { echo "Install the GitHub CLI first: https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Sign in first: gh auth login"; exit 1; }

# Every label this script uses, created up front so the script does not depend on any
# other having run first. `--force` makes this safe to repeat.
ensure_labels() {
  for spec in "$@"; do
    name="${spec%%|*}"; rest="${spec#*|}"; color="${rest%%|*}"; desc="${rest#*|}"
    gh label create "$name" --color "$color" --description "$desc" --repo "$REPO" --force >/dev/null
  done
}

ensure_labels "track:research|1d76db|Research, experiments and the trial" "season-1|0e8a16|Season 1: Oct 5 to Oct 29, 2026" "help wanted|008672|Extra attention is wanted"


issue() {  # title, labels, body on stdin
  gh issue create --repo "$REPO" --title "$1" --label "$2" --body-file - >/dev/null
  echo "created: $1"
}

issue "Take part in the distributed trial" "track:research,season-1,help wanted" <<'EOF'
The trial is the group's first experiment: real sensors on members' own development agents, a real exchange of anonymized sightings, and a measured time to protection across organizations.

**What taking part involves**

- The sensor runs in **monitor mode** on a development or staging agent. Not on customer production systems, unless your company chooses that in writing.
- You run `python3 -m guardian_sensor report --preview` and see exactly what would be shared before anything leaves your machine. A sighting carries only a member id you choose, the sensor and rules versions, a pattern id, whether it was flagged or blocked, the hour, and a count.
- You share that file. Nothing else.

**What it does not involve**

No tool names, no arguments, no URLs, no file paths, no message text, and no timestamp finer than the hour. Those are not stripped out of the shared file; they are never read. The allow-list is in `sensor/guardian_sensor/hub.py` and the tests that attack it are in `sensor/tests/test_hub.py`. Please read both before you decide.

**Before you say yes**

This is opt-in per company, with your company's own written approval from whoever owns security or legal there. You can withdraw at any time and have your data removed before publication. We are not lawyers and this is not legal advice.

Comment here if your company is interested and we will send the participation guide.
EOF

issue "Experiment 1: cross-company baseline" "track:research,season-1" <<'EOF'
Each participating company runs the scanner against its own agent and records the results in the attack matrix format.

```bash
cd scanner
python3 -m guardian_scanner run --target <your target> --repeat 20 --record ../results
python3 -m guardian_scanner run --target <your target> --repeat 20 --sensor --record ../results
```

At least 20 runs per cell, sensor off and on. Results stay private until the group and each company approve publication; see [SECURITY.md](../blob/main/SECURITY.md).

**Output:** a row per company in the matrix, and the first comparison of the same attacks across different agents and models.
EOF

issue "Experiment 2: false alarms on real work" "track:research,season-1" <<'EOF'
Sensors run in **monitor mode only** on each company's development agent traffic for two to three weeks. Monitor mode flags and records; it blocks nothing.

**Output:** a false-alarm rate measured on real work rather than on a corpus, from the sightings plus each member's own review of what was flagged.

Every false alarm found here becomes a benign corpus case in `corpus/benign/`, which is how it stops happening to everyone else. Known false alarms are marked in the case, never hidden.
EOF

issue "Experiment 3: fire drill, time to protection" "track:research,season-1" <<'EOF'
One member contributes a new harmless pattern: canary tokens and reserved `.test` destinations only. We release it, and measure the time from merge and release until each participating sensor has updated and blocks the drill attack.

Each sensor's `.guardian/updates.jsonl` records when it updated and to which rules version, so the measurement is taken from the members' own machines rather than claimed centrally.

**Headline metric:** time to protection across N organizations. That number is the argument for the protocol existing, and nobody has published it.
EOF

issue "Experiment 4: privacy test, try to break the sightings" "track:research,season-1" <<'EOF'
Members try to recover sensitive information from the shared sightings. Adversarial, on purpose.

Things worth trying: can you tell which company a sighting came from; can counts plus timing identify a specific incident; does the `scripts/aggregate_sightings.py` threshold actually hold when one organization contributes most of the volume; can a crafted evidence log get content into an output file.

**Output:** what leaked, if anything, and the fix. Every successful attempt becomes a test in `sensor/tests/test_hub.py` so it cannot come back.

This issue is a good first contribution for anyone who likes breaking things, and it needs no company to take part.
EOF
