#!/usr/bin/env bash
# Create the issues for rule safety and the at-scale design. Run once, from the repository
# root, after scripts/create_starter_issues.sh:
#
#   bash scripts/create_rule_safety_issues.sh
#
# Running it twice creates duplicates.
set -euo pipefail

REPO="${1:-guardianprotocol-ai/registry}"
command -v gh >/dev/null || { echo "Install the GitHub CLI first: https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Sign in first: gh auth login"; exit 1; }

gh label create "track:governance" --color "5319e7" --description "Policy, process and project decisions" --repo "$REPO" --force >/dev/null

issue() {  # title, labels, body on stdin
  gh issue create --repo "$REPO" --title "$1" --label "$2" --body-file - >/dev/null
  echo "created: $1"
}

issue "Proposal 0001: declarative detection rules" "proposal,track:sensor,track:governance" <<'EOF'
Discussion and decision for [docs/proposals/0001-declarative-rules.md](../blob/main/docs/proposals/0001-declarative-rules.md).

Signatures are already data. This proposal moves each pattern's detection logic out of Python and into small rule files evaluated by a fixed engine, so a rule change can only ever flag the wrong thing, never run code, and every future engine (Go or Rust sensor, client hooks) evaluates the same files.

Open for at least 7 days, then decided by a majority of maintainers (GOVERNANCE.md). Open questions are listed at the end of the proposal.
EOF

issue "Proposal 0002: running the registry at scale" "proposal,track:governance" <<'EOF'
Discussion and decision for [docs/proposals/0002-registry-at-scale.md](../blob/main/docs/proposals/0002-registry-at-scale.md).

Content separate from code, one directory per pattern, signed rule bundles in channels, the corpus as a conformance suite for every engine, per-rule budgets, and field feedback. The proposal recommends moving to the new layout before v0.1, while there are few patterns.
EOF

issue "Ratify the rule safety policy" "proposal,track:governance" <<'EOF'
[docs/RULE_SAFETY.md](../blob/main/docs/RULE_SAFETY.md) lists proposed defaults: no new false alarms on the benign corpus, how long new rules run in monitor mode, who can promote a pattern to enforced, when false-alarm rates get written into pattern files, and how emergency rules work.

Discuss here, then update `corpus/policy.json` and the document to match what the group decides.
EOF

issue "Implement the declarative rule engine (after 0001 is accepted)" "track:sensor,help wanted" <<'EOF'
Once proposal 0001 is accepted: write an engine that evaluates rule files beside the current one, port GP-0001 to GP-0012, and show with `python3 scripts/rule_gate.py` that every corpus case gives the same result before and after. Then remove the Python per-pattern logic.

The corpus is the proof: no case may change outcome.
EOF

issue "Move to one directory per pattern (after 0002 is accepted)" "track:patterns,help wanted" <<'EOF'
Once proposal 0002 is accepted: move each pattern to `patterns/GP-NNNN/` with `pattern.yaml`, its detection and its own test cases, and update the validator, the rule gate and the docs. IDs and content stay the same.
EOF

issue "Fix the known false alarm: a user's own request after reading instruction-like text" "track:sensor,help wanted" <<'EOF'
`corpus/benign/known-egress-after-instruction-like-file.json` documents it: once anything instruction-like is read, every send outside the allow-list raises GP-0001, including requests the user made themselves.

Fixing it needs the engine to track where a destination came from: a destination the user typed is theirs; one that first appeared in untrusted content is suspect. When fixed, the gate will report the known false alarm no longer fires; remove the `known_false_alarm` field so it's checked as clean from then on.
EOF

issue "Prototype a signed rule bundle" "track:sensor,help wanted" <<'EOF'
Proposal 0002 and the roadmap (v0.2) describe sensors loading a single signed bundle rather than the repository: a versioned file with a manifest of every rule, its hash and its mode.

**Task:** a script that builds the bundle from the repository, and a sensor option to load it and refuse a bundle whose hashes don't match. Signing with TUF comes after; design the format so it can be signed without changes.
EOF

issue "Require two-factor authentication for the organization" "track:governance" <<'EOF'
Stolen maintainer accounts are the most common way open source projects get compromised. Organization owners: Settings, Authentication security, require two-factor authentication for everyone. Note in THREAT_MODEL.md when it's on.
EOF

echo "Done."
