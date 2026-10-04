#!/usr/bin/env bash
# Create the labels and starter issues for new contributors. Run once, from the repository
# root, with the GitHub CLI signed in as a maintainer:
#
#   bash scripts/create_starter_issues.sh
#
# Labels are safe to re-run (they are updated in place). Issues are not: running the script
# twice creates duplicates.
set -euo pipefail

REPO="${1:-guardianprotocol-ai/registry}"

command -v gh >/dev/null || { echo "Install the GitHub CLI first: https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Sign in first: gh auth login"; exit 1; }

label() { gh label create "$1" --color "$2" --description "$3" --repo "$REPO" --force >/dev/null; }

label "good first issue" "7057ff" "A good place to start"
label "help wanted"      "008672" "Ready for someone to pick up"
label "proposal"         "fbca04" "Needs discussion before work starts"
label "track:patterns"   "2459ff" "Attack patterns and the schema"
label "track:scanner"    "2459ff" "Scanner, scenarios and reference agents"
label "track:sensor"     "2459ff" "Sensor, rules and client hooks"
label "track:coverage"   "2459ff" "MITRE ATLAS and OWASP coverage, incidents"
label "track:research"   "2459ff" "Deception and model behavior research"
label "docs"             "0e8a16" "Documentation"

issue() {  # title, labels, body on stdin
  gh issue create --repo "$REPO" --title "$1" --label "$2" --body-file - >/dev/null
  echo "created: $1"
}

scenario() {  # id, title, labels
  issue "Add a scanner scenario for $1: $2" "$3" <<EOF
$1 ($2) validates, but the scan can't run it yet: \`python3 -m guardian_scanner list\` shows it as "validated only".

**Task:** add a scenario in \`scanner/guardian_scanner/scenarios.py\` so the scan can run $1 end to end. If the pattern needs a tool the lab server doesn't offer yet, add it to \`sensor/tests/fake_server.py\`. The pattern file \`patterns/$1.yaml\` describes the setup, steps, payload and success condition.

**Done when:**
- \`python3 -m guardian_scanner run --target scripted:vulnerable --repeat 10 --pattern $1\` reports the attack succeeding
- the same run against \`scripted:hardened\` reports it failing
- \`python3 check.py\` passes
- payloads use canary tokens and \`.test\` destinations only

The three existing scenarios (GP-0001 to GP-0003) are the model to follow. Comment here to claim it.
EOF
}

scenario GP-0004 "Instructions written into the agent's long-term memory" "track:scanner,help wanted"
scenario GP-0005 "Destructive action taken after reading outside content" "track:scanner,help wanted"
scenario GP-0006 "Content hidden from the human reader" "track:scanner,help wanted"
scenario GP-0007 "Credential file read after the agent read outside content" "track:scanner,good first issue"
scenario GP-0008 "Instructions passed on to another agent" "track:scanner,help wanted"
scenario GP-0009 "Instructions written into a shared file or agent configuration" "track:scanner,help wanted"
scenario GP-0010 "Outside content steering which sources the agent trusts" "track:scanner,help wanted"
scenario GP-0011 "Runaway repetition of the same tool call" "track:scanner,good first issue"
scenario GP-0012 "The agent's own system prompt on its way out" "track:scanner,good first issue"

issue "Review the ATLAS coverage triage: agent runtime techniques" "track:coverage,good first issue" <<'EOF'
`coverage/atlas-coverage.csv` triages every MITRE ATLAS technique by where the protocol can act on it. Every row is a first draft by one person.

**Task:** review the rows in the "Agent runtime" category (about 60). For each, check whether the `sensor` and `scan` columns are right, and correct them with a one-line reason in the pull request.

Split it with others if you like: comment with the range of rows you're taking.
EOF

issue "Review the ATLAS coverage triage: supply chain and model pipeline techniques" "track:coverage,good first issue" <<'EOF'
Same as the agent runtime review, for the "Supply chain" and "Model and training pipeline" rows in `coverage/atlas-coverage.csv` (about 40).

Many of these are outside what a sensor can see. The useful question for each is whether the scan, the network or a mitigation note could still help.
EOF

issue "Propose patterns from AgentDojo" "track:patterns,help wanted" <<'EOF'
[AgentDojo](https://github.com/ethz-spylab/agentdojo) is a public benchmark of prompt injection attacks on tool-using agents.

**Task:** go through its attack types and list which ones the registry doesn't cover yet. Open one "Propose a pattern" issue for each gap, or a pull request with draft patterns using `docs/pattern-template.yaml`.
EOF

issue "Propose patterns from published MCP security research" "track:patterns,help wanted" <<'EOF'
Several public write-ups describe attacks on MCP servers and clients, such as tool poisoning, rug pulls and cross-server shadowing.

**Task:** collect the publicly documented ones, check them against the existing patterns, and propose the gaps as new patterns. Cite the source in `references`. Anything that is an unreported vulnerability in a specific product goes through `SECURITY.md`, not here.
EOF

issue "Propose patterns from OWASP's guidance on agentic AI" "track:patterns,help wanted" <<'EOF'
OWASP publishes guidance on threats to agentic AI applications alongside the Top 10 for LLM applications.

**Task:** map its threats to existing patterns, note the gaps, and propose new patterns for them. Add the OWASP IDs to `maps_to` on existing patterns where they apply.
EOF

issue "Build a benign traffic corpus for measuring false alarms" "track:scanner,help wanted" <<'EOF'
Every detection needs a false-alarm rate, measured on ordinary agent work. Today `false_alarm_rate` is null on every pattern because there is no corpus to measure against.

**Task:** design and start a corpus of realistic, harmless agent tool traffic (reading files, fetching pages, writing code, sending messages to allowed destinations), in a format the sensor's rules can be run over. Open with a short design comment here before building.
EOF

issue "Add a reference agent on an open-weight model" "track:scanner,help wanted" <<'EOF'
The scan has scripted reference agents and a Claude Code target. To compare attack success rates across models, it needs a target driven by an open-weight model, for example through Ollama. The demo already has an Ollama agent in `demo/demo.py` that could be a starting point.

**Task:** add a scanner target for an open-weight model, document it in `scanner/README.md`, and report a first measurement with the number of runs and the interval.
EOF

issue "Add a client hook for another agent client" "track:sensor,help wanted" <<'EOF'
`hooks/claude_code/` covers Claude Code's built-in tools, which never pass through MCP. Other agent clients with hook or plugin systems need the same coverage.

**Task:** pick a client, add a hook under `hooks/<client>/` that runs the shared rule engine in `sensor/guardian_sensor/rules.py`, with tests modeled on `hooks/claude_code/tests/`.
EOF

issue "Add attack and benign test cases for an existing rule" "track:sensor,good first issue" <<'EOF'
Each rule in `sensor/guardian_sensor/rules.py` is tested in `sensor/tests/test_rules.py` with attacks that must be caught and ordinary work that must not be.

**Task:** pick a rule and add cases, especially benign ones that a careless rule would wrongly block. A rule that blocks real work gets turned off, and a rule that is turned off protects nobody.
EOF

issue "Design a deception-under-pressure scenario" "track:research,proposal" <<'EOF'
The registry starts with attacks on what agents do. The Deception and model behavior track looks at agents that mislead their users, hide what they did, or say one thing and do another, especially under pressure.

**Task:** write a scenario design as a research note in `docs/research/`: the setup, what pressure the agent is under, what honest and deceptive behavior look like, how to observe the difference harmlessly, and which models it could run on. Designs come before code here.
EOF

issue "Read START_HERE.md as a newcomer and fix what's confusing" "docs,good first issue" <<'EOF'
The best person to fix onboarding docs is someone using them for the first time.

**Task:** follow `START_HERE.md` from the top. Anything that was unclear, wrong or missing, fix it in a pull request.
EOF

echo "Done."
