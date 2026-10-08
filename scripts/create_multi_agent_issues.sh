#!/usr/bin/env bash
# Create the multi-agent issues. Run once, from the repository root:
#
#   bash scripts/create_multi_agent_issues.sh
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

ensure_labels "track:multi-agent|b60205|Attacks that need more than one agent" "track:scanner|1d76db|Scanner, reference agents and measurement" "track:governance|5319e7|Policy, process and project decisions" "help wanted|008672|Extra attention is wanted" "proposal|d4c5f9|A written proposal for the group to decide"


issue() {  # title, labels, body on stdin
  gh issue create --repo "$REPO" --title "$1" --label "$2" --body-file - >/dev/null
  echo "created: $1"
}

runnable() {  # pattern id, title, what the scenario has to show
  cat <<EOF | issue "Make $1 runnable: $2" "track:multi-agent,help wanted"
$1 validates but does not run. Give it a scenario so the scan can measure it, the way GP-0008 has one.

**What exists already.** The lab server (\`sensor/tests/fake_server.py\`) has \`fetch_brief\`, \`send_to_agent\` and \`read_agent_messages\`, which is enough for two agents to pass work between them. \`scanner/guardian_scanner/scenarios.py\` shows the shape: a chain for the vulnerable pair, a \`decline\` for the hardened pair, and a \`succeeded\` check that reads what actually travelled rather than what an agent claimed.

**What this scenario has to show.** $3

**Rules.** Canary tokens and reserved \`.test\` destinations only, like every other pattern. The hardened pair should still do the legitimate part of the task: refusing to work is not the same as resisting an attack, and a scenario where it just stops measures nothing.

**Done when** \`python3 -m guardian_scanner list\` says $1 is runnable, the vulnerable pair is exploited, the hardened pair is not, and \`python3 check.py\` passes.
EOF
}

runnable "GP-0013" "instructions that copy themselves between agents" \
"An instruction reaches an agent that never read the document it came from. Count the agents holding the token after one pass. The lab needs a third agent, or a loop through the two it has."

runnable "GP-0014" "a worker agent used to do what the caller cannot" \
"One agent performs an action that the requesting agent's own permissions refuse. The lab needs per-agent permissions, which it does not have yet, so this one starts with a small change to the lab server."

runnable "GP-0015" "a message claiming to come from a trusted agent" \
"A message names a sender it is not, and the receiver acts on the claim. The lab's \\\`send_to_agent\\\` lets any caller set \\\`to\\\`; it needs a sender field that the caller also controls, which is exactly the weakness being modelled."

runnable "GP-0016" "instructions written into shared agent memory" \
"An agent in a fresh session acts on an instruction it found in a shared store, having never seen the original document. The lab needs a shared notes tool that persists between sessions."

runnable "GP-0017" "two agents triggering each other without progress" \
"A pair exchanges messages past a hop ceiling with nothing completed. The test must stop itself at a fixed ceiling rather than relying on anything else to stop it."

runnable "GP-0018" "one agent swaying a group decision" \
"A combined result changes because one participant read planted content, while each individual answer still looks ordinary. The lab needs three agents and a tool that records each answer."

issue "Extend the two-agent lab for the next pattern" "track:multi-agent,help wanted" <<'EOF'
The lab can hand work from one agent to another and that is all. Each pattern from GP-0013 to GP-0018 needs a little more, and the six issues above each name what.

Rather than six separate extensions, it is worth deciding once what the lab should look like: per-agent permissions, a sender field on messages, a shared store that persists between sessions, and more than two agents. Those four cover all six patterns.

**This issue is for the design**, not for all the code. Propose the shape in a comment, then the pattern issues can be picked up in parallel without conflicting.

Keep it small. The lab is a test fixture, not a multi-agent framework, and the moment it starts to look like one it will stop being something a contributor can read in a sitting.
EOF

issue "Proposal 0003: seeing traffic between agents" "proposal,track:multi-agent,track:governance" <<'EOF'
Discussion and decision for [docs/proposals/0003-agent-to-agent-coverage.md](../blob/main/docs/proposals/0003-agent-to-agent-coverage.md).

The sensor only sees agent-to-agent traffic that passes through MCP. Six of the eighteen patterns assume something is watching the path between agents, and for most real deployments nothing is.

Three options in the proposal: an A2A transport for the sensor, hooks in multi-agent frameworks, and message signing. None of them gives everything the patterns need, which the proposal says plainly.

**The one thing worth deciding first** is the corpus format: an optional `agent` on each event, and `from` and `to` on a message event. It is cheap, additive, needed by all three options, and without it the six new patterns cannot carry attack or benign cases at all.

Open for at least 7 days, then decided by a majority of maintainers (GOVERNANCE.md). The open questions at the end of the proposal are the useful place to start, particularly whether any member company runs A2A today, which would make one option testable rather than theoretical.
EOF
