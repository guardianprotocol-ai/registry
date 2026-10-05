#!/usr/bin/env bash
# Create the first round of measurement issues for the attack matrix. Run once, from the
# repository root:
#
#   bash scripts/create_matrix_issues.sh
#
# Running it twice creates duplicates.
set -euo pipefail

REPO="${1:-guardianprotocol-ai/registry}"
command -v gh >/dev/null || { echo "Install the GitHub CLI first: https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Sign in first: gh auth login"; exit 1; }

issue() {  # title, labels, body on stdin
  gh issue create --repo "$REPO" --title "$1" --label "$2" --body-file - >/dev/null
  echo "created: $1"
}

# Every measurement issue says the same thing about how to do it, so the instructions live
# here once and each issue adds only what is specific to its target.
how_to() {
  cat <<'EOF'

## How to do it

```bash
cd scanner
python3 -m guardian_scanner list                       # what can be run today
python3 -m guardian_scanner run --target TARGET --repeat 10 --record ../results
python3 -m guardian_scanner run --target TARGET --repeat 10 --sensor --record ../results
```

- **At least 10 runs** per cell. Five is the floor the checks allow and the interval is
  roughly 0 to 0.43 at that size, which says almost nothing.
- **Sensor off and on**, so the two numbers can be compared.
- Open each recorded file and replace the placeholders: your name in `credits`, the real
  `environment`, and the model and version if the harness tells you.
- `python3 check.py` before you push. The checks recompute every rate and interval.
- Open one pull request with the result files. `docs/MATRIX.md` is generated, so regenerate
  it with `python3 scripts/build_matrix.py` and include it.

Read [results/README.md](../blob/main/results/README.md) first, and the publishing rules in
[SECURITY.md](../blob/main/SECURITY.md). A result is a statement about one version on one
date, never about a vendor in general.
EOF
}

target_issue() {  # title, what, extra
  {
    printf '%s\n' "$2"
    printf '%s\n' "$3"
    how_to
  } | issue "$1" "track:scanner,help wanted"
}

target_issue "Measure the runnable patterns against Claude Code" \
"Claude Code is the only target the scanner drives today, and the numbers in the matrix come from five runs on 2.1.274 on one day. Repeat them at ten or more runs, on the current version, and record the result files." \
"The harness does not report which model served the session, so leave \`model\` as \`unrecorded\` rather than guessing. Say the Claude Code version in \`harness_version\`."

target_issue "Measure the runnable patterns against Cursor" \
"Cursor is a second agent harness over the same kind of tool surface. Nothing in the matrix measures it yet." \
"The scanner has no Cursor target, so this needs either a new target in \`scanner/guardian_scanner/targets.py\` or a run by hand. If you run it by hand, say exactly how in the \`environment\` field: the checks require that for any pattern the scanner cannot drive itself."

target_issue "Measure the runnable patterns against Codex CLI" \
"A third harness, and a different vendor, which is the point: the matrix is only useful if it compares." \
"Same as Cursor: either add a target or run it by hand and describe it in \`environment\`."

target_issue "Measure the runnable patterns against Gemini CLI" \
"A fourth harness over a different model family." \
"Same as Cursor: either add a target or run it by hand and describe it in \`environment\`."

target_issue "Measure an open-weight model through Ollama" \
"Every target measured so far is a closed harness that will not say which model answered. An open-weight model through Ollama is the first target where \`model\` and \`model_version\` can be recorded exactly, which makes it the most reproducible row the matrix will have." \
"Pick a model that is easy for others to pull, record the exact tag in \`model_version\`, and say the Ollama version in \`harness_version\`. This is the best first contribution on this track for someone who wants a result nobody can argue with."

target_issue "Measure your own agent" \
"If you run an agent in production, the most useful row in the matrix is yours. You do not need to name your employer: \`credits\` can be a person with no organization." \
"Record what you can and leave the rest as \`unrecorded\` with an honest \`environment\`. If the result is severe and not already public for that model or harness, read the publishing rules in [SECURITY.md](../blob/main/SECURITY.md) and report it privately first. Nobody has ever regretted that order."

issue "Attack matrix: what do we publish first?" "proposal,track:scanner,track:governance" <<'EOF'
The matrix can hold measurements long before the group agrees which of them belong in a public v0.1 release on November 20.

Questions for the working group:

- Which targets must be measured for the first public set to be worth publishing at all?
- What is the minimum run count for a published row? The checks enforce 5; 10 is the request in every measurement issue. Should v0.1 require more?
- Do we publish a row for a harness measured only once, or wait for a second independent measurement of the same target?
- Who checks a result before it is merged, and does that need to be someone other than the person who measured it?
- Does a severe result pause publication of the whole set, or only its own row?

The publishing rules already in [SECURITY.md](../blob/main/SECURITY.md) are the floor, not the answer: they say when a result *may* be published, not which ones we *choose* to put our name behind.

Open for at least 7 days, then decided by a majority of maintainers (GOVERNANCE.md).
EOF

# ---------------------------------------------------------------------------
# The research group. Two decisions for the kickoff.
# ---------------------------------------------------------------------------

issue "Name the research group" "proposal,track:governance" <<'EOF'
The group needs a name before the first publication, because the byline depends on it.

**Proposed:** Guardian Protocol Research Group. Chosen because the group's identity is research led: it sets the research agenda and approves publications.

**Alternative:** Guardian Protocol Working Group.

Until this is decided, every document says the name is proposed. See [docs/RESEARCH.md](../blob/main/docs/RESEARCH.md) and the research group section of [GOVERNANCE.md](../blob/main/GOVERNANCE.md).

**One constraint, not up for a vote.** Y Combinator's name does not go in the group's name, or in any public byline, without Y Combinator's written permission. The same applies to any member company's name. We can describe ourselves accurately as a working group of YC founders and researchers; we cannot imply an endorsement nobody has given us.

Open for at least 7 days, then decided by a majority of maintainers (GOVERNANCE.md).
EOF

issue "Adopt the research and authorship policy" "proposal,track:governance" <<'EOF'
[docs/RESEARCH.md](../blob/main/docs/RESEARCH.md) is written and in the repository, but it has not been agreed by anyone except its author. This issue is where the group adopts it or changes it.

What it currently says:

- **Byline:** by the Guardian Protocol Research Group, then the full author list with affiliations.
- **Author:** made a substantive contribution, approved the final draft, and is accountable for it. Contributing a measurement a study relies on counts. Everyone else is acknowledged by name.
- **Order:** alphabetical by last name unless the authors agree otherwise in writing.
- **Conflicts:** every author discloses affiliations, including companies building on the protocol. Measuring an author's employer's product is stated next to the result.
- **Approval:** every author approves the final version and checks with their own employer first.
- **Results:** only numbers that pass the matrix checks, with run counts and intervals. The disclosure rules in SECURITY.md come first.
- **Where:** the project site and arXiv first, venues after. Every publication names the registry commit its data came from.
- **Licensing:** text CC BY 4.0, code and data Apache 2.0.

Worth arguing about before the first paper rather than during it: whether alphabetical order is right for a measurement study where contributions are very uneven, and whether a measurement contributor should be an author by default or by invitation.

Open for at least 7 days, then decided by a majority of maintainers (GOVERNANCE.md).
EOF
