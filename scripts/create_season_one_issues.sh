#!/usr/bin/env bash
# Create the Season 1 Map issues: one per MITRE ATLAS technique that happens while an
# agent is running. Run from the repository root:
#
#   bash scripts/create_season_one_issues.sh
#
# Safe to run more than once. It reads every existing issue title first and skips any
# technique that already has one, so a half finished run can simply be run again.
set -euo pipefail

REPO="${1:-guardianprotocol-ai/registry}"
command -v gh >/dev/null || { echo "Install the GitHub CLI first: https://cli.github.com"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Sign in first: gh auth login"; exit 1; }

# Every label this script uses, created up front so the script does not depend on any
# other having run first. `--force` makes this safe to repeat.
ensure_labels() {
  for spec in "$@"; do
    name="${spec%%|*}"; rest="${spec#*|}"; color="${rest%%|*}"; desc="${rest#*|}"
    gh label create "$name" --color "$color" --description "$desc" --repo "$REPO" --force >/dev/null
  done
}

ensure_labels "season-1|0e8a16|Season 1: Oct 5 to Oct 29, 2026" "track:patterns|1d76db|Attack patterns" "track:coverage|1d76db|MITRE ATLAS and OWASP coverage" "good first issue|7057ff|Good for newcomers"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"


# Every title already in the repository, open or closed, so re-running creates nothing twice.
echo "Reading existing issues..."
existing="$(gh issue list --repo "$REPO" --state all --limit 1000 --json title --jq '.[].title')"

created=0
skipped=0
while IFS= read -r line; do
  title="$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["title"])')"
  if printf '%s\n' "$existing" | grep -Fxq "$title"; then
    skipped=$((skipped + 1))
    continue
  fi
  labels="$(printf '%s' "$line" | python3 -c 'import json,sys; print(",".join(json.loads(sys.stdin.read())["labels"]))')"
  printf '%s' "$line" \
    | python3 -c 'import json,sys; sys.stdout.write(json.loads(sys.stdin.read())["body"])' \
    | gh issue create --repo "$REPO" --title "$title" --label "$labels" --body-file - >/dev/null
  created=$((created + 1))
  echo "created: $title"
done < <(python3 "$HERE/season_one_issues.py" --jsonl)

echo
echo "Created $created, skipped $skipped that already existed."
echo "Next: add them to the Season 1 board. See docs/MAINTAINING.md."
