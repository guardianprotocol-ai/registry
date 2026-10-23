#!/usr/bin/env bash
# The whole loop, on one machine, with every step visible.
#
#   one node detects  ->  reports  ->  three clear the threshold  ->  an alert is
#   published  ->  every other node reads it on its next poll
#
# Each arrow is a thing that happens, not a thing described. The point of running it this way
# is that the steps can be timed and the intermediate files inspected, which is what the
# paper needs and what a diagram cannot give.
#
#   scripts/demonstrate_loop.sh
set -euo pipefail

WORK="${WORK:-$HOME/.guardian-loop}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-8791}"
export PYTHONPATH="$REPO/sensor"

rm -rf "$WORK"
mkdir -p "$WORK/publish/season1" "$WORK/sightings"
( cd "$WORK/publish" && python3 -m http.server "$PORT" >/dev/null 2>&1 & echo $! > "$WORK/server.pid" )
sleep 1
trap 'kill "$(cat "$WORK/server.pid")" 2>/dev/null || true' EXIT
BASE="http://localhost:$PORT/season1"

echo "STEP 1  three nodes run the exercise. each detects locally."
for org in acme-labs north-river kestrel; do
  mkdir -p "$WORK/$org"
  python3 -m guardian_sensor drill --org "$org" --dir "$WORK/$org/drill" --no-next-steps \
    >"$WORK/$org/drill.log" 2>&1
  echo "  $org: $(grep -o '[0-9] of 3 exercises caught' "$WORK/$org/drill.log")"
done

echo
echo "STEP 2  each sends counts. nothing else leaves a machine."
for org in acme-labs north-river kestrel; do
  mkdir -p "$WORK/sightings/$org"
  python3 -m guardian_sensor report --org "$org" \
    --evidence "$WORK/$org/drill/evidence.jsonl" \
    --out "$WORK/sightings/$org/sightings.json" >/dev/null
  echo "  $org: $(python3 -c "import json;print(len(json.load(open('$WORK/sightings/$org/sightings.json'))['sightings']))") entries"
done

echo
echo "STEP 3  the aggregate. a total appears only above three organizations."
python3 "$REPO/scripts/aggregate_sightings.py" "$WORK/sightings" --source drill | sed 's/^/  /'

echo
echo "STEP 4  alerts published, as a static file."
python3 "$REPO/scripts/publish_alerts.py" "$WORK/sightings" \
  --out "$WORK/publish/season1/alerts.json" --source drill | sed 's/^/  /'

echo
echo "STEP 5  a fourth node, which saw nothing, polls and is told."
mkdir -p "$WORK/orchid"
python3 -m guardian_sensor agenda --base "$BASE" --org orchid \
  --log "$WORK/orchid/agenda.jsonl" --dir "$WORK/orchid/drill" 2>&1 | sed 's/^/  /'

echo
echo "STEP 6  polling again says nothing, because it already knows."
python3 -m guardian_sensor agenda --base "$BASE" --org orchid \
  --log "$WORK/orchid/agenda.jsonl" --dir "$WORK/orchid/drill" 2>&1 | sed 's/^/  /'
echo "  (silence above is correct)"

echo
echo "what the fourth node learned, and what it did not:"
python3 - <<PY
import json, os
seen = json.load(open("$WORK/orchid/alerts-seen.json"))
print("  patterns it was told about:", ", ".join(sorted(seen)))
blob = open("$WORK/publish/season1/alerts.json").read()
for leak in ("acme-labs", "north-river", "kestrel", "notes.txt", "CANARY", "send_message"):
    print("  %-14s in the published alerts: %s" % (leak, leak in blob))
PY
