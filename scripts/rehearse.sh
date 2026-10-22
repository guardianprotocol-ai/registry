#!/usr/bin/env bash
# A rehearsal: many nodes, one published agenda, both arms, then the aggregate.
#
# Directories on one machine prove the logic. They do not prove the deployment, because they
# share an operating system, a clock, a filesystem and a Python, and because a person invokes
# each poll by hand instead of a timer firing. Every defect found late in this work came from
# the gap between those two things: an unwritable home directory, a nested path, a log that
# grew without bound, two polls running at once.
#
# So this runs each node as its own container with its own filesystem, reaching a shared
# publish point over a real network, polling on its own loop. Closer to a participant's
# machine than a directory, and cheaper than asking thirty people to find out for us.
#
#   scripts/rehearse.sh            eight nodes
#   NODES=20 scripts/rehearse.sh   twenty
#
# Needs docker or podman. Nothing else, and nothing is installed on the host.
set -euo pipefail

NODES="${NODES:-8}"
# Under the home directory, not /tmp. A container runtime on macOS shares the home directory
# with the host and often does not share /tmp, so a node writing to /tmp writes to its own
# private view of it and the host sees an empty directory. The first run of this looked like
# eight nodes doing nothing; they had each run perfectly and written somewhere invisible.
WORK="${WORK:-$HOME/.guardian-rehearsal}"
PORT="${PORT:-8761}"
IMAGE="${IMAGE:-python:3.9-slim}"
NET="guardian-rehearsal"

RUNTIME=""
for candidate in docker podman; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" info >/dev/null 2>&1; then
    RUNTIME="$candidate"
    break
  fi
done
if [ -z "$RUNTIME" ]; then
  echo "Needs docker or podman, with the daemon running. Neither is usable here." >&2
  echo "The rest of the rehearsal is a script, so run it wherever one of them is." >&2
  exit 1
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# A container runtime on macOS shares the home directory and usually not much else. A
# repository outside it mounts as an empty directory, and the failure is an OCI runtime error
# about a read-only filesystem that says nothing about the real cause. Checked here so the
# message is about the cause.
case "$REPO" in
  "$HOME"/*) ;;
  *)
    echo "This repository is at $REPO, outside $HOME." >&2
    echo "A container runtime here shares the home directory and not that path, so every" >&2
    echo "node would mount an empty directory and fail with an unhelpful runtime error." >&2
    echo "Run the rehearsal from a clone under your home directory." >&2
    exit 1
    ;;
esac
echo "runtime:  $RUNTIME"
echo "image:    $IMAGE   (python 3.9, the oldest version supported)"
echo "nodes:    $NODES"
echo "repo:     $REPO"
echo

rm -rf "$WORK"
mkdir -p "$WORK/publish/season1" "$WORK/sightings"

cleanup() {
  echo
  echo "cleaning up"
  for i in $(seq 1 "$NODES"); do
    $RUNTIME rm -f "guardian-node-$i" >/dev/null 2>&1 || true
  done
  $RUNTIME rm -f guardian-publish >/dev/null 2>&1 || true
  $RUNTIME network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

$RUNTIME network create "$NET" >/dev/null 2>&1 || true

# The publish point. A static file server and nothing else, which is all this ever needs in
# production either: no application, no database, no credentials, nothing to compromise
# beyond the ability to schedule an exercise a participant already consented to.
$RUNTIME run -d --name guardian-publish --network "$NET" \
  -v "$WORK/publish:/srv:ro" -w /srv "$IMAGE" \
  python3 -m http.server 80 >/dev/null
echo "publish point up"

start_node() {
  local n="$1" arm="$2"
  local data="$WORK/node-$n"
  mkdir -p "$data"
  local args
  if [ "$arm" = offline ]; then
    args="--offline --every-hours 0"
  else
    args="--base http://guardian-publish/season1"
  fi
  # Its own filesystem, its own clock reading, its own Python process, reaching the publish
  # point over a real network. A loop stands in for a service timer: systemd inside a
  # container is a fight that teaches nothing about this protocol.
  $RUNTIME run -d --name "guardian-node-$n" --network "$NET" \
    -v "$REPO:/repo:ro" -v "$data:/data" -w /repo/sensor \
    -e PYTHONPATH=/repo/sensor -e HOME=/data "$IMAGE" \
    sh -c "while true; do python3 -m guardian_sensor agenda $args \
             --org node-$n --log /data/agenda.jsonl --dir /data/drill \
             >> /data/poll.log 2>&1; sleep 5; done" >/dev/null
}

wait_for() {
  local pattern="$1" label="$2" limit="${3:-60}"
  local waited=0
  while [ "$waited" -lt "$limit" ]; do
    local seen
    seen=$(grep -l "$pattern" "$WORK"/node-*/agenda.jsonl 2>/dev/null | wc -l | tr -d ' ')
    if [ "$seen" -ge "$NODES" ]; then
      echo "  all $NODES nodes: $label"
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  echo "  only $(grep -l "$pattern" "$WORK"/node-*/agenda.jsonl 2>/dev/null | wc -l | tr -d ' ') of $NODES nodes reached: $label" >&2
  return 1
}

echo
echo "ARM 1: offline. nothing is published and nothing is fetched."
for i in $(seq 1 "$NODES"); do start_node "$i" offline; done
wait_for '"offline' "ran the local exercise" || true
for i in $(seq 1 "$NODES"); do $RUNTIME rm -f "guardian-node-$i" >/dev/null 2>&1; done

echo
echo "ARM 2: networked. the same nodes, now polling one agenda."
for i in $(seq 1 "$NODES"); do start_node "$i" networked; done
sleep 8
cat > "$WORK/publish/season1/agenda.json" <<JSON
{"exercise_id": "rehearsal-networked",
 "run_after": "2020-01-01T00:00:00Z",
 "settings": {"mode": "block", "respond": true},
 "note": "Rehearsal. Nothing leaves your machine."}
JSON
echo "  agenda published. every node now polls it at once."
wait_for 'rehearsal-networked' "picked it up and ran it" || true

# Everything below reports on data. If there is none, every check passes vacuously and the
# rehearsal congratulates itself on having proved nothing, which is exactly the failure the
# drill refuses to make. The first version of this script printed "every node ran it exactly
# once" and "nothing leaked" after eight nodes wrote nothing at all.
ran_count=$(grep -l 'rehearsal-networked' "$WORK"/node-*/agenda.jsonl 2>/dev/null | wc -l | tr -d ' ')
if [ "$ran_count" -eq 0 ]; then
  echo
  echo "No node produced anything, so nothing below would mean anything." >&2
  echo "Every check after this point would pass on an empty set." >&2
  echo
  echo "What a node logged:" >&2
  for i in $(seq 1 "$NODES"); do
    if [ -s "$WORK/node-$i/poll.log" ]; then
      echo "  node-$i:" >&2
      sed 's/^/    /' "$WORK/node-$i/poll.log" | tail -6 >&2
      break
    fi
  done
  echo "  (nothing in any poll.log)" >&2
  echo >&2
  echo "The usual cause is the work directory not being shared with the host. Containers" >&2
  echo "then write to their own view of it and this sees an empty directory." >&2
  exit 1
fi
echo
echo "$ran_count of $NODES nodes produced a record"

echo
echo "checking nothing ran twice, which a shared agenda makes easy to get wrong"
twice=0
for i in $(seq 1 "$NODES"); do
  runs=$(grep -c '"rehearsal-networked".*"ran"' "$WORK/node-$i/agenda.jsonl" 2>/dev/null || echo 0)
  [ "$runs" -gt 1 ] && { echo "  node-$i ran it $runs times"; twice=1; }
done
[ "$twice" -eq 0 ] && echo "  every node that ran it ran it exactly once"

echo
echo "each node reports, which is a separate and deliberate act"
for i in $(seq 1 "$NODES"); do
  mkdir -p "$WORK/sightings/node-$i"
  $RUNTIME run --rm --network "$NET" \
    -v "$REPO:/repo:ro" -v "$WORK/node-$i:/data" \
    -v "$WORK/sightings/node-$i:/out" -w /repo/sensor \
    -e PYTHONPATH=/repo/sensor "$IMAGE" \
    python3 -m guardian_sensor report --org "node-$i" \
      --evidence /data/drill/evidence.jsonl \
      --out "/out/sightings.json" >/dev/null 2>&1 || echo "  node-$i produced nothing"
done
reported=$(find "$WORK/sightings" -name 'sightings.json' | wc -l | tr -d ' ')
echo "  $reported of $NODES reported"
if [ "$reported" -eq 0 ]; then
  echo "  Nothing was reported, so the aggregate below would be empty and the leak check" >&2
  echo "  would pass on nothing." >&2
  exit 1
fi

echo
echo "the exchange, over $NODES organizations"
python3 "$REPO/scripts/aggregate_sightings.py" "$WORK/sightings" --source drill

echo
echo "and with two organizations, where a total would be traceable"
mkdir -p "$WORK/two"
cp -r "$WORK/sightings/node-1" "$WORK/sightings/node-2" "$WORK/two/" 2>/dev/null || true
python3 "$REPO/scripts/aggregate_sightings.py" "$WORK/two" --source drill

echo
echo "nothing sensitive left any node"
if grep -rl -e CANARY -e notes.txt -e send_message -e registry.test "$WORK/sightings" 2>/dev/null; then
  echo "  SOMETHING LEAKED, shown above" >&2
  exit 1
fi
echo "  no tool names, paths, canaries or destinations across $reported sightings files"
echo
echo "rehearsal complete. state is in $WORK"
