#!/usr/bin/env python3
"""Guardian Protocol hook for Claude Code (prototype).

The MCP sensor only sees tools that come from MCP servers. A client's own tools
(shell, file reads and writes, web fetches) never pass through MCP. This hook closes
that gap by running the same rule engine inside the client.

Claude Code sends one JSON payload on stdin per tool call and reads JSON on stdout:

  PreToolUse   checks the call before it runs (rules.check_call) and can deny it
  PostToolUse  checks what the call returned (rules.check_output) and carries taint forward

Each hook is a separate process, so the session state (what has tainted this session,
how many times each call has been seen) is kept in a file per session id.

Fails open: any fault in the hook itself leaves the tool call alone.

Install (settings.json):

  "hooks": {
    "PreToolUse":  [{"matcher": "*", "hooks": [{"type": "command",
      "command": "python3 /path/to/hooks/claude_code/guardian_hook.py --config /path/to/guardian.json"}]}],
    "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command",
      "command": "python3 /path/to/hooks/claude_code/guardian_hook.py --config /path/to/guardian.json"}]}]
  }
"""
import argparse
import datetime
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "sensor"))
from guardian_sensor import rules  # noqa: E402

DEFAULT_CONFIG = {
    "mode": "block",                 # "block" or "monitor"
    "allowlist": [],                 # domains data may be sent to
    "state_dir": ".guardian/hook-state",
    "evidence_path": ".guardian/evidence.jsonl",
    "max_repeat": 10,
}

# Field names differ by tool and by client version, so read every spelling we have seen.
RESPONSE_KEYS = ("tool_response", "tool_result")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def harvest_text(value, depth=0):
    """Collect the human readable text anywhere in a tool's response.

    Recorded shapes differ per tool: Bash returns {"stdout", "stderr"}, Read returns
    {"file": {"content"}}, Write returns {"content"}, WebFetch returns {"result"}.
    Rather than name them all, walk the structure and keep the strings.
    """
    if depth > 6:
        return []
    if isinstance(value, str):
        return [value]
    out = []
    if isinstance(value, dict):
        for v in value.values():
            out.extend(harvest_text(v, depth + 1))
    elif isinstance(value, list):
        for v in value:
            out.extend(harvest_text(v, depth + 1))
    return out


def response_of(payload):
    for key in RESPONSE_KEYS:
        if key in payload:
            return payload[key]
    return None


class Store:
    """Session state, one file per session id, so taint survives between hook processes."""

    def __init__(self, cfg, session_id):
        safe = hashlib.sha256((session_id or "unknown").encode()).hexdigest()[:16]
        self.path = os.path.join(cfg["state_dir"], f"{safe}.json")

    def load(self):
        try:
            with open(self.path) as f:
                state = json.load(f)
        except (OSError, ValueError):
            state = {}
        state.setdefault("tainted_by", None)
        state.setdefault("counts", {})
        return state

    def save(self, state):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(state, f)


def record(cfg, pattern_ids, action, detail):
    rec = {"time": now(), "patterns": pattern_ids,
           "reasons": [rules.RULES[p] for p in pattern_ids],
           "action": action, "detail": detail,
           "sensor": "guardian-hook claude-code v0 (prototype)"}
    os.makedirs(os.path.dirname(cfg["evidence_path"]) or ".", exist_ok=True)
    with open(cfg["evidence_path"], "a") as f:
        f.write(json.dumps(rec) + "\n")
    sys.stderr.write(f"[guardian] {action.upper()} {', '.join(pattern_ids)}: {json.dumps(detail)}\n")


def handle_pre(payload, cfg, store):
    state = store.load()
    name = payload.get("tool_name") or ""
    args = payload.get("tool_input") or {}

    found = rules.check_call(name, args, state, cfg)
    store.save(state)
    if not found:
        return None

    ids = sorted({pid for pid, _ in found})
    detail = {"tool": name}
    for _, d in found:
        detail.update(d)

    blocking = cfg["mode"] == "block"
    record(cfg, ids, "blocked" if blocking else "flagged", detail)
    if not blocking:
        return None
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": (
            f"Blocked by Guardian ({', '.join(ids)}). "
            + " ".join(rules.RULES[p] for p in ids) + "."),
    }}


def handle_post(payload, cfg, store):
    state = store.load()
    name = payload.get("tool_name") or ""
    text = "\n".join(harvest_text(response_of(payload)))

    before = state.get("tainted_by")
    found = rules.check_output(name, text, state)
    store.save(state)

    for pid, d in found:
        record(cfg, [pid], "flagged", {"tool": name, **d})
    if state.get("tainted_by") and not before:
        record(cfg, ["GP-0001"], "flagged",
               {"tool": name, "reason": "tool output carried instructions, session is now tainted"})
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardian_hook")
    ap.add_argument("--config", default=None)
    a = ap.parse_args(argv)

    try:
        cfg = {**DEFAULT_CONFIG, **(json.load(open(a.config)) if a.config else {})}
        payload = json.loads(sys.stdin.read())
        store = Store(cfg, payload.get("session_id"))
        event = payload.get("hook_event_name")
        if event == "PreToolUse":
            out = handle_pre(payload, cfg, store)
        elif event == "PostToolUse":
            out = handle_post(payload, cfg, store)
        else:
            out = None
    except Exception as e:  # fail open: a fault in the hook never stops the agent
        sys.stderr.write(f"[guardian] hook fault, allowing the call: {e}\n")
        return 0

    if out:
        sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
