"""Declarative detection rules for the Guardian sensor and hooks (v0 prototype).

What the sensor looks for is data: the signatures in signatures.json, which this module
compiles. How signatures combine into a detection for each pattern is the fixed engine in
check_call and check_output below. Nothing in signatures.json can execute on the host.
docs/proposals/0001-declarative-rules.md moves the per-pattern conditions into data too. The MCP sensor
(guardian_sensor.sensor) and the client hooks (hooks/) share these checks.
"""
import base64
import hashlib
import json
import os
import re

# ---------- Signatures ----------
# The patterns live in signatures.json, as data. This module compiles them and runs fixed
# checks over them. Changing what the sensor looks for means changing that file, which the
# rule lint (scripts/lint_rules.py) and the rule gate (scripts/rule_gate.py) check.

SIGNATURES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures.json")

_FLAGS = {"i": re.I, "s": re.S}


def _flags(spec: str) -> int:
    out = 0
    for ch in spec or "":
        out |= _FLAGS[ch]
    return out


def _compile(entry: dict):
    return re.compile(entry["pattern"], _flags(entry.get("flags", "")))


def load_signatures(path: str = SIGNATURES_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


SIGNATURES = load_signatures()
_S = SIGNATURES

# ---------- Content checks ----------

INSTRUCTION_PATTERNS = [e["pattern"] for e in _S["instruction"]]
INSTRUCTION_RES = [_compile(e) for e in _S["instruction"]]
_BY_ID = {e["id"]: e for e in _S["instruction"]}
BIAS_PATTERNS = [_BY_ID[i]["pattern"] for i in _S["bias"]]
BIAS_RES = [re.compile(_BY_ID[i]["pattern"], re.I) for i in _S["bias"]]

SECRET_PATTERNS = [e["pattern"] for e in _S["secret"]]
SECRET_RES = [_compile(e) for e in _S["secret"]]
SYSTEM_PROMPT_CANARY = _compile(_S["system_prompt_canary"])

# Hidden or obfuscated content (GP-0006)
ZERO_WIDTH = _compile(_S["hidden"]["zero_width"])
TAG_CHARS = _compile(_S["hidden"]["tag_chars"])
HIDDEN_HTML = _compile(_S["hidden"]["hidden_html"])
BASE64_BLOB = _compile(_S["hidden"]["base64_blob"])

# ---------- Action classes ----------

DESTINATION_KEYS = set(_S["destination_keys"])
PATH_KEYS = set(_S["path_keys"])
DESTRUCTIVE_TOOL = _compile(_S["tool_classes"]["destructive"])
MEMORY_TOOL = _compile(_S["tool_classes"]["memory"])
AGENT_TOOL = _compile(_S["tool_classes"]["agent"])
WRITE_TOOL = _compile(_S["tool_classes"]["write"])

SENSITIVE_PATHS = _compile(_S["paths"]["sensitive"])
# Files that configure agents: writing instructions into them persists an attack (GP-0009)
AGENT_CONFIG_PATHS = _compile(_S["paths"]["agent_config"])

DESTRUCTIVE_SHELL = _compile(_S["shell"]["destructive"])
EGRESS_SHELL = _compile(_S["shell"]["egress"])
URL_RE = _compile(_S["url"])


def decode_hidden(text: str) -> str:
    """Reveal text hidden in Unicode tag characters (invisible ASCII smuggling)."""
    return "".join(chr(ord(c) - 0xE0000) for c in TAG_CHARS.findall(text or ""))


def has_instructions(text: str, raw: bool = False) -> bool:
    text = text or ""
    if not raw:
        text = ZERO_WIDTH.sub("", text + " " + decode_hidden(text))
    return any(r.search(text) for r in INSTRUCTION_RES)


def hidden_content(text: str) -> list:
    """Reasons the text contains content a human reader would not see."""
    text = text or ""
    reasons = []
    if TAG_CHARS.search(text):
        reasons.append("invisible Unicode tag characters")
    if len(ZERO_WIDTH.findall(text)) >= 3 and has_instructions(ZERO_WIDTH.sub("", text), raw=True):
        reasons.append("zero-width characters splitting instructions")
    if HIDDEN_HTML.search(text) and has_instructions(text, raw=True):
        reasons.append("hidden HTML carrying instructions")
    for blob in BASE64_BLOB.findall(text)[:5]:
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8")
        except Exception:
            continue
        if has_instructions(decoded, raw=True):
            reasons.append("base64-encoded instructions")
            break
    return reasons


def find_secrets(text: str):
    return [r.pattern for r in SECRET_RES if r.search(text or "")]


def destinations(args) -> list:
    """Collect values that look like where data is being sent."""
    out = []
    if isinstance(args, dict):
        for k, v in args.items():
            if k.lower() in DESTINATION_KEYS:
                out.extend(v if isinstance(v, list) else [v])
            elif isinstance(v, (dict, list)):
                out.extend(destinations(v))
    elif isinstance(args, list):
        for v in args:
            out.extend(destinations(v))
    return [str(x) for x in out if x]


def domain_of(dest: str) -> str:
    dest = dest.strip().lower()
    if "@" in dest and "://" not in dest:
        return dest.rsplit("@", 1)[-1]
    m = re.match(r"^[a-z]+://([^/:?#]+)", dest)
    return m.group(1) if m else dest


def allowed(domain: str, allowlist) -> bool:
    return any(domain == a or domain.endswith("." + a) for a in allowlist)


def paths_in(args) -> list:
    out = []
    if isinstance(args, dict):
        for k, v in args.items():
            if k.lower() in PATH_KEYS and isinstance(v, str):
                out.append(v)
            elif isinstance(v, (dict, list)):
                out.extend(paths_in(v))
    return out


def text_of(args) -> str:
    return args if isinstance(args, str) else json.dumps(args, ensure_ascii=False)


def tool_fingerprint(tool: dict) -> str:
    canonical = json.dumps({k: tool.get(k) for k in ("name", "description", "inputSchema")}, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


RULES = {
    "GP-0001": "Unrequested send to a destination outside the allow-list after a tool result carried instructions",
    "GP-0002": "Outbound tool arguments contain a secret or canary token",
    "GP-0003": "Tool definition changed after approval, or contains instructions for the agent",
    "GP-0004": "Write to the agent's long-term memory carrying instructions from untrusted content",
    "GP-0005": "Destructive action requested after the agent read untrusted content with instructions",
    "GP-0006": "Tool output hides content from human readers (invisible characters, hidden HTML, encoded instructions)",
    "GP-0007": "Credential file read after the agent read untrusted content with instructions",
    "GP-0008": "Instructions from untrusted content passed on to another agent",
    "GP-0009": "Instructions from untrusted content written into a shared file or agent configuration",
    "GP-0010": "Untrusted content tries to steer which sources the agent trusts or recommends",
    "GP-0011": "Runaway tool use: the same call repeated beyond the session budget",
    "GP-0012": "Outbound content contains the agent's own system prompt canary",
}


def check_call(name: str, args, state: dict, cfg: dict) -> list:
    """Checks for one tool call before it runs. Returns a list of (pattern_id, detail) hits.

    state: {"tainted_by": str|None, "counts": {signature: n}}
    cfg:   {"allowlist": [...], "max_repeat": int}
    """
    hits = []
    blob = text_of(args)
    tainted = state.get("tainted_by")

    secrets = find_secrets(blob)
    if SYSTEM_PROMPT_CANARY.search(blob):
        hits.append(("GP-0012", {"reason": "system prompt canary in outbound arguments"}))
    elif secrets:
        hits.append(("GP-0002", {"secret_patterns": len(secrets)}))

    outside = [d for d in destinations(args) if not allowed(domain_of(d), cfg.get("allowlist", []))]
    if tainted and outside and not AGENT_TOOL.search(name or ""):
        hits.append(("GP-0001", {"destinations": sorted({domain_of(d) for d in outside}), "tainted_by": tainted}))

    if tainted and DESTRUCTIVE_TOOL.search(name or ""):
        hits.append(("GP-0005", {"tool": name, "tainted_by": tainted}))

    if tainted and MEMORY_TOOL.search(name or "") and (has_instructions(blob) or URL_RE.search(blob)):
        hits.append(("GP-0004", {"tool": name, "tainted_by": tainted}))

    if tainted and any(SENSITIVE_PATHS.search(p) for p in paths_in(args)):
        hits.append(("GP-0007", {"paths": [p for p in paths_in(args) if SENSITIVE_PATHS.search(p)], "tainted_by": tainted}))

    if tainted and AGENT_TOOL.search(name or "") and has_instructions(blob):
        hits.append(("GP-0008", {"tool": name, "tainted_by": tainted}))

    if tainted and WRITE_TOOL.search(name or "") and not MEMORY_TOOL.search(name or ""):
        cfg_paths = [p for p in paths_in(args) if AGENT_CONFIG_PATHS.search(p)]
        if cfg_paths or has_instructions(blob):
            hits.append(("GP-0009", {"tool": name, "paths": paths_in(args), "tainted_by": tainted}))

    sig = hashlib.sha256(f"{name}|{blob}".encode()).hexdigest()[:16]
    counts = state.setdefault("counts", {})
    counts[sig] = counts.get(sig, 0) + 1
    if counts[sig] > cfg.get("max_repeat", 10):
        hits.append(("GP-0011", {"tool": name, "repeats": counts[sig]}))
    return hits


def check_output(source: str, text: str, state: dict) -> list:
    """Checks on a tool's output after it runs. Updates taint. Returns (pattern_id, detail) hits (flags)."""
    hits = []
    hidden = hidden_content(text)
    if hidden:
        hits.append(("GP-0006", {"source": source, "reasons": hidden}))
    if any(r.search(text or "") for r in BIAS_RES):
        hits.append(("GP-0010", {"source": source}))
    if hidden or has_instructions(text):
        state["tainted_by"] = state.get("tainted_by") or source
    return hits
