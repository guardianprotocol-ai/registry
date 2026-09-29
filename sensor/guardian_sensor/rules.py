"""Declarative detection rules for the Guardian sensor and hooks (v0 prototype).

Rules are data, never code: each rule names a registry pattern and the checks a fixed
engine runs. Nothing in a rule can execute on the host. The MCP sensor
(guardian_sensor.sensor) and the client hooks (hooks/) share these checks.
"""
import base64
import hashlib
import json
import re

# ---------- Content checks ----------

INSTRUCTION_PATTERNS = [
    r"\b(assistant|ai|agent)\s*[:,]\s*\w+",
    r"\bignore (all |any )?(previous|prior|above|earlier) (instructions|rules)\b",
    r"\bdo not (mention|tell|reveal|inform)\b",
    r"\b(before|after) (you )?(summariz|answer|respond|reply)\w*\b.{0,80}\b(send|email|post|upload|forward|delete|remember|write|tell)\b",
    r"\b(send|email|post|upload|forward) (its|the|all|full|entire|your)\b.{0,40}\b(to|contents)\b",
    r"\balways include\b.{0,60}\b(file|contents|notes|token|key|password|instructions)\b",
    r"\b(remember|memorize|store) (that|this|permanently)\b",
    r"\b(treat|consider) \S+ as (a |the )?(trusted|authoritative|official)\b",
    r"\b(recommend|prefer|promote) \S+ (first|above|over|exclusively)\b",
    r"\b(tell|instruct|ask|forward this to) (every|all|other|the next) (agent|assistant)s?\b",
    r"\b(delete|remove|wipe|purge|drop) (all|every|the entire)\b",
    r"\b(your|the) (system prompt|hidden instructions|initial instructions)\b",
    r"\bcall \w+ (again|repeatedly|\d+ times)\b",
]

SECRET_PATTERNS = [
    r"GP\d{4}-CANARY-[0-9a-f]{4}",            # registry canary tokens
    r"AKIA[0-9A-Z]{16}",                        # AWS access key id
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",      # private keys
    r"\bsk-[A-Za-z0-9_-]{20,}\b",               # common API key shape
    r"\bghp_[A-Za-z0-9]{36}\b",                 # GitHub token
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",        # Slack token
]
BIAS_PATTERNS = INSTRUCTION_PATTERNS[7:9]           # "treat X as trusted", "recommend X first" (GP-0010)
SYSTEM_PROMPT_CANARY = re.compile(r"GP0012-CANARY-[0-9a-f]{4}")

# Hidden or obfuscated content (GP-0006)
ZERO_WIDTH = re.compile(r"[​-‏⁠-⁤﻿]")
TAG_CHARS = re.compile(r"[\U000E0000-\U000E007F]")
HIDDEN_HTML = re.compile(r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px)?\b|<!--.*?-->)", re.I | re.S)
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# ---------- Action classes ----------

DESTINATION_KEYS = {"to", "recipient", "recipients", "email", "url", "endpoint", "webhook", "address",
                    "host", "cc", "bcc", "agent", "target", "channel"}
DESTRUCTIVE_TOOL = re.compile(r"(delete|remove|drop|destroy|truncate|wipe|purge|erase|reset|revoke)", re.I)
MEMORY_TOOL = re.compile(r"(memory|remember|memorize|save_fact|store_fact)", re.I)
AGENT_TOOL = re.compile(r"(send_to_agent|delegate|handoff|hand_off|a2a|message_agent|spawn_agent)", re.I)
WRITE_TOOL = re.compile(r"(write|create_file|save_file|update_file|append|put_object|upload_file)", re.I)

SENSITIVE_PATHS = re.compile(
    r"(^|/)(\.env(\.|$)|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.netrc|\.npmrc|\.pypirc|"
    r"\.git-credentials|\.kube/config|credentials\.json|secrets?\.(ya?ml|json|txt)|\.docker/config\.json)", re.I)

# Files that configure agents: writing instructions into them persists an attack (GP-0009)
AGENT_CONFIG_PATHS = re.compile(
    r"(^|/)(CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.cursor/rules|\.windsurfrules|\.clinerules|"
    r"\.github/copilot-instructions\.md|\.claude/settings(\.local)?\.json|\.mcp\.json|\.github/workflows/)", re.I)

DESTRUCTIVE_SHELL = re.compile(
    r"(\brm\s+-[a-z]*[rf][a-z]*\b|\bgit\s+push\b.*--force|\bgit\s+reset\s+--hard\b|\bdrop\s+(table|database)\b|"
    r"\btruncate\s+table\b|\bmkfs\b|\bdd\s+if=|\bchmod\s+-R\s+777\b|:\(\)\s*\{)", re.I)
EGRESS_SHELL = re.compile(r"\b(curl|wget|nc|ncat|netcat|scp|rsync|sftp|ftp|telnet|Invoke-WebRequest)\b", re.I)
URL_RE = re.compile(r"(?:https?|ftp)://[^\s'\"<>]+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.I)


def decode_hidden(text: str) -> str:
    """Reveal text hidden in Unicode tag characters (invisible ASCII smuggling)."""
    return "".join(chr(ord(c) - 0xE0000) for c in TAG_CHARS.findall(text or ""))


def has_instructions(text: str, raw: bool = False) -> bool:
    text = text or ""
    if not raw:
        text = ZERO_WIDTH.sub("", text + " " + decode_hidden(text))
    return any(re.search(p, text, re.I | re.S) for p in INSTRUCTION_PATTERNS)


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
    return [p for p in SECRET_PATTERNS if re.search(p, text or "")]


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
            if k.lower() in {"path", "file", "file_path", "filename", "filepath", "notebook_path"} and isinstance(v, str):
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
    if any(re.search(p, text or "", re.I) for p in BIAS_PATTERNS):
        hits.append(("GP-0010", {"source": source}))
    if hidden or has_instructions(text):
        state["tainted_by"] = state.get("tainted_by") or source
    return hits
