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
import sys

from . import home

# ---------- Signatures ----------
# The patterns live in signatures.json, as data. This module compiles them and runs fixed
# checks over them. Changing what the sensor looks for means changing that file, which the
# rule lint (scripts/lint_rules.py) and the rule gate (scripts/rule_gate.py) check.

# A sensor runs as its own process for one session, so the rule set is chosen once at
# startup and never changes underneath a running session. GUARDIAN_SIGNATURES points at a
# verified bundle on disk, which is how an operator runs rules newer than their install
# without replacing it, and how the response drill measures the before and after of
# adopting one. It is a path to data, not a way to author rules: nothing in the file can
# execute, and the checks that read it are still the fixed ones in this module.
INSTALLED_SIGNATURES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "signatures.json")


def signatures_path():
    """Which rule bundle this session runs, in order of precedence.

    1. GUARDIAN_SIGNATURES, because somebody who named a file meant that file.
    2. A bundle the member adopted, under their own data directory.
    3. The one that shipped with the install.

    Step 2 is the step that was missing. `update` fetched a bundle, checked every file
    against the manifest and wrote it to <home>/rules, and then nothing read it. A member
    who ran it was told they had updated, and kept running the rules they had before
    unless they knew to set an environment variable. The network could tell a machine that
    an attack existed and the machine's defences did not change, which is the difference
    between an exchange and an immune system.

    Only a bundle that passed the manifest check is ever written there, so preferring it
    adopts nothing that arrived unverified, and nothing in it can execute.
    """
    named = os.environ.get("GUARDIAN_SIGNATURES")
    if named:
        return named
    from . import home
    adopted = home.path("rules", "signatures.json")
    if os.path.exists(adopted):
        return adopted
    return INSTALLED_SIGNATURES


# A sensor runs as its own process for one session, so the bundle is chosen once at
# startup and never changes underneath a running session.
SIGNATURES_PATH = signatures_path()

_FLAGS = {"i": re.I, "s": re.S}


def _flags(spec: str) -> int:
    out = 0
    for ch in spec or "":
        out |= _FLAGS[ch]
    return out


def _compile(entry: dict):
    return re.compile(entry["pattern"], _flags(entry.get("flags", "")))


def local_path():
    """A member's own patterns, kept beside the ones they adopt from the network."""
    return home.path("local-signatures.json")


def merge_signatures(base: dict, local: dict) -> dict:
    """The network's patterns and the member's own, in one rule set.

    A security team has attacks that are theirs: an internal hostname, a product name, a
    phrasing seen in their own incidents. Before this, pointing the sensor at their own
    file replaced the published set entirely, so adding one pattern of their own silently
    stopped them receiving everybody else's. Nobody would notice until an attack the
    network already knew about went through.

    Lists are added to, keys the member does not mention are left alone. Their patterns
    are extra signatures in the existing categories, so a hit is reported under the same
    GP number as any other: nothing about an internal rule travels, and the receiver
    never sees a pattern id it does not recognise.
    """
    merged = dict(base)
    for key, value in (local or {}).items():
        if isinstance(value, list) and isinstance(merged.get(key), list):
            merged[key] = merged[key] + value
        elif isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def load_signatures(path: str = None, local: str = None) -> dict:
    """The active rule set: what was published, plus whatever the member added."""
    with open(path or signatures_path(), encoding="utf-8") as f:
        document = json.load(f)
    where = local if local is not None else local_path()
    try:
        with open(where, encoding="utf-8") as f:
            own = json.load(f)
    except OSError:
        return document          # no local file, which is the ordinary case
    except ValueError as e:
        _refuse_local(where, "it is not readable JSON: %s" % e)
        return document
    # Checked the same way an adopted bundle is. A member's own pattern can backtrack
    # catastrophically just as easily as a published one, and the sensor runs it against
    # every tool call. Their file is dropped rather than the sensor being taken down, and
    # it is said out loud, because believing you are covered by a rule that never loaded
    # is worse than knowing it did not.
    from . import safety
    try:
        safety.check_signatures(merge_signatures({"instruction": []}, own))
    except safety.Unsafe as e:
        _refuse_local(where, str(e))
        return document
    return merge_signatures(document, own)


def _refuse_local(where, why):
    sys.stderr.write("guardian: ignoring your own patterns in %s. %s\n" % (where, why))
    sys.stderr.write("guardian: the published rules are still running.\n")


SIGNATURES = load_signatures()
_S = SIGNATURES


def signatures_fingerprint(path: str = None) -> str:
    """A short digest of the rule bundle actually in use.

    Recorded on every detection so a sighting cannot claim a rule set it was not running.
    Without it, a sensor pointed at a stripped bundle produces evidence indistinguishable
    from a fully armed one, and `rules_version` is whatever the member types at report time.
    The specification requires that an entry's rule set be knowable; this is what makes that
    true rather than asserted.
    """
    try:
        with open(path or SIGNATURES_PATH, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:12]
    except OSError:
        return "unreadable"

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
# A shell command arrives as one string under one key, so every rule that reads argument
# names saw nothing in it. The hook exists for the tools a proxy cannot see, and shell is
# the largest of them, so that was the gap doing the most work.
# Defaulted rather than indexed. A member running an adopted bundle from before this key
# existed would otherwise get a KeyError on import, which takes their sensor down to add a
# rule. A bundle may always be older than the engine reading it.
COMMAND_KEYS = set(_S.get("command_keys") or ("code", "cmd", "command", "script"))
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


def commands_in(args) -> list:
    """Shell commands among these arguments, as strings."""
    out = []
    if isinstance(args, dict):
        for k, v in args.items():
            if k.lower() in COMMAND_KEYS and isinstance(v, str):
                out.append(v)
            elif isinstance(v, (dict, list)):
                out.extend(commands_in(v))
    elif isinstance(args, list):
        for v in args:
            out.extend(commands_in(v))
    return out


def paths_in_command(command: str) -> list:
    """Path looking words in a shell command.

    Split rather than matched with a pattern. A regular expression over attacker
    controlled command text is where catastrophic backtracking comes from, and this
    only has to over-collect safely: a word is a candidate, and SENSITIVE_PATHS is what
    decides whether it matters.
    """
    out = []
    for word in (command or "").split():
        word = word.strip("\"'`,;()<>").lstrip("@")
        if "/" in word and not word.startswith("-"):
            out.append(word)
    return out


def destinations(args) -> list:
    """Collect values that look like where data is being sent."""
    out = []
    # A URL inside a shell command is a destination as surely as one in a `url` argument.
    # It still only matters to a rule that also requires taint, so an ordinary fetch in an
    # untainted session raises nothing.
    for command in commands_in(args):
        out.extend(URL_RE.findall(command))
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
    for command in commands_in(args):
        out.extend(paths_in_command(command))
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
    "GP-0019": "A tool appeared on an approved server, or its input schema changed, after approval",
    "GP-0020": "A canary the operator registered appeared in outbound tool arguments",
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

    # A destructive tool is recognised by its name, and a shell has one name for every
    # job it does, so the command itself is what says whether this one destroys anything.
    destructive_shell = [c for c in commands_in(args) if DESTRUCTIVE_SHELL.search(c)]
    if tainted and (DESTRUCTIVE_TOOL.search(name or "") or destructive_shell):
        hits.append(("GP-0005", {"tool": name, "tainted_by": tainted,
                                 "shell": bool(destructive_shell)}))

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
