"""Agent identity and access for the MCP proxy: who the agent is, whether it is still
provisioned, and whether the host it runs on attests a passing posture.

Opt-in. Nothing here runs unless guardian.json has an `agent_access` block. When it does,
every tools/call is checked before it is forwarded, and anything that goes wrong while
checking denies the call. The rest of the sensor fails open on its own faults; an access
check that failed open would be no access check, so configuring this block is the
operator choosing to fail closed.

Three checks, in order:

1. **Token.** An OIDC-shaped bearer token: a compact JWT whose `iss`, `aud`, `sub`, `exp`
   and, when present, `nbf` and `iat` are checked. The signature is HS256, an HMAC with a
   secret shared with a configured issuer. That is what the standard library can verify.
   It is not RS256 or ES256 against an identity provider's published keys, there is no
   discovery document and no key rotation, so this is an OIDC-shaped token check in a
   stdlib-only core, not a production identity provider integration. A deployment that
   needs RS256 verifies the token at a gateway and hands this a token it re-signed, or
   waits for the core to take a dependency, which decision 11 does not allow yet.

2. **Directory.** A small file of agent identities with a SCIM-style lifecycle:
   provision, update, deprovision by `active: false`, or delete. The token's
   (`iss`, `sub`) must name an active entry. The file is read again on every call, so a
   deprovisioned agent is denied on its next call without restarting anything. This is
   not an RFC 7644 server; `apply_scim` takes the resource shape and verbs such a server
   would receive, so an integration can feed it from one.

3. **Posture.** For sensitive tools only, a short HS256-signed attestation from the host:
   which host, when it was issued and whether its posture check passed. It must verify,
   be recent, and say `pass`. This is a statement the host makes about itself, signed by
   whatever holds the posture key. It is not MDM, does not inspect the machine, and is
   only as trustworthy as the process that signs it.

Where the token and attestation come from: files named in the host's config, read on
every call. Not from MCP `_meta` or anything else in the message. The proxy forwards the
client's message line exactly as it arrived, so a bearer token carried in the message
would be handed to every MCP server the agent talks to, and anything in the message is
reachable by whatever steers the agent. The host writes the files and refreshes them;
the agent's own tools must not be able to read or write them.

Python 3.9+ standard library only.
"""
import base64
import hashlib
import hmac
import json
import os
import tempfile
import time

from . import home

SCHEMA_VERSION = 1
# A token larger than this is not a token anybody issued for this.
MAX_TOKEN_BYTES = 8192
# RFC 7518 asks for an HMAC key at least as long as the hash output.
MIN_SECRET_BYTES = 32
DEFAULT_LEEWAY_SECONDS = 60
DEFAULT_POSTURE_MAX_AGE_SECONDS = 900
# The tool classes the shared rule engine already treats as sensitive (signatures.json,
# tool_classes). A call to a tool whose name matches one of these needs a posture
# attestation. Exact names can be added in config with `sensitive_tools`.
DEFAULT_SENSITIVE_CLASSES = ("destructive", "memory", "agent", "write")
SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"


class Denied(Exception):
    """A call that must not be forwarded. The message is for the local log only."""


# ---------- compact HS256 tokens ----------

def _b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text):
    if not isinstance(text, str) or not text or any(c in text for c in "=+/ \n"):
        raise Denied("token segment is not base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise Denied("token segment is not base64url")


def encode_hs256(claims, secret):
    """A compact HS256 token. For hosts that mint attestations, and for tests."""
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"},
                                       separators=(",", ":")).encode())
    body = _b64url_encode(json.dumps(claims, separators=(",", ":"),
                                     sort_keys=True).encode())
    signing_input = (header + "." + body).encode("ascii")
    sig = hmac.new(_key_bytes(secret), signing_input, hashlib.sha256).digest()
    return header + "." + body + "." + _b64url_encode(sig)


def _key_bytes(secret):
    return secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)


def _unverified_parts(token):
    if not isinstance(token, str):
        raise Denied("no token")
    token = token.strip()
    if not token:
        raise Denied("no token")
    if len(token) > MAX_TOKEN_BYTES:
        raise Denied("token too large")
    parts = token.split(".")
    if len(parts) != 3:
        raise Denied("token is not a compact JWS")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
    except ValueError:
        raise Denied("token is not JSON")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise Denied("token is not a JSON object")
    # Exactly HS256. "none", RS256 handed an HMAC secret, and anything else are refused,
    # because accepting an algorithm the token names is how alg confusion works.
    if header.get("alg") != "HS256":
        raise Denied("token algorithm is not HS256")
    if "crit" in header:
        raise Denied("token has critical header extensions")
    return parts, claims


def _check_signature(parts, secret):
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    expected = hmac.new(_key_bytes(secret), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(parts[2])):
        raise Denied("token signature does not verify")


def _number(claims, name, required):
    value = claims.get(name)
    if value is None:
        if required:
            raise Denied("token has no %s" % name)
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Denied("token %s is not a number" % name)
    return value


def verify_token(token, issuers, audience, now, leeway=DEFAULT_LEEWAY_SECONDS):
    """The claims of a valid token, or Denied saying why not.

    `issuers` maps an issuer string to its HMAC secret. The issuer is read from the token
    before the signature is checked, only to choose the secret: an unknown issuer is
    refused without trying any key.
    """
    parts, claims = _unverified_parts(token)
    iss = claims.get("iss")
    if not isinstance(iss, str) or iss not in issuers:
        raise Denied("token issuer is not configured")
    _check_signature(parts, issuers[iss])
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if not audience or audience not in auds:
        raise Denied("token audience does not match")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise Denied("token has no subject")
    exp = _number(claims, "exp", required=True)
    if now >= exp + leeway:
        raise Denied("token expired")
    nbf = _number(claims, "nbf", required=False)
    if nbf is not None and now + leeway < nbf:
        raise Denied("token not yet valid")
    iat = _number(claims, "iat", required=False)
    if iat is not None and now + leeway < iat:
        raise Denied("token issued in the future")
    return claims


def verify_attestation(document, secret, now, max_age, leeway=DEFAULT_LEEWAY_SECONDS,
                       host=None):
    """The claims of a fresh, passing posture attestation, or Denied saying why not.

    The attestation is an HS256 token with `host`, `iat` and `posture`, and optionally
    `checks`, a map of named checks that must all be true. Fresh means issued within
    `max_age` seconds. `host`, when configured, must match.
    """
    parts, claims = _unverified_parts(document)
    _check_signature(parts, secret)
    iat = _number(claims, "iat", required=True)
    if now + leeway < iat:
        raise Denied("attestation issued in the future")
    if now - iat > max_age:
        raise Denied("attestation is stale")
    if host is not None and claims.get("host") != host:
        raise Denied("attestation is for another host")
    if claims.get("posture") != "pass":
        raise Denied("attestation posture is not pass")
    checks = claims.get("checks", {})
    if not isinstance(checks, dict) or not all(v is True for v in checks.values()):
        raise Denied("attestation has a failing check")
    return claims


# ---------- the directory ----------

def empty_directory():
    return {"schema_version": SCHEMA_VERSION, "agents": {}}


def load_directory(path):
    """The directory as it is on disk now. A missing or unreadable file is Denied.

    Missing is not treated as empty-and-fine: a typo in the path must not quietly mean
    every agent is unknown and nobody notices why, or worse, that checks are skipped.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise Denied("agent directory unreadable: %s" % e.__class__.__name__)
    if (not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION
            or not isinstance(data.get("agents"), dict)):
        raise Denied("agent directory has the wrong shape")
    return data


def find_agent(directory, issuer, subject):
    """The (id, entry) whose issuer and subject match, or (None, None)."""
    for agent_id, entry in sorted(directory["agents"].items()):
        if (isinstance(entry, dict) and entry.get("issuer") == issuer
                and entry.get("subject") == subject):
            return agent_id, entry
    return None, None


def _save_directory(path, data):
    """Written whole and renamed into place, so a reader never sees half a file."""
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".agents-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load_for_edit(path):
    if not os.path.exists(path):
        return empty_directory()
    return load_directory(path)


def provision(path, agent_id, issuer, subject, display_name=None):
    """Add an agent, or reactivate it. Returns the entry."""
    for name, value in (("id", agent_id), ("issuer", issuer), ("subject", subject)):
        if not isinstance(value, str) or not value:
            raise ValueError("%s is required" % name)
    data = _load_for_edit(path)
    other, _ = find_agent(data, issuer, subject)
    if other is not None and other != agent_id:
        raise ValueError("issuer and subject already belong to %s" % other)
    entry = {"issuer": issuer, "subject": subject, "active": True}
    if display_name:
        entry["display_name"] = display_name
    data["agents"][agent_id] = entry
    _save_directory(path, data)
    return entry


def update(path, agent_id, changes):
    """Change fields of an existing agent. `active: false` is a deprovision."""
    data = _load_for_edit(path)
    if agent_id not in data["agents"]:
        raise KeyError(agent_id)
    allowed = {"active", "display_name", "subject", "issuer"}
    unknown = set(changes) - allowed
    if unknown:
        raise ValueError("cannot change %s" % ", ".join(sorted(unknown)))
    if "active" in changes and not isinstance(changes["active"], bool):
        raise ValueError("active must be true or false")
    data["agents"][agent_id].update(changes)
    _save_directory(path, data)
    return data["agents"][agent_id]


def deprovision(path, agent_id, delete=False):
    """Mark an agent inactive, or remove it. Its next call is denied either way."""
    if delete:
        data = _load_for_edit(path)
        if data["agents"].pop(agent_id, None) is None:
            raise KeyError(agent_id)
        _save_directory(path, data)
        return None
    return update(path, agent_id, {"active": False})


def apply_scim(path, method, resource=None, agent_id=None):
    """Apply one SCIM-style change, shaped like what a SCIM server would receive.

    method is POST (create), PUT (replace), PATCH (only `active` and `displayName`, as
    replace operations) or DELETE. A User resource maps to an entry as: `id` to the
    agent id, `userName` to the token subject, and the issuer is taken from the
    resource's `urn:guardianprotocol:agent` extension, `{"issuer": ...}`, because SCIM
    has no field for which identity provider signs the agent's tokens.
    """
    method = (method or "").upper()
    resource = resource or {}
    agent_id = agent_id or resource.get("id")
    if method == "DELETE":
        return deprovision(path, agent_id, delete=True)
    if method in ("POST", "PUT"):
        if SCIM_USER_SCHEMA not in (resource.get("schemas") or []):
            raise ValueError("resource is not a SCIM User")
        issuer = (resource.get("urn:guardianprotocol:agent") or {}).get("issuer")
        entry = provision(path, agent_id, issuer, resource.get("userName"),
                          resource.get("displayName"))
        if resource.get("active") is False:
            entry = update(path, agent_id, {"active": False})
        return entry
    if method == "PATCH":
        changes = {}
        for op in resource.get("Operations") or []:
            if (op.get("op") or "").lower() != "replace":
                raise ValueError("only replace operations are supported")
            value = op.get("value")
            target = op.get("path")
            pairs = value.items() if target is None and isinstance(value, dict) \
                else [(target, value)]
            for key, val in pairs:
                if key == "active":
                    changes["active"] = val
                elif key == "displayName":
                    changes["display_name"] = val
                else:
                    raise ValueError("cannot patch %s" % key)
        return update(path, agent_id, changes)
    raise ValueError("unsupported method %r" % method)


# ---------- the gate the proxy calls ----------

def _read_secret(path, what):
    try:
        with open(path, "rb") as f:
            secret = f.read().strip()
    except (OSError, TypeError):
        raise Denied("%s secret unreadable" % what)
    if len(secret) < MIN_SECRET_BYTES:
        raise Denied("%s secret shorter than %d bytes" % (what, MIN_SECRET_BYTES))
    return secret


def _read_text(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read(MAX_TOKEN_BYTES + 1).strip()
    except (OSError, TypeError, ValueError):
        raise Denied("no %s presented" % what)


class Gate:
    """Decides whether one tools/call may be forwarded. Built from `agent_access`.

    Every input is read again on each call: the token so a host can refresh it, the
    directory so a deprovision takes effect at once, the attestation so it can age out.
    """

    def __init__(self, cfg, clock=time.time, tool_classes=None):
        if not isinstance(cfg, dict):
            raise ValueError("agent_access must be an object")
        self.cfg = cfg
        self.clock = clock
        self.log_path = cfg.get("log_path") or home.path("access.jsonl")
        self.leeway = cfg.get("leeway_seconds", DEFAULT_LEEWAY_SECONDS)
        self.sensitive_names = set(cfg.get("sensitive_tools") or [])
        classes = cfg.get("sensitive_classes", list(DEFAULT_SENSITIVE_CLASSES))
        if tool_classes is None:
            from . import rules
            tool_classes = {"destructive": rules.DESTRUCTIVE_TOOL,
                            "memory": rules.MEMORY_TOOL,
                            "agent": rules.AGENT_TOOL,
                            "write": rules.WRITE_TOOL}
        self.sensitive_res = [tool_classes[c] for c in classes]

    def is_sensitive(self, tool):
        tool = tool if isinstance(tool, str) else ""
        return tool in self.sensitive_names or any(r.search(tool) for r in self.sensitive_res)

    def _issuers(self):
        issuers = {}
        for entry in self.cfg.get("issuers") or []:
            issuers[entry["issuer"]] = _read_secret(entry.get("secret_path"), "issuer")
        if not issuers:
            raise Denied("no issuers configured")
        return issuers

    def decide(self, tool):
        """(allowed, record). Never raises: an unexpected error is a denial."""
        record = {"time": None, "tool": tool if isinstance(tool, str) else None,
                  "sensitive": False}
        try:
            now = self.clock()
            record["time"] = int(now)
            token = _read_text(self.cfg.get("token_path"), "token")
            claims = verify_token(token, self._issuers(), self.cfg.get("audience"),
                                  now, self.leeway)
            record["subject"] = claims["sub"]
            directory = load_directory(self.cfg.get("directory_path"))
            agent_id, entry = find_agent(directory, claims["iss"], claims["sub"])
            if entry is None:
                raise Denied("agent not provisioned")
            record["agent"] = agent_id
            if entry.get("active") is not True:
                raise Denied("agent deprovisioned")
            if self.is_sensitive(tool):
                record["sensitive"] = True
                posture = self.cfg.get("posture") or {}
                if not posture:
                    raise Denied("sensitive tool and no posture policy configured")
                document = _read_text(posture.get("attestation_path"), "attestation")
                verify_attestation(
                    document, _read_secret(posture.get("secret_path"), "posture"), now,
                    posture.get("max_age_seconds", DEFAULT_POSTURE_MAX_AGE_SECONDS),
                    self.leeway, posture.get("host"))
            record["decision"] = "allowed"
        except Denied as e:
            record["decision"] = "denied"
            record["reason"] = str(e)
        except Exception as e:  # fail closed
            record["decision"] = "denied"
            record["reason"] = "access check fault: %s" % e.__class__.__name__
        return record["decision"] == "allowed", record

    def log(self, record):
        """One line per decision, on this machine. Never the token or the attestation.

        Kept apart from evidence.jsonl on purpose: a denial is not a detection of an
        attack pattern, and nothing here must ever be reported as a sighting.
        """
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
        except OSError:
            pass


# ---------- command line ----------

def main(argv, out=None):
    """guardian agents provision | update | deprovision | list | attest"""
    import argparse
    import sys
    out = out or sys.stdout
    ap = argparse.ArgumentParser(prog="guardian agents",
                                 description="Manage agent identities the sensor accepts.")
    sub = ap.add_subparsers(dest="command")
    p = sub.add_parser("provision", help="add or reactivate an agent")
    p.add_argument("--directory", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--issuer", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--display-name")
    p = sub.add_parser("deprovision", help="deny an agent from its next call")
    p.add_argument("--directory", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--delete", action="store_true", help="remove the entry entirely")
    p = sub.add_parser("list", help="show every agent and whether it is active")
    p.add_argument("--directory", required=True)
    p = sub.add_parser("attest", help="write a signed posture attestation for this host")
    p.add_argument("--secret-path", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--posture", choices=("pass", "fail"), required=True)
    p.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        if a.command == "provision":
            provision(a.directory, a.id, a.issuer, a.subject, a.display_name)
            out.write("provisioned %s\n" % a.id)
        elif a.command == "deprovision":
            deprovision(a.directory, a.id, delete=a.delete)
            out.write("%s %s\n" % ("deleted" if a.delete else "deprovisioned", a.id))
        elif a.command == "list":
            for agent_id, entry in sorted(load_directory(a.directory)["agents"].items()):
                out.write("%s  %s  %s %s\n" % (
                    agent_id, "active" if entry.get("active") is True else "inactive",
                    entry.get("issuer"), entry.get("subject")))
        elif a.command == "attest":
            secret = _read_secret(a.secret_path, "posture")
            document = encode_hs256({"host": a.host, "iat": int(time.time()),
                                     "posture": a.posture}, secret)
            fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(document + "\n")
            out.write("wrote a %s attestation for %s\n" % (a.posture, a.host))
        else:
            ap.print_help(out)
            return 2
    except (Denied, KeyError, ValueError) as e:
        sys.stderr.write("guardian agents: %s\n" % e)
        return 1
    return 0
