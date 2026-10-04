"""Load and validate pattern files against schema.yaml.

Validation is part of the scan, not a side errand. A pattern that does not parse, or that
carries a live destination or a malformed canary, would be run by somebody against a real
agent, so it is refused here.
"""
import os
import re

from . import yamlish

REQUIRED = ["schema_version", "id", "title", "status", "version", "summary", "severity",
            "surfaces", "maps_to", "preconditions", "test", "detection", "mitigations",
            "references", "credits", "created"]
REQUIRED_NESTED = {
    "maps_to": ["owasp", "atlas"],
    "test": ["target", "setup", "steps", "payload", "success_when"],
    "detection": ["type", "signals", "logic", "false_alarm_rate"],
}
STATUSES = ("draft", "verified", "enforced")
DETECTION_TYPES = ("rule", "signature", "behavior")
SEVERITIES = ("low", "medium", "high", "critical")

ID = re.compile(r"^GP-\d{4}$")
CANARY_ANY = re.compile(r"GP\d{4}-CANARY-[^\s,.)\"']*")
CANARY_GOOD = re.compile(r"^GP\d{4}-CANARY-[0-9a-f]{4}$")
# Finding destinations a test could really reach.
#
# This was once a list of real-looking TLDs to catch. That is the wrong way round: a list
# of what is forbidden lets everything unlisted through, and attacker.ru, attacker.xyz and
# a bare IP address all validated clean. The rule now is the other way: a destination has
# to be inside reserved, unroutable space, and anything else is refused.
HOST_IN_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://([^/\s'\"<>]+)", re.I)
EMAIL = re.compile(r"\b[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.I)
BARE_HOST = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Reserved by RFC 2606 and RFC 6761. None of these resolve on the public internet.
RESERVED_SUFFIXES = (".test", ".example", ".invalid", ".localhost")
RESERVED_NAMES = {"localhost", "example.com", "example.net", "example.org"}
# RFC 5737 documentation ranges and loopback, the only literal addresses a test may name.
RESERVED_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "127.")
# A dotted token whose last part is one of these is a filename or an identifier, not a host.
NOT_A_HOST_SUFFIX = {
    "yaml", "yml", "py", "md", "txt", "html", "htm", "json", "jsonl", "csv", "sh", "svg",
    "png", "ico", "js", "css", "toml", "cfg", "ini", "lock", "log", "pyc", "zip", "gz",
    "env", "sample", "tmpl", "example",
}


def _is_reserved_host(host):
    host = host.split("@")[-1].split(":")[0].strip().strip(".").lower()
    if not host:
        return True
    if IPV4.fullmatch(host):
        return host.startswith(RESERVED_IP_PREFIXES)
    return host in RESERVED_NAMES or host.endswith(RESERVED_SUFFIXES)


def reachable_destinations(text):
    """Hosts in the text that are not in reserved space, so a test could really reach them."""
    found = set()
    for host in HOST_IN_URL.findall(text) + EMAIL.findall(text):
        if not _is_reserved_host(host):
            found.add(host.split("@")[-1].split(":")[0].lower())
    for token in BARE_HOST.findall(text):
        if token.rsplit(".", 1)[-1].lower() in NOT_A_HOST_SUFFIX:
            continue
        if not _is_reserved_host(token):
            found.add(token.lower())
    for address in IPV4.findall(text):
        if not address.startswith(RESERVED_IP_PREFIXES):
            found.add(address)
    return sorted(found)


class Report:
    def __init__(self):
        self.patterns = {}
        self.problems = []

    @property
    def ok(self):
        return not self.problems

    def fail(self, name, msg):
        self.problems.append(f"{name}: {msg}")


def _strings(value, key=None, skip=("references",)):
    """Every string in the document, except under keys whose content is meant to be links."""
    if key in skip:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in _strings(v, k, skip)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v, key, skip)]
    return []


def validate_one(name, doc, report):
    if not isinstance(doc, dict):
        report.fail(name, "the file is not a mapping")
        return
    for field in REQUIRED:
        if doc.get(field) in (None, "", []) and field != "false_alarm_rate":
            report.fail(name, f"missing required field {field}")
    for parent, children in REQUIRED_NESTED.items():
        block = doc.get(parent)
        if not isinstance(block, dict):
            report.fail(name, f"{parent} is not a block")
            continue
        for child in children:
            if child not in block:
                report.fail(name, f"missing {parent}.{child}")

    pid = doc.get("id")
    if not (isinstance(pid, str) and ID.match(pid or "")):
        report.fail(name, f"id is not in GP-nnnn form: {pid!r}")
    elif name != f"{pid}.yaml":
        report.fail(name, f"id {pid} does not match the filename")
    if doc.get("schema_version") != "0.1":
        report.fail(name, f"schema_version is not \"0.1\": {doc.get('schema_version')!r}")
    if doc.get("status") not in STATUSES:
        report.fail(name, f"status is not one of {STATUSES}: {doc.get('status')!r}")
    detection = doc.get("detection") or {}
    if isinstance(detection, dict) and detection.get("type") not in DETECTION_TYPES:
        report.fail(name, f"detection.type is not one of {DETECTION_TYPES}")
    severity = doc.get("severity") or ""
    if not any(str(severity).startswith(s) for s in SEVERITIES):
        report.fail(name, f"severity does not start with one of {SEVERITIES}")

    text = "\n".join(_strings(doc))
    for token in CANARY_ANY.findall(text):
        if not CANARY_GOOD.match(token):
            report.fail(name, f"canary is not in GPnnnn-CANARY-xxxx form: {token}")
    for destination in reachable_destinations(text):
        report.fail(name, "a destination outside reserved space, which a test could really "
                          f"reach: {destination}")


def validate_dir(path):
    """Validate every pattern file in a directory. Returns a Report."""
    report = Report()
    seen = {}
    for name in sorted(os.listdir(path)):
        if not name.endswith(".yaml"):
            continue
        try:
            doc = yamlish.load_file(os.path.join(path, name))
        except yamlish.YamlishError as e:
            report.fail(name, f"could not be read: {e}")
            continue
        validate_one(name, doc, report)
        if isinstance(doc, dict):
            report.patterns[name[:-5]] = doc
            seen.setdefault(doc.get("id"), []).append(name)
    for pid, names in seen.items():
        if len(names) > 1:
            report.fail(", ".join(names), f"id {pid} is used more than once, and ids are never reused")
    return report


def registry_dir():
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(here, "patterns")
