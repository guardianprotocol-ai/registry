"""A small, strict reader for the subset of YAML the pattern format uses.

The registry carries no third-party dependencies, so the scanner reads pattern files with
this rather than with a YAML library. It covers exactly what `schema.yaml` needs:

  key: value            maps, nested by two-space indent
  - item                block lists
  [a, b]                inline lists
  {name: a, org: b}     inline maps
  key: >                folded block scalars
  "quoted"  'quoted'    quoted strings
  42  null              integers and null

Anything outside that subset raises `YamlishError` instead of being guessed at. A pattern
file that drifts into wider YAML is then caught at the door, rather than being read
wrongly somewhere further downstream where the mistake would be silent.
"""
import re

__all__ = ["YamlishError", "loads", "load_file"]

KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*):(?:\s+(.*))?$")
INT = re.compile(r"^-?\d+$")
# "some words: more" is a map to YAML, not the sentence the author meant.
MAPLIKE = re.compile(r"^[^:'\"]+:(?:\s|$)")
UNSUPPORTED = {
    "&": "anchors",
    "*": "aliases",
    "|": "literal block scalars",
    "!": "tags",
    "?": "explicit keys",
}


class YamlishError(ValueError):
    """The file used something outside the supported subset, or is malformed."""


def _strip_comment(raw):
    """Drop a trailing comment from a plain scalar.

    YAML starts a comment at a `#` preceded by whitespace, so a `#` inside quotes or in a
    url fragment is left alone. The pattern template is written with these, and without
    this a newcomer copying it gets a parse error instead of a pattern.
    """
    quote, depth = None, 0
    for i, ch in enumerate(raw):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "#" and depth == 0 and (i == 0 or raw[i - 1] in " \t"):
            return raw[:i].rstrip()
    return raw


def _split_top_level(text, sep=","):
    """Split on `sep`, ignoring separators inside quotes or nested brackets."""
    out, buf, depth, quote = [], "", 0, None
    for ch in text:
        if quote:
            buf += ch
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote, buf = ch, buf + ch
        elif ch in "[{":
            depth, buf = depth + 1, buf + ch
        elif ch in "]}":
            depth, buf = depth - 1, buf + ch
        elif ch == sep and depth == 0:
            out.append(buf)
            buf = ""
        else:
            buf += ch
    out.append(buf)
    return [p.strip() for p in out if p.strip() != ""]


def _scalar(raw):
    raw = raw.strip()
    if raw == "" or raw in ("null", "~"):
        return None
    if raw[0] in "\"'":
        if len(raw) < 2 or raw[-1] != raw[0]:
            raise YamlishError(f"unterminated quoted string: {raw}")
        return raw[1:-1].replace('\\"', '"')
    if raw[0] == "[":
        if raw[-1] != "]":
            raise YamlishError(f"unterminated inline list: {raw}")
        return [_scalar(p) for p in _split_top_level(raw[1:-1])]
    if raw[0] == "{":
        if raw[-1] != "}":
            raise YamlishError(f"unterminated inline map: {raw}")
        out = {}
        for part in _split_top_level(raw[1:-1]):
            k, _, v = part.partition(":")
            if not _:
                raise YamlishError(f"inline map entry without a colon: {part}")
            out[k.strip()] = _scalar(v)
        return out
    if raw[0] in UNSUPPORTED:
        raise YamlishError(f"{UNSUPPORTED[raw[0]]} are not supported: {raw}")
    if INT.match(raw):
        return int(raw)
    return raw


class _Reader:
    def __init__(self, text):
        self.lines = []
        for n, line in enumerate(text.splitlines(), 1):
            if "\t" in line[: len(line) - len(line.lstrip())]:
                raise YamlishError(f"line {n}: indent with spaces, not tabs")
            self.lines.append(line)
        self.i = 0

    # ---------- cursor ----------
    def _skip_blanks(self):
        while self.i < len(self.lines):
            stripped = self.lines[self.i].strip()
            if stripped == "" or stripped.startswith("#"):
                self.i += 1
            else:
                return
        return

    def _peek(self):
        self._skip_blanks()
        if self.i >= len(self.lines):
            return None, None
        line = self.lines[self.i]
        return len(line) - len(line.lstrip()), line.strip()

    # ---------- folded scalars ----------
    def _folded(self, indent):
        parts, current = [], []
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.strip() == "":
                self.i += 1
                if current:
                    parts.append(" ".join(current))
                    current = []
                continue
            if len(line) - len(line.lstrip()) <= indent:
                break
            current.append(line.strip())
            self.i += 1
        if current:
            parts.append(" ".join(current))
        text = "\n".join(parts)
        # YAML's default chomping keeps exactly one trailing newline.
        return text + "\n" if text else ""

    def _wrapped(self, indent):
        """Lines continuing a plain scalar: more indented, and not starting a new item."""
        parts = []
        while self.i < len(self.lines):
            line = self.lines[self.i]
            stripped = line.strip()
            if stripped == "" or stripped.startswith("#"):
                break
            if len(line) - len(line.lstrip()) <= indent or stripped.startswith("- "):
                break
            parts.append(stripped)
            self.i += 1
        return parts

    # ---------- blocks ----------
    def parse(self, indent):
        depth, stripped = self._peek()
        if depth is None or depth < indent:
            return None
        return self._list(depth) if stripped.startswith("- ") or stripped == "-" else self._map(depth)

    def _list(self, indent):
        items = []
        while True:
            depth, stripped = self._peek()
            if depth is None or depth < indent or not (stripped.startswith("- ") or stripped == "-"):
                break
            if depth > indent:
                raise YamlishError(f"line {self.i + 1}: unexpected indent in a list")
            rest = stripped[2:].strip() if stripped.startswith("- ") else ""
            self.i += 1
            if rest == "":
                items.append(self.parse(indent + 1))
            elif rest[0] in "\"'[{":
                items.append(_scalar(_strip_comment(rest)))
            elif MAPLIKE.match(rest):
                # YAML reads "- some words: more" as a map, which is never what a pattern
                # means. Refusing it is what stops a file being read one way here and
                # another way, or not at all, by any other YAML reader.
                raise YamlishError(
                    f"line {self.i}: a list item reading as a map, {rest!r}. "
                    "Quote the whole item, or reword it so it has no colon followed by a space.")
            else:
                items.append(_strip_comment(" ".join([rest] + self._wrapped(indent))))
        return items

    def _map(self, indent):
        out = {}
        while True:
            depth, stripped = self._peek()
            if depth is None or depth < indent:
                break
            if depth > indent:
                raise YamlishError(f"line {self.i + 1}: unexpected indent in a map")
            m = KEY.match(stripped)
            if not m:
                raise YamlishError(f"line {self.i + 1}: expected 'key: value', got {stripped!r}")
            key, raw = m.group(1), _strip_comment((m.group(2) or "").strip())
            self.i += 1
            if raw == ">":
                out[key] = self._folded(indent)
            elif raw == "":
                out[key] = self.parse(indent + 1)
            elif raw[0] in "\"'[{":
                out[key] = _scalar(_strip_comment(raw))
            else:
                out[key] = _scalar(_strip_comment(" ".join([raw] + self._wrapped(indent))))
        return out


def loads(text):
    """Read a document. Returns a dict, or None for an empty document."""
    reader = _Reader(text)
    value = reader.parse(0)
    reader._skip_blanks()
    if reader.i < len(reader.lines):
        raise YamlishError(f"line {reader.i + 1}: could not read {reader.lines[reader.i]!r}")
    return value


def load_file(path):
    with open(path, encoding="utf-8") as f:
        return loads(f.read())
