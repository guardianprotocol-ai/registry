"""Assumed-breach response: watch registered paths, quarantine, listen for a decoy.

Two layers catch a touch. The sensor and the client hook see tool calls and refuse them
before the tool runs. This module is the other layer: an OS watcher that sees reads,
copies, moves and renames by any process, and a loopback listener that sees a connection
to a hostname nothing legitimate should call.

The path is not read back out of the canary file. The watcher hashes paths under the
operator's root and compares the digests. On a trip it writes a local audit record and,
when the canary is armed, quarantines inside that root. A path that resolves outside the
root is refused. Nothing here sends the file anywhere.

Python 3.9+ standard library only. inotify is used on Linux through libc. Where that
cannot be opened, a poll of size, link count and timestamps is the fallback. A read on
a volume mounted noatime or relatime may not move the access time, so the fallback can
miss a read that does not change the file. inotify does not have that gap.
"""
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import os
import select
import socket
import stat
import struct
import threading
import time

from . import canaries
from . import path_canaries
from . import rules

RESPONSE_QUARANTINE = "quarantine"
RESPONSE_READONLY = "readonly"
RESPONSE_FLAG = "flag"
RESPONSES = (RESPONSE_QUARANTINE, RESPONSE_READONLY, RESPONSE_FLAG)

# inotify constants. The numeric values are the kernel ABI, not a guess.
IN_ACCESS = 0x00000001
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_ONLYDIR = 0x01000000
IN_ISDIR = 0x40000000
IN_IGNORED = 0x00008000
IN_NONBLOCK = 0x00000800
IN_CLOEXEC = 0x00080000

DIR_MASK = (IN_OPEN | IN_ACCESS | IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_FROM
            | IN_MOVED_TO | IN_DELETE | IN_MOVE_SELF | IN_DELETE_SELF | IN_ONLYDIR)
FILE_MASK = IN_OPEN | IN_ACCESS | IN_CLOSE_WRITE | IN_MOVE_SELF | IN_DELETE_SELF
TRIP_MASK = IN_OPEN | IN_ACCESS | IN_MOVED_FROM | IN_MOVE_SELF | IN_DELETE_SELF
_EVENT_SIZE = struct.calcsize("iIII")


class BreachError(Exception):
    pass


def empty_policy():
    return {
        "schema_version": 1,
        "root": None,
        "roots": [],
        "quarantine_dir": "quarantine",
        "response": RESPONSE_QUARANTINE,
        "allow_processes": [],
        "siblings": {},
        "assets": {},
        "seeds": {},
        "observe": [],
        "sentinel": {
            "enabled": False,
            "host": "127.0.0.1",
            "port": 0,
            "label": "network-sentinel",
            "path": "/crown-jewels-internal",
        },
        "audit_path": None,
        # Set by a drill or a lab run. Live traffic leaves this false, so a sighting
        # built from the evidence is marked live unless the operator said otherwise.
        "drill": False,
    }


def load_policy(path=None):
    """Operator policy. This file may name roots and siblings. It does not hold canary values."""
    path = path or path_canaries.default_policy_path()
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError):
        return empty_policy()
    if not isinstance(raw, dict):
        raise BreachError("breach policy is not a JSON object")
    if raw.get("schema_version") not in (None, 1):
        raise BreachError("breach policy schema_version is not 1")
    policy = empty_policy()
    for key in policy:
        if key in raw:
            policy[key] = raw[key]
    if policy["response"] not in RESPONSES:
        raise BreachError("response must be one of %s" % ", ".join(RESPONSES))
    for key in ("allow_processes", "roots", "observe"):
        if not isinstance(policy[key], list):
            raise BreachError("%s must be a list" % key)
    for key in ("siblings", "assets", "seeds", "sentinel"):
        if not isinstance(policy[key], dict):
            raise BreachError("%s must be an object" % key)
    sentinel_host = policy["sentinel"].get("host")
    if sentinel_host not in (None, "127.0.0.1") and not rfc1918_host(sentinel_host):
        raise BreachError(
            "the sentinel listens on 127.0.0.1 or an RFC1918 address, never on a public address")
    return policy


def save_policy(policy, path=None):
    path = path or path_canaries.default_policy_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(policy, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def inside(path, root):
    """True when `path` resolves inside `root`. A missing path is judged by its normalized form."""
    if not path or not root:
        return False
    path = os.path.realpath(path)
    root = os.path.realpath(root)
    if path == root:
        return True
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe_name(label):
    cleaned = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in (label or ""))
    return (cleaned[:80] or "canary")


def _append_jsonl(path, record):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def quarantine_dir_of(policy):
    root = policy.get("root")
    raw = policy.get("quarantine_dir") or "quarantine"
    if os.path.isabs(raw):
        return raw
    if not root:
        return raw
    return os.path.join(root, raw)


def _sibling_path(root, relative):
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        return None
    if os.path.isabs(relative):
        return None
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    return os.path.join(root, relative)


def _readonly(path, root):
    """Make a file read-only, or refuse if that would follow a link out of the root."""
    if not path or not os.path.lexists(path):
        return "missing"
    parent = os.path.realpath(os.path.dirname(os.path.abspath(path)))
    if not inside(parent, root):
        return "refused"
    target = os.path.realpath(path)
    if not inside(target, root):
        return "refused"
    try:
        os.chmod(target, 0o400)
    except OSError:
        return "refused"
    return "readonly"


def _hash_fd(fd, limit):
    """SHA-256 of the bytes behind an open descriptor, or None past the cap."""
    digest = hashlib.sha256()
    size = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            return None
        digest.update(chunk)
    return digest.hexdigest()


def _empty_original_decoy(path, hit):
    """Truncate a decoy on the descriptor that just showed it is still the bait.

    The link count and the digest are read from that descriptor, and the
    truncate uses it too. A check on the path, then a later open, can empty
    whatever the name points at by then. A second link, or bytes that no
    longer match the digest `canary decoy` wrote, is not bait.
    """
    if not path or not isinstance(hit, dict) or hit.get("role") != "decoy":
        return
    expected = hit.get("decoy_hash")
    if not isinstance(expected, str) or len(expected) != 64:
        return
    flags = os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return
        digest = _hash_fd(fd, path_canaries.MAX_CONTENT_BYTES)
        if not isinstance(digest, str) or len(digest) != len(expected):
            return
        if not hmac.compare_digest(digest, expected):
            return
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return
        os.ftruncate(fd, 0)
    except OSError:
        return
    finally:
        os.close(fd)


def _move_into(path, root, quarantine_dir, label, hit):
    """Move a directory entry into the quarantine directory.

    chmod follows symlinks, so a link whose target is outside the root is renamed
    and never chmod'd. A regular file is emptied only when the same descriptor
    still shows one link and the decoy digest. Anything else is made mode 0400
    and moved, and the bytes stay.
    """
    if not path or not os.path.lexists(path):
        return "missing", None
    parent = os.path.realpath(os.path.dirname(os.path.abspath(path)))
    if not inside(parent, root):
        return "refused", None
    if not inside(quarantine_dir, root) and os.path.realpath(quarantine_dir) != os.path.realpath(root):
        # The directory may not exist yet. Its parent, once created, is checked below.
        pass
    try:
        os.makedirs(quarantine_dir, mode=0o700, exist_ok=True)
        os.chmod(quarantine_dir, 0o700)
    except OSError:
        return "refused", None
    if not inside(quarantine_dir, root):
        return "refused", None
    dest = os.path.join(quarantine_dir, _safe_name(label) + "-" + "%08x" % (time.time_ns() & 0xFFFFFFFF))
    try:
        if os.path.islink(path):
            os.rename(path, dest)
            return "moved-link", dest
        target = os.path.realpath(path)
        if not inside(target, root):
            return "refused", None
        _empty_original_decoy(path, hit)
        os.chmod(target, 0o400)
        os.rename(path, dest)
    except OSError:
        return "refused", None
    return "quarantined", dest


def contain(policy, hit, tool=None, process=None, reason="", audit_path=None,
            backend="tool", events=None, opened_before=None):
    """Flag, and when armed quarantine, a single hit. Returns the audit record.

    Baseline canaries are recorded and not moved. The refusal sent back to an agent is
    not built here; callers use the sensor's uniform refusal so the answer does not say
    which canary fired.
    """
    policy = policy or empty_policy()
    label = hit.get("label") or hit.get("canary") or "unnamed"
    state = hit.get("state") or path_canaries.BASELINE
    role = hit.get("role") or "decoy"
    kind = hit.get("kind") or path_canaries.KIND_PATH
    access = hit.get("access_path")
    if isinstance(process, dict):
        proc = {"pid": process.get("pid"), "comm": process.get("comm") or "unknown"}
    elif process:
        proc = {"pid": None, "comm": str(process)}
    else:
        proc = {"pid": None, "comm": "unknown"}

    response = policy.get("response") or RESPONSE_FLAG
    root = policy.get("root")
    action = "flagged"
    moved_to = None
    note = reason
    sibling_rows = []

    armed = state == path_canaries.ARMED
    if armed and response != RESPONSE_FLAG and root:
        # A sentinel has no file. A path hit is moved or made read-only, and either way
        # the siblings named for this label are made read-only. Both stay inside the root.
        if access and kind != path_canaries.KIND_SENTINEL:
            if response == RESPONSE_READONLY:
                action = _readonly(access, root)
            else:
                action, moved_to = _move_into(
                    access, root, quarantine_dir_of(policy), label, hit)
        for relative in (policy.get("siblings") or {}).get(label) or []:
            sibling = _sibling_path(root, relative)
            if sibling is None:
                sibling_rows.append({"path": relative, "action": "refused"})
                continue
            sibling_rows.append({"path": sibling, "action": _readonly(sibling, root)})
        if action == "flagged" and sibling_rows:
            action = "siblings-locked"
    elif armed and response != RESPONSE_FLAG and not root:
        note = (reason + "; " if reason else "") + "no root configured, so nothing was moved"

    record = {
        "time": _now(),
        "label": label,
        "state": state,
        "kind": kind,
        "role": role,
        "process": proc,
        "tool": tool,
        "access_path": access,
        "action": action,
        "moved_to": moved_to,
        "siblings": sibling_rows,
        "reason": note,
        "backend": backend,
        "opened_before": list(opened_before or [])[:50],
    }
    if events is not None:
        events.append(record)
    where = audit_path or policy.get("audit_path")
    if where:
        _append_jsonl(where, record)
    return record


def write_evidence(path, pattern_ids, action, detail, drill=False):
    """A sensor-shaped evidence row. Sharing reads pattern, action and time, not detail."""
    if not path:
        return None
    record = {
        "time": _now(),
        "patterns": list(pattern_ids),
        "reasons": [rules.RULES[pid] for pid in pattern_ids],
        "action": action,
        "detail": detail,
        "sensor": "guardian-sensor v0 (prototype)",
        "rules_fingerprint": rules.signatures_fingerprint(),
    }
    if drill:
        record["drill"] = True
    _append_jsonl(path, record)
    return record


def evidence_detail(hit, via, tool=None, process=None, reason=""):
    detail = path_canaries.redacted(hit)
    detail["via"] = via
    detail["tool"] = tool
    detail["reason"] = reason
    if hit.get("access_path"):
        detail["access_path"] = hit["access_path"]
    if isinstance(process, dict) and process.get("comm"):
        detail["process"] = process.get("comm")
    return detail


def comm_allowed(comm, names):
    if not comm or comm == "unknown" or not names:
        return False
    base = os.path.basename(comm)
    return comm in names or base in names


def processes_holding(path):
    """Processes that currently have `path` open, from /proc. Empty if it cannot be read."""
    if not path or not os.path.isdir("/proc"):
        return []
    try:
        real = os.path.realpath(path)
    except OSError:
        real = path
    found = []
    try:
        pids = os.listdir("/proc")
    except OSError:
        return []
    for pid in pids:
        if not pid.isdigit():
            continue
        fd_dir = "/proc/%s/fd" % pid
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        held = False
        for fd in fds:
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if link == path or link == real or link.startswith(real + " "):
                held = True
                break
            try:
                if os.path.realpath(link) == real:
                    held = True
                    break
            except OSError:
                continue
        if not held:
            continue
        comm = "unknown"
        try:
            with open("/proc/%s/comm" % pid, encoding="utf-8", errors="replace") as handle:
                comm = handle.read().strip() or "unknown"
        except OSError:
            pass
        found.append({"pid": int(pid), "comm": comm})
    return found


def resolve_labels(store, root, limit=10000):
    """label -> path, for files under root whose digest is registered. Memory only."""
    table = {}
    if not root or not os.path.isdir(root):
        return table
    by_hash = {}
    for entry in store.get("paths") or []:
        if entry.get("kind") == path_canaries.KIND_SENTINEL:
            continue
        if isinstance(entry.get("hash"), str):
            by_hash[entry["hash"]] = entry
        if isinstance(entry.get("realpath_hash"), str):
            by_hash[entry["realpath_hash"]] = entry
    count = 0
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name != os.path.basename(quarantine_dir_of({"root": root, "quarantine_dir": "quarantine"}))]
        for name in files:
            count += 1
            if count > limit:
                return table
            path = os.path.abspath(os.path.join(dirpath, name))
            try:
                digest = path_canaries._digest(path, store["salt"])
            except (ValueError, KeyError):
                continue
            entry = by_hash.get(digest)
            if entry and entry["label"] not in table:
                table[entry["label"]] = path
    return table


def rfc1918_host(host):
    """True for 10/8, 172.16/12 and 192.168/16.

    The wildcard address, a public address, a name and IPv6 are false. The sentinel
    uses this so a lab can bind an address inside an isolated network, and a public
    address is refused before the socket exists.
    """
    if not isinstance(host, str):
        return False
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(part) for part in parts]
    except ValueError:
        return False
    if any(num < 0 or num > 255 for num in nums):
        return False
    if nums[0] == 10:
        return True
    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return True
    if nums[0] == 192 and nums[1] == 168:
        return True
    return False


class Sentinel:
    """A decoy listener. It accepts a connection, records it, and serves nothing."""

    def __init__(self, host="127.0.0.1", port=0, on_connect=None):
        if host != "127.0.0.1" and not rfc1918_host(host):
            raise BreachError(
                "the sentinel listens on 127.0.0.1 or an RFC1918 address, never on a public address")
        if host == "127.0.0.1":
            bind_host = "127.0.0.1"
        else:
            parts = [int(part) for part in host.split(".")]
            bind_host = "%d.%d.%d.%d" % (parts[0], parts[1], parts[2], parts[3])
        self.host = bind_host
        self.events = []
        self._on = on_connect
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_host, int(port or 0)))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._loop, name="guardian-sentinel", daemon=True)

    def url(self, path="/crown-jewels-internal"):
        if not path.startswith("/"):
            path = "/" + path
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def start(self):
        self._thread.start()
        return self.port

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        try:
            self._sock.close()
        except OSError:
            pass

    def _loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            peer = addr[0] if isinstance(addr, tuple) and addr else ""
            event = {
                "time": _now(),
                "peer": peer,
                "peer_port": addr[1] if isinstance(addr, tuple) and len(addr) > 1 else None,
            }
            self.events.append(event)
            try:
                conn.close()
            except OSError:
                pass
            # Any completed handshake is the event. Nothing is read and nothing is
            # sent. The bind address is what keeps the socket off the public internet.
            if self._on:
                try:
                    self._on(event)
                except Exception:
                    # A fault in the response must not kill the listener.
                    pass


def _libc():
    return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def _inotify_fd():
    libc = _libc()
    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_init1.restype = ctypes.c_int
    fd = libc.inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err) if err else "inotify_init1 failed")
    return fd, libc


class Watcher:
    """Watch a root for touches of registered paths.

    `backend` is "auto", "inotify" or "poll". "auto" uses inotify and falls back to
    polling when the kernel call fails.
    """

    def __init__(self, root, store, policy=None, value_store=None, audit_path=None,
                 evidence_path=None, backend="auto", on_record=None):
        if not root or not os.path.isdir(root):
            raise BreachError("the watcher needs a directory to watch")
        self.root = os.path.realpath(root)
        self.store = store
        self.policy = policy or empty_policy()
        if not self.policy.get("root"):
            self.policy["root"] = self.root
        self.value_store = value_store
        self.audit_path = audit_path or self.policy.get("audit_path")
        self.evidence_path = evidence_path
        self.backend_request = backend
        self.backend = None
        self.events = []
        self.trace = []
        self.sentinel = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._fd = None
        self._libc = None
        self._dir_wd = {}
        self._file_wd = {}
        self.by_label = {}
        self._by_hash = {}
        self._content = {}
        self._snap = {}
        self._known_files = {}
        self._recent = {}
        self._self_until = {}
        self._moves = {}
        self._seen_trace = set()
        self._done = set()
        self.observe_paths = []
        self.on_record = on_record

    def start(self):
        self._index()
        sentinel_cfg = self.policy.get("sentinel") or {}
        if sentinel_cfg.get("enabled"):
            self.sentinel = Sentinel(
                host=sentinel_cfg.get("host") or "127.0.0.1",
                port=sentinel_cfg.get("port") or 0,
                on_connect=self._on_sentinel)
            self.sentinel.start()
        if self.backend_request != "poll":
            try:
                self._fd, self._libc = _inotify_fd()
                self._arm_inotify()
                self.backend = "inotify"
            except OSError:
                if self.backend_request == "inotify":
                    raise
                self._fd = None
                self.backend = "poll"
        else:
            self.backend = "poll"
        if self.backend == "poll":
            self._snapshot()
        self._thread = threading.Thread(target=self._loop, name="guardian-watch", daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self.sentinel is not None:
            self.sentinel.stop()
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def wait_for(self, predicate, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return False

    def sentinel_url(self):
        if not self.sentinel:
            return None
        path = ((self.policy.get("sentinel") or {}).get("path")) or "/crown-jewels-internal"
        return self.sentinel.url(path)

    def _index(self):
        self.by_label = resolve_labels(self.store, self.root)
        self._by_hash = {}
        for entry in self.store.get("paths") or []:
            if isinstance(entry.get("hash"), str):
                self._by_hash[entry["hash"]] = entry
            if isinstance(entry.get("realpath_hash"), str):
                self._by_hash[entry["realpath_hash"]] = entry
            content = entry.get("content_hash")
            path = self.by_label.get(entry["label"])
            if content and path:
                self._content[content] = {"label": entry["label"], "path": path, "entry": entry}
        self.observe_paths = []
        for relative in self.policy.get("observe") or []:
            observed = _sibling_path(self.root, relative)
            if observed and os.path.lexists(observed):
                self.observe_paths.append(os.path.abspath(observed))

    def _mark_self(self, path):
        if not path:
            return
        try:
            real = os.path.realpath(path)
        except OSError:
            real = path
        self._self_until[real] = time.monotonic() + 0.6

    def _is_self(self, path):
        if not path:
            return False
        try:
            real = os.path.realpath(path)
        except OSError:
            real = os.path.abspath(path)
        return time.monotonic() < self._self_until.get(real, 0)

    def _ignored(self, path):
        if not path:
            return True
        quarantine = quarantine_dir_of(self.policy)
        try:
            if inside(path, quarantine) or os.path.realpath(path) == os.path.realpath(quarantine):
                return True
        except OSError:
            return True
        if not inside(os.path.dirname(os.path.abspath(path)), self.root) and not inside(path, self.root):
            # Events for the root directory itself are not a file touch.
            if os.path.realpath(path) != self.root:
                return True
        return False

    def _arm_inotify(self):
        libc = self._libc
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        for dirpath, dirs, _files in os.walk(self.root, followlinks=False):
            dirs[:] = [name for name in dirs if not self._ignored(os.path.join(dirpath, name))]
            self._watch_dir(dirpath)
        for label, path in self.by_label.items():
            self._watch_file(path, label)

    def _watch_dir(self, path):
        wd = self._libc.inotify_add_watch(self._fd, os.fsencode(path), DIR_MASK)
        if wd >= 0:
            self._dir_wd[wd] = path

    def _watch_file(self, path, label):
        # No IN_DONT_FOLLOW: an open through a symlink should hit the inode we registered.
        wd = self._libc.inotify_add_watch(self._fd, os.fsencode(path), FILE_MASK)
        if wd >= 0:
            self._file_wd[wd] = label

    def _snapshot(self):
        self._snap = {}
        for label, path in self.by_label.items():
            self._snap[label] = _stat_key(path)
        self._known_files = {}
        for dirpath, _dirs, files in os.walk(self.root, followlinks=False):
            for name in files:
                path = os.path.join(dirpath, name)
                self._known_files[os.path.abspath(path)] = _stat_key(path)

    def _loop(self):
        if self.backend == "inotify":
            poller = select.poll()
            poller.register(self._fd, select.POLLIN)
            while not self._stop.is_set():
                try:
                    ready = poller.poll(200)
                except OSError:
                    break
                if not ready:
                    continue
                for wd, mask, cookie, name in _read_events(self._fd):
                    try:
                        self._on_inotify(wd, mask, cookie, name)
                    except Exception:
                        # One bad event must not kill the watcher.
                        continue
        else:
            while not self._stop.is_set():
                try:
                    self._poll_once()
                except Exception:
                    pass
                self._stop.wait(0.05)

    def _on_inotify(self, wd, mask, cookie, name):
        if mask & IN_IGNORED:
            return
        if wd in self._file_wd and not name:
            label = self._file_wd[wd]
            path = self.by_label.get(label)
            if path and mask & TRIP_MASK:
                self._on_registered_path(path, mask)
            return
        directory = self._dir_wd.get(wd)
        if directory is None:
            return
        if mask & IN_CREATE and mask & IN_ISDIR and name:
            created = os.path.join(directory, name)
            if not self._ignored(created):
                self._watch_dir(created)
            return
        if mask & IN_ISDIR and not name:
            return
        if not name:
            return
        path = os.path.join(directory, name)
        if mask & IN_MOVED_FROM:
            self._moves[cookie] = path
        if mask & IN_MOVED_TO and cookie in self._moves:
            source = self._moves.pop(cookie)
            self._on_rename(source, path)
        if self._ignored(path):
            return
        # A create event fires before the writer has finished. Scanning then hashes a
        # partial file, and the self-open window hides the close that carries the
        # finished bytes. Close, and a rename into the tree, are the finished file.
        if mask & (IN_CLOSE_WRITE | IN_MOVED_TO) and os.path.isfile(path) and not os.path.islink(path):
            self._scan_written(path)
        if mask & TRIP_MASK and _is_observed(self.policy, self.root, path):
            if not self._is_self(path):
                self._observe(path, None, "observed", self._process(path))
        if mask & TRIP_MASK:
            self._on_registered_path(path, mask)

    def _on_rename(self, source, dest):
        entry = self._entry_for(source)
        if not entry:
            return
        self.by_label[entry["label"]] = os.path.abspath(dest)
        if self._ignored(dest) or not inside(dest, self.root):
            hit = dict(entry)
            hit["access_path"] = os.path.abspath(source)
            self._trip(hit, reason="renamed", via="watcher", left=not inside(dest, self.root))
            return
        hit = dict(entry)
        hit["access_path"] = os.path.abspath(dest)
        self._trip(hit, reason="renamed", via="watcher")

    def _on_registered_path(self, path, mask):
        if self._is_self(path) or self._ignored(path):
            return
        entry = self._entry_for(path)
        if not entry:
            return
        reason = "opened"
        if mask & (IN_MOVED_FROM | IN_MOVE_SELF):
            reason = "renamed"
        elif mask & IN_DELETE_SELF:
            reason = "deleted"
        elif mask & IN_ACCESS:
            reason = "read"
        # The old name is already gone by the time a move is delivered. The MOVED_TO
        # event carries the new name and is what quarantine has to follow.
        if (mask & (IN_MOVED_FROM | IN_MOVE_SELF)) and not os.path.lexists(path):
            return
        hit = dict(entry)
        hit["access_path"] = os.path.abspath(path)
        self._trip(hit, reason=reason, via="watcher")

    def _poll_once(self):
        for label, path in list(self.by_label.items()):
            current = _stat_key(path)
            previous = self._snap.get(label, current)
            self._snap[label] = current
            if current == previous:
                continue
            if self._is_self(path):
                continue
            entry = self._entry_for(path) or by_label_entry(self.store, label)
            if not entry:
                continue
            hit = dict(entry)
            hit["access_path"] = os.path.abspath(path) if os.path.lexists(path or "") else path
            reason = "changed"
            if current is None:
                reason = "disappeared"
            elif previous and len(current) > 3 and current[3] != previous[3] and current[4] == previous[4]:
                reason = "read"
            self._trip(hit, reason=reason, via="watcher")
        for path in self.observe_paths:
            current = _stat_key(path)
            previous = self._snap.get("observe:" + path, current)
            self._snap["observe:" + path] = current
            if current != previous and not self._is_self(path):
                self._observe(path, None, "observed", self._process(path))
        # New or rewritten files: a copy of a seeded dataset lands here.
        seen = {}
        for dirpath, dirs, files in os.walk(self.root, followlinks=False):
            dirs[:] = [name for name in dirs if not self._ignored(os.path.join(dirpath, name))]
            for name in files:
                path = os.path.abspath(os.path.join(dirpath, name))
                if self._ignored(path):
                    continue
                key = _stat_key(path)
                seen[path] = key
                if self._known_files.get(path) == key:
                    continue
                self._known_files[path] = key
                if path not in self._known_files or self._entry_for(path) is None:
                    self._scan_written(path)
        for gone in list(self._known_files):
            if gone not in seen:
                self._known_files.pop(gone, None)

    def _entry_for(self, path):
        if not path:
            return None
        absolute = os.path.abspath(path)
        texts = [absolute]
        if os.path.exists(path) or os.path.islink(path):
            texts.append(os.path.realpath(path))
        for text in texts:
            try:
                digest = path_canaries._digest(text, self.store["salt"])
            except (ValueError, KeyError):
                continue
            entry = self._by_hash.get(digest)
            if entry and entry.get("kind") != path_canaries.KIND_SENTINEL:
                return entry
        return None

    def _process(self, path):
        holders = processes_holding(path) if path else []
        if holders:
            return holders[0]
        return {"pid": None, "comm": "unknown"}

    def _allowed(self, entry, process):
        comm = (process or {}).get("comm")
        if comm_allowed(comm, self.policy.get("allow_processes") or []):
            return True
        if entry.get("role") == "asset":
            asset = (self.policy.get("assets") or {}).get(entry["label"]) or {}
            if comm_allowed(comm, asset.get("allow_processes") or []):
                return True
        return False

    def _observe(self, path, label, action, process):
        key = (action, os.path.abspath(path) if path else label)
        if key in self._seen_trace:
            return
        self._seen_trace.add(key)
        self.trace.append({
            "time": time.time(),
            "path": os.path.abspath(path) if path else None,
            "label": label,
            "action": action,
            "process": (process or {}).get("comm"),
        })

    def _trip(self, hit, reason, via, left=False, honor_allow=True, process=None):
        path = hit.get("access_path")
        label = hit.get("label")
        # Done is per path. One read must not quarantine the same file forever, and
        # locking the original must not leave a second copy of it sitting in the tree.
        done_key = (label, os.path.abspath(path) if path else "")
        if done_key in self._done:
            return
        # Self-caused opens are ignored by the event handlers. A trip decided by a
        # content scan still has to run: the scan marks the path so its own read is
        # not a second event, and that mark must not swallow the finding.
        if path and self._ignored(path) and hit.get("kind") != "seed":
            return
        entry_role = hit.get("role")
        if process is None:
            process = self._process(path) if via == "watcher" else {"pid": None, "comm": via}
        if honor_allow and self._allowed(hit, process):
            self._observe(path, label, "allowed", process)
            return
        # Reading the file that holds a seed is normal for whoever is allowed to use the
        # dataset. The copy is what proves it left. Asset and decoy reads are not normal.
        if entry_role == "seed-home" and reason in ("opened", "read", "changed"):
            self._observe(path, label, "observed", process)
            return
        # Open and a following read of the same path are one touch. A second path
        # with the same label, such as a copy, is a different touch.
        key = (label, os.path.abspath(path) if path else "", process.get("pid"), process.get("comm"))
        now = time.monotonic()
        if key in self._recent and now - self._recent[key] < 0.75:
            return
        self._recent[key] = now
        if left:
            reason = reason + "; the new path is outside the root and was not followed"
        opened = [{"path": row["path"], "label": row["label"]}
                  for row in self.trace if row["action"] in ("observed", "allowed")]
        self._mark_self(path)
        record = contain(
            self.policy, hit, process=process, reason=reason,
            audit_path=self.audit_path, backend=via if via == "sentinel" else (self.backend or via),
            events=self.events, opened_before=opened)
        # A rename is often seen first as the old name disappearing. That attempt
        # cannot move a path that is already gone, and the following event still
        # has the new name. Marking the label done here would drop that event.
        if record["action"] != "missing":
            self._done.add(done_key)
        self.trace.append({
            "time": time.time(),
            "path": path,
            "label": label,
            "action": record["action"],
            "process": process.get("comm"),
        })
        if self.evidence_path:
            action = "blocked" if record["action"] in (
                "quarantined", "readonly", "moved-link", "siblings-locked") else "flagged"
            evidence = write_evidence(
                self.evidence_path, ["GP-0041"], action,
                evidence_detail(hit, via, process=process, reason=reason),
                drill=bool(self.policy.get("drill")))
            if self.on_record and evidence:
                try:
                    self.on_record(evidence)
                except Exception:
                    # Sharing the sighting must not undo the local quarantine.
                    pass

    def _scan_written(self, path):
        if self._ignored(path) or self._is_self(path):
            return
        # A symlink or a second name for the registered inode is not a copy. Reading it
        # here would mark the real file and hide the open that follows. The open itself
        # is the event.
        if os.path.islink(path):
            return
        entry = self._entry_for(path)
        if entry is not None:
            home = self.by_label.get(entry["label"])
            try:
                same = bool(home) and os.path.samefile(path, home)
            except OSError:
                same = False
            if same or entry.get("role") == "seed-home":
                return
        self._mark_self(path)
        if self.value_store is not None:
            text = path_canaries.text_of_file(path)
            for entry in canaries.matches(self.value_store, text):
                home = (self.policy.get("seeds") or {}).get(entry["label"])
                home_path = self.by_label.get(home) if home else None
                if home_path and os.path.realpath(home_path) == os.path.realpath(path):
                    continue
                hit = {
                    "label": entry["label"],
                    "state": entry["state"],
                    "kind": "seed",
                    "role": "seed",
                    "access_path": os.path.abspath(path),
                }
                self._trip(hit, reason="a seeded record appeared in another file",
                           via="watcher", honor_allow=False)
                if home_path and entry["state"] == canaries.ARMED:
                    home_entry = by_label_entry(self.store, home)
                    if home_entry:
                        home_hit = dict(home_entry)
                        home_hit["access_path"] = home_path
                        home_hit["role"] = "asset"
                        self._trip(home_hit, reason="seeded dataset was copied",
                                   via="watcher", honor_allow=False)
        try:
            digest, _size = path_canaries.hash_file(path)
        except OSError:
            digest = None
        meta = self._content.get(digest) if digest else None
        if not meta:
            return
        original = meta.get("path")
        try:
            if original and os.path.samefile(original, path):
                return
        except OSError:
            pass
        hit = dict(meta["entry"])
        hit["access_path"] = os.path.abspath(path)
        hit["role"] = "asset"
        self._trip(hit, reason="a byte-for-byte copy of a registered file was written",
                   via="watcher", honor_allow=False)
        original = meta.get("path")
        if original and os.path.realpath(original) != os.path.realpath(path):
            original_hit = dict(meta["entry"])
            original_hit["access_path"] = original
            self._trip(original_hit, reason="registered file was copied",
                       via="watcher", honor_allow=False)

    def _on_sentinel(self, event):
        label = ((self.policy.get("sentinel") or {}).get("label")) or "network-sentinel"
        stored = by_label_entry(self.store, label)
        hit = dict(stored) if stored else {
            "label": label,
            "state": path_canaries.ARMED,
            "kind": path_canaries.KIND_SENTINEL,
            "role": "decoy",
        }
        hit["access_path"] = None
        hit["state"] = hit.get("state") or path_canaries.ARMED
        # Record the connection, not a payload. The peer is whoever completed
        # the handshake. The socket has already been closed.
        process = {"pid": None, "comm": "connect:%s" % (event.get("peer") or "unknown")}
        self._trip(hit, reason="connection to the decoy endpoint", via="sentinel",
                   honor_allow=False, process=process)


def by_label_entry(store, label):
    for entry in store.get("paths") or []:
        if entry.get("label") == label:
            return entry
    return None


def _is_observed(policy, root, path):
    if not path:
        return False
    for relative in policy.get("observe") or []:
        sibling = _sibling_path(root, relative)
        if sibling and os.path.abspath(sibling) == os.path.abspath(path):
            return True
    return False


def _stat_key(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_ino, st.st_nlink, st.st_size, st.st_atime_ns, st.st_mtime_ns)


def _read_events(fd):
    try:
        data = os.read(fd, 65536)
    except BlockingIOError:
        return []
    except OSError:
        return []
    events = []
    offset = 0
    while offset + _EVENT_SIZE <= len(data):
        wd, mask, cookie, length = struct.unpack_from("iIII", data, offset)
        name = ""
        if length:
            raw = data[offset + _EVENT_SIZE:offset + _EVENT_SIZE + length]
            name = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
        events.append((wd, mask, cookie, name))
        offset += _EVENT_SIZE + length
    return events
