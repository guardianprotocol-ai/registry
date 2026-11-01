"""What the watcher catches, measured rather than described.

Each probe builds a throwaway directory, arms a decoy, and performs one kind of access.
The result is what happened. Tests assert the cases we claim. The benchmark records the
same results so the report cannot drift from the code.

Python 3.9+ standard library only.
"""
import mmap
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

from . import breach
from . import canaries
from . import path_canaries

_HOLD = (
    "import ctypes,sys,time\n"
    "libc=ctypes.CDLL(None)\n"
    "libc.prctl(15, sys.argv[1].encode(), 0, 0, 0)\n"
    "f=open(sys.argv[2], 'rb')\n"
    "f.read(1)\n"
    "sys.stdout.write('open\\n')\n"
    "sys.stdout.flush()\n"
    "time.sleep(2)\n"
)


def _hold(comm, path):
    proc = subprocess.Popen(
        [sys.executable, "-c", _HOLD, comm, path],
        stdout=subprocess.PIPE, text=True)
    proc.stdout.readline()
    return proc


def _decoy_box(backend="auto", allow=None, content=True):
    root = tempfile.mkdtemp(prefix="guardian-probe-")
    path = os.path.join(root, "decoy.bin")
    _fields, _token, digest = path_canaries.write_decoy(path, "weights")
    store = path_canaries.load(os.path.join(root, "missing-path.json"))
    path_canaries.add_path(
        store, path, "weights-decoy", state=path_canaries.ARMED, role="decoy",
        root=root, content=content, decoy_hash=digest)
    policy = breach.empty_policy()
    policy["root"] = root
    if allow:
        policy["allow_processes"] = list(allow)
    parent = tempfile.mkdtemp(prefix="guardian-probe-meta-")
    watcher = breach.Watcher(
        root, store, policy, backend=backend,
        audit_path=os.path.join(parent, "audit.jsonl"),
        evidence_path=os.path.join(parent, "evidence.jsonl"))
    watcher.start()
    return {"root": root, "path": path, "store": store, "policy": policy,
            "watcher": watcher, "meta": parent}


def _stop(box):
    watcher = box.get("watcher")
    if watcher is not None:
        watcher.stop()
    shutil.rmtree(box["root"], ignore_errors=True)
    shutil.rmtree(box.get("meta", ""), ignore_errors=True)


def _tripped(box, timeout=2.0):
    watcher = box["watcher"]
    return watcher.wait_for(lambda: bool(watcher.events), timeout)


def _row(caught, note):
    return {"caught": bool(caught), "note": note}


# What `caught` means differs by probe. For the evasion cases it means the touch was
# stopped. For git status, an allowlisted reader, an unrelated file, another directory
# and a descriptor opened before the watch, caught means a false positive, so the
# expected value is false. poll_read depends on whether this host updates access time.
EXPECT_CAUGHT = {
    "open": True,
    "hardlink_inside": True,
    "hardlink_outside": True,
    "symlink": True,
    "mmap": True,
    "other_process": True,
    "rename": True,
    "tar": True,
    "git_status": False,
    "allowlisted_open": False,
    "unrelated_file": False,
    "other_directory": False,
    "fd_held_before_start": False,
    "symlink_escape": True,
    "sentinel": True,
    "sentinel_bind": True,
    "poll_unlink": True,
    "poll_read": None,
    "seed_copy": True,
    "asset_allow": True,
    "sibling_lock": True,
    "byte_copy": True,
    "tool_names_path": True,
    "tool_omits_path": True,
}


def expectations_hold(results):
    """Problems, empty when the probes match EXPECT_CAUGHT."""
    problems = []
    for name, want in EXPECT_CAUGHT.items():
        row = results.get(name) or {}
        note = row.get("note") or ""
        caught = bool(row.get("caught"))
        if name not in results:
            problems.append("%s did not run" % name)
            continue
        if name == "poll_read":
            if "did not move" in note and caught:
                problems.append("poll_read tripped although the access time did not move")
            elif "moved" in note and not caught:
                problems.append("poll_read: access time moved and the backend did not trip")
            elif "did not move" not in note and "moved" not in note:
                problems.append("poll_read note does not say whether access time moved: %s" % note)
            continue
        if name == "git_status" and "not installed" in note:
            continue
        if caught != want:
            problems.append("%s caught %s, expected %s (%s)" % (name, caught, want, note))
    return problems


def run():
    """Every probe. A thrown probe is recorded as not caught, with the error."""
    names = [
        "open", "hardlink_inside", "hardlink_outside", "symlink", "mmap",
        "other_process", "rename", "tar", "git_status", "allowlisted_open",
        "unrelated_file", "other_directory", "fd_held_before_start",
        "symlink_escape", "sentinel", "sentinel_bind", "poll_unlink", "poll_read",
        "seed_copy", "asset_allow", "sibling_lock", "byte_copy",
        "tool_names_path", "tool_omits_path",
    ]
    out = {}
    for name in names:
        try:
            out[name] = globals()["_probe_" + name]()
        except Exception as exc:
            out[name] = _row(False, "probe failed: %s" % exc)
    return out


def _probe_open():
    box = _decoy_box()
    try:
        subprocess.run(["cat", box["path"]], capture_output=True)
        caught = _tripped(box)
        return _row(caught, "cat of the decoy" + ("" if caught else " produced no event"))
    finally:
        _stop(box)


def _probe_hardlink_inside():
    box = _decoy_box()
    try:
        link = os.path.join(box["root"], "link.bin")
        os.link(box["path"], link)
        subprocess.run(["cat", link], capture_output=True)
        caught = _tripped(box)
        remaining = b""
        if os.path.exists(link):
            remaining = open(link, "rb").read()
        elif os.path.exists(box["path"]):
            remaining = open(box["path"], "rb").read()
        kept = remaining != b""
        return _row(caught and kept,
                    "trip %s, bytes left on the other name: %d" % (caught, len(remaining)))
    finally:
        _stop(box)


def _probe_hardlink_outside():
    box = _decoy_box()
    outside = tempfile.mkdtemp(prefix="guardian-outside-")
    try:
        link = os.path.join(outside, "link.bin")
        os.link(box["path"], link)
        subprocess.run(["cat", link], capture_output=True)
        caught = _tripped(box)
        blob = open(link, "rb").read() if os.path.exists(link) else b"missing"
        # The outside directory entry is not deleted. A second link means the
        # bytes are not bait we can empty, so they stay. We do not walk the
        # machine looking for other names.
        kept = blob not in (b"", b"missing")
        return _row(caught and kept and os.path.exists(link),
                    "trip %s, outside name still exists %s, bytes %d" % (
                        caught, os.path.exists(link), len(blob) if blob != b"missing" else -1))
    finally:
        _stop(box)
        shutil.rmtree(outside, ignore_errors=True)


def _probe_symlink():
    box = _decoy_box(content=True)
    try:
        link = os.path.join(box["root"], "sym")
        os.symlink(box["path"], link)
        subprocess.run(["cat", link], capture_output=True)
        return _row(_tripped(box), "open through a symlink")
    finally:
        _stop(box)


def _probe_mmap():
    box = _decoy_box()
    try:
        code = "import mmap,sys\nf=open(sys.argv[1],'rb')\nmm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)\nmm.read(1)\n"
        subprocess.run([sys.executable, "-c", code, box["path"]], capture_output=True)
        return _row(_tripped(box), "mmap after open")
    finally:
        _stop(box)


def _probe_other_process():
    box = _decoy_box()
    proc = None
    try:
        proc = _hold("snooper", box["path"])
        caught = _tripped(box)
        comm = box["watcher"].events[0]["process"]["comm"] if box["watcher"].events else None
        return _row(caught and comm == "snooper", "process comm %r" % comm)
    finally:
        if proc is not None:
            proc.kill()
        _stop(box)


def _probe_rename():
    box = _decoy_box(content=False)
    try:
        dest = os.path.join(box["root"], "moved.bin")
        os.rename(box["path"], dest)
        caught = box["watcher"].wait_for(
            lambda: any(e["action"] in ("quarantined", "readonly", "moved-link")
                        for e in box["watcher"].events), 2)
        return _row(caught and not os.path.exists(dest),
                    "new name still present: %s" % os.path.exists(dest))
    finally:
        _stop(box)


def _probe_tar():
    box = _decoy_box()
    try:
        archive = os.path.join(box["root"], "out.tar")
        subprocess.run(["tar", "cf", archive, "-C", box["root"], "decoy.bin"],
                       capture_output=True)
        return _row(_tripped(box), "tar reads the file to archive it")
    finally:
        _stop(box)


def _probe_git_status():
    if shutil.which("git") is None:
        return _row(False, "git is not installed, so this was not measured")
    box = _decoy_box()
    try:
        subprocess.run(["git", "init", "-q"], cwd=box["root"], capture_output=True)
        subprocess.run(["git", "status", "--porcelain"], cwd=box["root"], capture_output=True)
        caught = _tripped(box, timeout=0.6)
        return _row(caught, "git status on a repository that contains the decoy"
                    + (" tripped" if caught else " did not trip"))
    finally:
        _stop(box)


def _probe_allowlisted_open():
    box = _decoy_box(allow=["indexer"])
    proc = None
    try:
        proc = _hold("indexer", box["path"])
        caught = _tripped(box, timeout=0.5)
        allowed = any(row["action"] == "allowed" for row in box["watcher"].trace)
        return _row(caught, "allowlisted comm tripped %s, recorded as allowed %s" % (caught, allowed))
    finally:
        if proc is not None:
            proc.kill()
        _stop(box)


def _probe_unrelated_file():
    box = _decoy_box()
    try:
        other = os.path.join(box["root"], "README.txt")
        with open(other, "w", encoding="utf-8") as handle:
            handle.write("ordinary notes\n")
        subprocess.run(["cat", other], capture_output=True)
        return _row(_tripped(box, timeout=0.4), "reading a file that is not registered")
    finally:
        _stop(box)


def _probe_other_directory():
    box = _decoy_box()
    other = tempfile.mkdtemp(prefix="guardian-backup-")
    try:
        with open(os.path.join(other, "notes.txt"), "w", encoding="utf-8") as handle:
            handle.write("backup of somewhere else\n")
        subprocess.run(["grep", "-R", ".", other], capture_output=True)
        return _row(_tripped(box, timeout=0.4), "grep of a different directory")
    finally:
        _stop(box)
        shutil.rmtree(other, ignore_errors=True)


def _probe_fd_held_before_start():
    root = tempfile.mkdtemp(prefix="guardian-probe-")
    path = os.path.join(root, "decoy.bin")
    path_canaries.write_decoy(path, "weights")
    store = path_canaries.load(os.path.join(root, "missing-path.json"))
    path_canaries.add_path(store, path, "weights-decoy", state=path_canaries.ARMED,
                           role="decoy", root=root)
    policy = breach.empty_policy()
    policy["root"] = root
    held = open(path, "rb")
    held.read(1)
    meta = tempfile.mkdtemp(prefix="guardian-probe-meta-")
    watcher = breach.Watcher(root, store, policy, audit_path=os.path.join(meta, "audit.jsonl"),
                             evidence_path=os.path.join(meta, "evidence.jsonl"))
    try:
        watcher.start()
        held.read()
        caught = watcher.wait_for(lambda: bool(watcher.events), 0.6)
        return _row(caught, "a read on a descriptor opened before the watcher started")
    finally:
        held.close()
        watcher.stop()
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(meta, ignore_errors=True)


def _probe_symlink_escape():
    root = tempfile.mkdtemp(prefix="guardian-probe-")
    outside = tempfile.mkdtemp(prefix="guardian-outside-")
    try:
        victim = os.path.join(outside, "victim.txt")
        with open(victim, "w", encoding="utf-8") as handle:
            handle.write("leave this alone\n")
        os.chmod(victim, 0o600)
        before = os.stat(victim).st_mode
        decoy = os.path.join(root, "decoy.env")
        path_canaries.write_decoy(decoy, "env")
        os.symlink(victim, os.path.join(root, "link-out"))
        policy = breach.empty_policy()
        policy["root"] = root
        policy["siblings"] = {"d": ["link-out", "nope/../../etc/passwd"]}
        record = breach.contain(policy, {
            "label": "d", "state": path_canaries.ARMED, "role": "decoy",
            "kind": "path", "access_path": decoy}, reason="probe")
        after = os.stat(victim).st_mode
        refused = all(row["action"] == "refused" for row in record["siblings"])
        return _row(before == after and refused,
                    "victim mode unchanged %s, sibling actions %s" % (
                        before == after, [row["action"] for row in record["siblings"]]))
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(outside, ignore_errors=True)


def _probe_sentinel():
    root = tempfile.mkdtemp(prefix="guardian-probe-")
    meta = tempfile.mkdtemp(prefix="guardian-probe-meta-")
    watcher = None
    try:
        os.makedirs(os.path.join(root, "models"))
        sibling = os.path.join(root, "models", "weights.bin")
        with open(sibling, "wb") as handle:
            handle.write(b"crown jewel\n")
        os.chmod(sibling, 0o600)
        store = path_canaries.load(os.path.join(root, "missing-path.json"))
        policy = breach.empty_policy()
        policy["root"] = root
        policy["sentinel"] = {"enabled": True, "host": "127.0.0.1", "port": 0,
                              "label": "network-sentinel", "path": "/crown-jewels-internal"}
        policy["siblings"] = {"network-sentinel": ["models/weights.bin"]}
        watcher = breach.Watcher(root, store, policy, audit_path=os.path.join(meta, "audit.jsonl"),
                                 evidence_path=os.path.join(meta, "evidence.jsonl"))
        watcher.start()
        try:
            conn = socket.create_connection(("127.0.0.1", watcher.sentinel.port), timeout=2)
            payload = conn.recv(16)
            conn.close()
        except OSError:
            payload = b"connect failed"
        caught = watcher.wait_for(lambda: bool(watcher.events), 2)
        mode = stat.S_IMODE(os.stat(sibling).st_mode)
        return _row(caught and mode == 0o400 and payload == b"",
                    "trip %s, sibling mode %o, bytes served %r" % (caught, mode, payload))
    finally:
        if watcher is not None:
            watcher.stop()
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(meta, ignore_errors=True)


def _probe_sentinel_bind():
    try:
        breach.Sentinel(host="0.0.0.0", port=0)
    except breach.BreachError:
        return _row(True, "a non-loopback bind is refused")
    return _row(False, "a non-loopback bind was accepted")


def _probe_poll_unlink():
    box = _decoy_box(backend="poll", content=False)
    try:
        if box["watcher"].backend != "poll":
            return _row(False, "poll backend was not selected")
        os.remove(box["path"])
        caught = _tripped(box, timeout=2)
        reason = box["watcher"].events[0]["reason"] if box["watcher"].events else ""
        return _row(caught and reason == "disappeared", "reason %r" % reason)
    finally:
        _stop(box)


def _probe_poll_read():
    box = _decoy_box(backend="poll", content=False)
    try:
        before = os.stat(box["path"]).st_atime_ns
        subprocess.run(["cat", box["path"]], capture_output=True)
        moved = os.stat(box["path"]).st_atime_ns != before
        caught = _tripped(box, timeout=1.5)
        # relatime and noatime may not move the access time, and then the poll
        # backend cannot see a read. The result says which one this host did.
        if not moved:
            return _row(False, "access time did not move, so the poll backend did not see the read")
        return _row(caught, "access time moved and the poll backend tripped: %s" % caught)
    finally:
        _stop(box)


def _probe_seed_copy():
    root = tempfile.mkdtemp(prefix="guardian-probe-")
    meta = tempfile.mkdtemp(prefix="guardian-probe-meta-")
    watcher = None
    try:
        dataset = os.path.join(root, "data", "customers.csv")
        seeded = path_canaries.write_seed_dataset(dataset, "csv", "customers")
        values = canaries.load(os.path.join(meta, "values.json"))
        entries = path_canaries.register_seeds(values, seeded, canaries.ARMED)
        canaries.save(values, os.path.join(meta, "values.json"))
        store = path_canaries.load(os.path.join(meta, "paths.json"))
        home = path_canaries.add_path(
            store, dataset, "customers-file", state=path_canaries.ARMED,
            role="seed-home", root=root)
        path_canaries.save(store, os.path.join(meta, "paths.json"))
        policy = breach.empty_policy()
        policy["root"] = root
        for entry in entries:
            policy["seeds"][entry["label"]] = home["label"]
        watcher = breach.Watcher(
            root, store, policy, value_store=values,
            audit_path=os.path.join(meta, "audit.jsonl"),
            evidence_path=os.path.join(meta, "evidence.jsonl"))
        watcher.start()
        filler = os.path.join(root, "staged", "filler.csv")
        os.makedirs(os.path.dirname(filler))
        with open(filler, "w", encoding="utf-8") as handle:
            handle.write("customer_id,name\ncus_filler0001,Filler Row\n")
        filler_trip = watcher.wait_for(lambda: bool(watcher.events), 0.4)
        copy = os.path.join(root, "staged", "copy.csv")
        shutil.copy(dataset, copy)
        caught = watcher.wait_for(lambda: bool(watcher.events), 2)
        audit = open(os.path.join(meta, "audit.jsonl"), encoding="utf-8").read()
        leaked = any(value in audit for value, _label, _column in seeded)
        stored = open(os.path.join(meta, "values.json"), encoding="utf-8").read()
        stored_leak = any(value in stored for value, _label, _column in seeded)
        return _row(caught and not filler_trip and not leaked and not stored_leak,
                    "copy tripped %s, filler tripped %s, value in audit %s, value in store %s" % (
                        caught, filler_trip, leaked, stored_leak))
    finally:
        if watcher is not None:
            watcher.stop()
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(meta, ignore_errors=True)


def _probe_asset_allow():
    root = tempfile.mkdtemp(prefix="guardian-probe-")
    meta = tempfile.mkdtemp(prefix="guardian-probe-meta-")
    asset = os.path.join(root, "models", "weights.bin")
    os.makedirs(os.path.dirname(asset))
    with open(asset, "wb") as handle:
        handle.write(b"FAKE-WEIGHTS\n" + b"abc" * 20)
    store = path_canaries.load(os.path.join(meta, "paths.json"))
    path_canaries.add_path(store, asset, "production-weights", state=path_canaries.ARMED,
                           role="asset", root=root, content=True)
    policy = breach.empty_policy()
    policy["root"] = root
    policy["assets"] = {"production-weights": {
        "allow_processes": ["trainer"], "allow_tools": [], "never_leaves": True}}
    watcher = breach.Watcher(root, store, policy, audit_path=os.path.join(meta, "audit.jsonl"),
                             evidence_path=os.path.join(meta, "evidence.jsonl"))
    trainer = intruder = None
    try:
        watcher.start()
        trainer = _hold("trainer", asset)
        trainer_trip = watcher.wait_for(lambda: bool(watcher.events), 0.4)
        trainer.kill()
        intruder = _hold("bash", asset)
        intruder_trip = watcher.wait_for(lambda: bool(watcher.events), 2)
        comm = watcher.events[0]["process"]["comm"] if watcher.events else None
        return _row((not trainer_trip) and intruder_trip and comm == "bash",
                    "trainer tripped %s, other comm %r tripped %s" % (
                        trainer_trip, comm, intruder_trip))
    finally:
        for proc in (trainer, intruder):
            if proc is not None:
                proc.kill()
        watcher.stop()
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(meta, ignore_errors=True)


def _probe_sibling_lock():
    box = _decoy_box(content=False)
    try:
        os.makedirs(os.path.join(box["root"], "models"))
        sibling = os.path.join(box["root"], "models", "weights.bin")
        with open(sibling, "wb") as handle:
            handle.write(b"crown jewel\n")
        os.chmod(sibling, 0o600)
        box["policy"]["siblings"] = {"weights-decoy": ["models/weights.bin"]}
        subprocess.run(["cat", box["path"]], capture_output=True)
        caught = _tripped(box)
        mode = stat.S_IMODE(os.stat(sibling).st_mode)
        return _row(caught and mode == 0o400, "sibling mode %o" % mode)
    finally:
        _stop(box)


_COPY = (
    "import ctypes,os,shutil,sys\n"
    "libc=ctypes.CDLL(None)\n"
    "libc.prctl(15, sys.argv[1].encode(), 0, 0, 0)\n"
    "os.makedirs(os.path.dirname(sys.argv[3]), exist_ok=True)\n"
    "shutil.copy(sys.argv[2], sys.argv[3])\n"
)


def _probe_byte_copy():
    root = tempfile.mkdtemp(prefix="guardian-probe-")
    meta = tempfile.mkdtemp(prefix="guardian-probe-meta-")
    watcher = None
    try:
        asset = os.path.join(root, "models", "weights.bin")
        os.makedirs(os.path.dirname(asset))
        os.makedirs(os.path.join(root, "staged"))
        with open(asset, "wb") as handle:
            handle.write(b"FAKE-WEIGHTS-PRODUCTION\n" + b"xyz" * 30)
        store = path_canaries.load(os.path.join(meta, "paths.json"))
        path_canaries.add_path(store, asset, "production-weights", state=path_canaries.ARMED,
                               role="asset", root=root, content=True)
        path_canaries.save(store, os.path.join(meta, "paths.json"))
        policy = breach.empty_policy()
        policy["root"] = root
        policy["assets"] = {"production-weights": {
            "allow_processes": ["trainer"], "allow_tools": [], "never_leaves": True}}
        watcher = breach.Watcher(root, store, policy, audit_path=os.path.join(meta, "audit.jsonl"),
                                 evidence_path=os.path.join(meta, "evidence.jsonl"))
        watcher.start()
        # The reader is allowlisted. The copy is still a violation of never-leaves.
        copy = os.path.join(root, "staged", "weights.bin")
        subprocess.run([sys.executable, "-c", _COPY, "trainer", asset, copy],
                       capture_output=True, timeout=5)
        caught = watcher.wait_for(
            lambda: any("copy" in (e.get("reason") or "") for e in watcher.events), 2)
        copy_gone = not os.path.exists(copy)
        return _row(caught and copy_gone,
                    "allowlisted writer, copy tripped %s, copy still present %s" % (
                        caught, os.path.exists(copy)))
    finally:
        if watcher is not None:
            watcher.stop()
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(meta, ignore_errors=True)


def _probe_tool_names_path():
    root = tempfile.mkdtemp(prefix="guardian-probe-")
    try:
        path = os.path.join(root, "decoys", "a.env")
        path_canaries.write_decoy(path, "env")
        store = path_canaries.load(os.path.join(root, "missing-path.json"))
        path_canaries.add_path(store, path, "env-decoy", state=path_canaries.ARMED,
                               role="decoy", root=root)
        policy = breach.empty_policy()
        policy["root"] = root
        read = path_canaries.hits_in_call(store, {"file_path": path}, policy, tool_name="Read")
        bash = path_canaries.hits_in_call(
            store, {"command": "cp %s /tmp/out" % path}, policy, tool_name="Bash")
        saved = os.path.join(root, "paths.json")
        path_canaries.save(store, saved)
        stored = open(saved, encoding="utf-8").read()
        return _row(bool(read) and bool(bash) and path not in stored,
                    "Read %s, Bash %s, path stored %s" % (bool(read), bool(bash), path in stored))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _probe_tool_omits_path():
    root = tempfile.mkdtemp(prefix="guardian-probe-")
    try:
        path = os.path.join(root, "decoys", "a.env")
        path_canaries.write_decoy(path, "env")
        store = path_canaries.load(os.path.join(root, "missing-path.json"))
        path_canaries.add_path(store, path, "env-decoy", state=path_canaries.ARMED,
                               role="decoy", root=root)
        policy = breach.empty_policy()
        policy["root"] = root
        # The command does not contain the path. The tool layer cannot see it.
        # The watcher still sees the open when the command actually runs.
        hits = path_canaries.hits_in_call(
            store, {"command": "cat $(printf '%s' \"$UNSET\")"}, policy, tool_name="Bash")
        return _row(not hits, "a command that does not contain the path matched %d candidates" % len(hits))
    finally:
        shutil.rmtree(root, ignore_errors=True)
