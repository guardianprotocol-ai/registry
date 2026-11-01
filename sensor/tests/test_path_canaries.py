"""Path canaries, seeded records, and real-asset policy.

The path is never stored. A seeded value is stored only as a digest. A filler row is
not a canary. An asset is enforced by the allowlist, and a destination outside the
sandbox is a trip even when the tool is allowed. Quarantine refuses to follow a path
out of the root.

Run from the sensor folder:  python3 tests/test_path_canaries.py
"""
import io
import json
import os
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from guardian_sensor import breach, canaries, canary_cli, path_canaries, sensor  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print("%s %s%s" % ("ok  " if condition else "FAIL", name, "" if condition else "  <- " + detail))
    if not condition:
        failures.append(name)


def test_the_path_is_not_stored():
    with tempfile.TemporaryDirectory() as root:
        path = os.path.join(root, "decoys", "a.env")
        _fields, token, digest = path_canaries.write_decoy(path, "env")
        store = path_canaries.load(os.path.join(root, "missing.json"))
        path_canaries.add_path(store, path, "env-decoy", state=path_canaries.ARMED,
                               role="decoy", root=root)
        saved = path_canaries.save(store, os.path.join(root, "paths.json"))
        raw = open(saved, encoding="utf-8").read()
        file_hash, _size = path_canaries.hash_file(path)
        check("the path is absent from the file", path not in raw)
        check("the decoy token is absent from the file", token not in raw)
        check("write_decoy returns a digest of the bytes it wrote", digest == file_hash)
        check("the label is present", "env-decoy" in raw)
        check("the file is owner only", stat.S_IMODE(os.stat(saved).st_mode) == 0o600)


def test_a_label_that_contains_the_path_is_refused():
    with tempfile.TemporaryDirectory() as root:
        path = os.path.join(root, "note.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("ordinary\n")
        store = path_canaries.load(os.path.join(root, "missing.json"))
        try:
            path_canaries.add_path(store, path, "watch " + os.path.abspath(path), root=root)
            check("a label containing the path is refused", False)
        except path_canaries.PathCanaryError:
            check("a label containing the path is refused", True)


def test_a_path_outside_the_root_is_refused():
    with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
        path = os.path.join(outside, "secret.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("leave me\n")
        store = path_canaries.load(os.path.join(root, "missing.json"))
        try:
            path_canaries.add_path(store, path, "outside", root=root)
            check("a path that resolves outside the root is refused", False)
        except path_canaries.PathCanaryError:
            check("a path that resolves outside the root is refused", True)


def test_decoy_refuses_to_overwrite_and_the_ssh_body_is_fake():
    with tempfile.TemporaryDirectory() as root:
        path = os.path.join(root, "id_ed25519")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("already here\n")
        try:
            path_canaries.write_decoy(path, "ssh")
            check("write_decoy refuses to overwrite", False)
        except path_canaries.PathCanaryError:
            check("write_decoy refuses to overwrite", True)
        check("the existing file was left as it was", open(path, encoding="utf-8").read() == "already here\n")
        fresh = os.path.join(root, "fresh_key")
        path_canaries.write_decoy(fresh, "ssh")
        body = open(fresh, encoding="utf-8").read()
        check("the ssh decoy says it is not a key", "FAKE NOT A KEY" in body)
        check("the ssh decoy uses the private-key header", "BEGIN OPENSSH PRIVATE KEY" in body)


def test_seeded_rows_match_and_filler_rows_do_not():
    with tempfile.TemporaryDirectory() as root:
        for fmt in ("csv", "sqlite"):
            dataset = os.path.join(root, "customers." + ("csv" if fmt == "csv" else "sqlite"))
            seeded = path_canaries.write_seed_dataset(dataset, fmt, "customers")
            text = path_canaries.text_of_file(dataset)
            values = canaries.load(os.path.join(root, "values-%s.json" % fmt))
            path_canaries.register_seeds(values, seeded, canaries.ARMED)
            saved = canaries.save(values, os.path.join(root, "values-%s.json" % fmt))
            raw = open(saved, encoding="utf-8").read()
            for value, label, _column in seeded:
                check("%s seeded value is in the dataset" % fmt, value in text)
                check("%s seeded value is not in the canary file" % fmt, value not in raw)
                hits = canaries.matches(values, text)
                check("%s seeded label matches" % fmt, label in [hit["label"] for hit in hits], label)
            filler = "customer_id,name\ncus_filler0001,Filler Row\n"
            check("%s filler text does not match" % fmt, canaries.matches(values, filler) == [])
            check("%s dataset names Avery Lang" % fmt, "Avery Lang" in text)


def test_tool_calls_name_decoys_and_obey_asset_policy():
    with tempfile.TemporaryDirectory() as root:
        decoy = os.path.join(root, "decoys", "a.env")
        path_canaries.write_decoy(decoy, "env")
        asset = os.path.join(root, "models", "weights.bin")
        os.makedirs(os.path.dirname(asset))
        with open(asset, "wb") as handle:
            handle.write(b"FAKE-WEIGHTS\n")
        dataset = os.path.join(root, "data", "customers.csv")
        path_canaries.write_seed_dataset(dataset, "csv", "customers")
        store = path_canaries.load(os.path.join(root, "missing.json"))
        path_canaries.add_path(store, decoy, "env-decoy", state=path_canaries.ARMED,
                               role="decoy", root=root)
        path_canaries.add_path(store, asset, "production-weights", state=path_canaries.ARMED,
                               role="asset", root=root, content=True)
        path_canaries.add_path(store, dataset, "customers-file", state=path_canaries.ARMED,
                               role="seed-home", root=root)
        policy = breach.empty_policy()
        policy["root"] = root
        policy["assets"] = {"production-weights": {
            "allow_processes": ["trainer"], "allow_tools": ["Read"], "never_leaves": True}}
        read = path_canaries.hits_in_call(store, {"file_path": decoy}, policy, tool_name="Read")
        bash = path_canaries.hits_in_call(
            store, {"command": "cp %s /tmp/out" % decoy}, policy, tool_name="Bash")
        hidden = path_canaries.hits_in_call(
            store, {"command": "cat $(printf '%s' \"$UNSET\")"}, policy, tool_name="Bash")
        home = path_canaries.hits_in_call(
            store, {"file_path": dataset}, policy, tool_name="Read")
        allowed = path_canaries.hits_in_call(
            store, {"file_path": asset}, policy, tool_name="Read")
        denied = path_canaries.hits_in_call(
            store, {"file_path": asset}, policy, tool_name="Bash")
        leaving = path_canaries.hits_in_call(
            store, {"file_path": asset, "url": "http://export.example.test/take"},
            policy, tool_name="Read")
        check("Read of a decoy matches", [hit["label"] for hit in read] == ["env-decoy"])
        check("Bash that names a decoy matches", bool(bash))
        check("a command that hides the path matches nothing", hidden == [])
        check("naming the seed file is not itself a trip", home == [])
        check("an allowlisted tool may read the asset", allowed == [])
        check("a tool that is not allowlisted trips on the asset", bool(denied))
        check("an allowlisted tool that names an outside URL still trips", bool(leaving))


def test_quarantine_does_not_follow_a_path_out_of_the_root():
    with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
        victim = os.path.join(outside, "victim.txt")
        with open(victim, "w", encoding="utf-8") as handle:
            handle.write("leave this alone\n")
        os.chmod(victim, 0o600)
        before = os.stat(victim).st_mode
        policy = breach.empty_policy()
        policy["root"] = root
        policy["siblings"] = {"d": ["nope/../../etc/passwd"]}
        record = breach.contain(policy, {
            "label": "d", "state": path_canaries.ARMED, "role": "asset",
            "kind": "path", "access_path": victim,
        }, reason="probe")
        check("an outside file is not moved", record["action"] == "refused", record["action"])
        check("the outside file's mode is unchanged", os.stat(victim).st_mode == before)
        check("a sibling with .. is refused", record["siblings"][0]["action"] == "refused")


def _sensor(workdir, store_path, policy_path, values_path=None):
    cfg = {
        "mode": "block",
        "allowlist": ["example.test"],
        "pins_path": os.path.join(workdir, "pins.json"),
        "evidence_path": os.path.join(workdir, "evidence.jsonl"),
        "canaries_path": values_path or os.path.join(workdir, "no-values.json"),
        "path_canaries_path": store_path,
        "breach_policy_path": policy_path,
    }
    return sensor.Sensor(cfg)


def _call(instance, name, arguments):
    return instance.inspect_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })


def test_baseline_path_canary_does_not_block_and_an_armed_one_uses_the_uniform_refusal():
    with tempfile.TemporaryDirectory() as root:
        decoy = os.path.join(root, "decoy.bin")
        path_canaries.write_decoy(decoy, "weights")
        other = os.path.join(root, "other.bin")
        path_canaries.write_decoy(other, "weights")
        store_path = os.path.join(root, "paths.json")
        store = path_canaries.load(os.path.join(root, "missing.json"))
        path_canaries.add_path(store, decoy, "weights-decoy", state=path_canaries.BASELINE,
                               role="decoy", root=root)
        path_canaries.add_path(store, other, "other-decoy", state=path_canaries.BASELINE,
                               role="decoy", root=root)
        path_canaries.save(store, store_path)
        policy = breach.empty_policy()
        policy["root"] = root
        policy_path = breach.save_policy(policy, os.path.join(root, "policy.json"))
        instance = _sensor(root, store_path, policy_path)
        reply = _call(instance, "Read", {"file_path": decoy})
        check("two baseline path canaries do not block", reply is None, str(reply))
        evidence = open(instance.cfg["evidence_path"], encoding="utf-8").read()
        check("baseline is flagged", '"flagged"' in evidence, evidence)
        path_canaries.arm(store, "weights-decoy")
        path_canaries.save(store, store_path)
        armed = _sensor(root, store_path, policy_path)
        reply = _call(armed, "Read", {"file_path": decoy})
        text = reply["result"]["content"][0]["text"]
        check("an armed path canary blocks", reply["result"]["isError"] is True)
        check("the refusal is the uniform text", text == sensor.REFUSAL, text)
        check("the refusal does not name the label", "weights-decoy" not in text)
        check("the refusal does not contain the path", decoy not in text)
        check("the refusal does not name the pattern", "GP-0041" not in text)
        evidence = open(armed.cfg["evidence_path"], encoding="utf-8").read()
        check("evidence names the pattern and the label",
              "GP-0041" in evidence and "weights-decoy" in evidence)
        check("the decoy was quarantined", not os.path.exists(decoy))


def test_a_seeded_value_in_a_tool_call_locks_the_dataset_and_hides_the_value():
    with tempfile.TemporaryDirectory() as root:
        dataset = os.path.join(root, "data", "customers.csv")
        seeded = path_canaries.write_seed_dataset(dataset, "csv", "customers")
        values_path = os.path.join(root, "values.json")
        values = canaries.load(os.path.join(root, "missing-values.json"))
        entries = path_canaries.register_seeds(values, seeded, canaries.ARMED)
        canaries.save(values, values_path)
        store_path = os.path.join(root, "paths.json")
        store = path_canaries.load(os.path.join(root, "missing.json"))
        home = path_canaries.add_path(store, dataset, "customers-file", state=path_canaries.ARMED,
                                      role="seed-home", root=root)
        path_canaries.save(store, store_path)
        policy = breach.empty_policy()
        policy["root"] = root
        for entry in entries:
            policy["seeds"][entry["label"]] = home["label"]
        policy_path = breach.save_policy(policy, os.path.join(root, "policy.json"))
        instance = _sensor(root, store_path, policy_path, values_path)
        planted = next(value for value, label, _column in seeded if label.endswith("marker"))
        reply = _call(instance, "send_message", {"to": "ops@example.test", "body": "key " + planted})
        text = reply["result"]["content"][0]["text"]
        evidence = open(instance.cfg["evidence_path"], encoding="utf-8").read()
        stored = open(values_path, encoding="utf-8").read()
        check("a seeded value in a tool call blocks", reply["result"]["isError"] is True)
        check("the refusal does not contain the value", planted not in text)
        check("evidence does not contain the value", planted not in evidence, evidence[:400])
        check("the value store does not contain the value", planted not in stored)
        check("evidence records GP-0020", "GP-0020" in evidence)
        check("the dataset was quarantined", not os.path.exists(dataset))


def test_path_canary_end_to_end_does_not_reach_the_sink():
    with tempfile.TemporaryDirectory() as work:
        decoy = os.path.join(work, "decoy.bin")
        path_canaries.write_decoy(decoy, "weights")
        store = path_canaries.load(os.path.join(work, "missing.json"))
        path_canaries.add_path(store, decoy, "weights-decoy", state=path_canaries.ARMED,
                               role="decoy", root=work)
        store_path = path_canaries.save(store, os.path.join(work, "paths.json"))
        policy = breach.empty_policy()
        policy["root"] = work
        policy_path = breach.save_policy(policy, os.path.join(work, "policy.json"))
        cfg = os.path.join(work, "guardian.json")
        with open(cfg, "w", encoding="utf-8") as handle:
            json.dump({
                "mode": "block", "allowlist": ["example.test"],
                "pins_path": os.path.join(work, "pins.json"),
                "evidence_path": os.path.join(work, "evidence.jsonl"),
                "canaries_path": os.path.join(work, "no-values.json"),
                "path_canaries_path": store_path,
                "breach_policy_path": policy_path,
            }, handle)
        sink = os.path.join(work, "sink.jsonl")
        env = {**os.environ, "PYTHONPATH": ROOT, "GUARDIAN_SINK": sink}
        cmd = [sys.executable, "-m", "guardian_sensor", "--config", cfg, "--",
               sys.executable, os.path.join(HERE, "fake_server.py")]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, bufsize=1, env=env, cwd=work)
        n = [0]

        def call(method, params=None):
            n[0] += 1
            proc.stdin.write(json.dumps({
                "jsonrpc": "2.0", "id": n[0], "method": method, "params": params or {},
            }) + "\n")
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())

        try:
            call("initialize")
            call("tools/list")
            reply = call("tools/call", {"name": "send_message", "arguments": {
                "to": "team@example.test", "body": decoy}})
        finally:
            proc.stdin.close()
            stderr = proc.stderr.read()
            proc.wait(timeout=10)
        text = ((reply.get("result") or {}).get("content") or [{}])[0].get("text", "")
        evidence_path = os.path.join(work, "evidence.jsonl")
        evidence = open(evidence_path, encoding="utf-8").read() if os.path.exists(evidence_path) else ""
        if not evidence:
            check("the proxy wrote evidence", False, stderr[-500:])
        leaked = os.path.exists(sink) and decoy in open(sink, encoding="utf-8").read()
        check("the proxy blocks the call", (reply.get("result") or {}).get("isError") is True, str(reply))
        check("the proxy refusal does not name the decoy", "weights-decoy" not in text and decoy not in text, text)
        check("the path did not reach the sink", not leaked)
        check("evidence records GP-0041 without the value of a weights file",
              "GP-0041" in evidence and "FAKE-WEIGHTS" not in evidence)


def _quarantine(root, path, entry):
    policy = breach.empty_policy()
    policy["root"] = root
    policy["response"] = breach.RESPONSE_QUARANTINE
    hit = dict(entry)
    hit["access_path"] = path
    return breach.contain(policy, hit, reason="read")


def test_add_file_default_role_keeps_real_bytes():
    with tempfile.TemporaryDirectory() as root:
        path = os.path.join(root, "models", "real.bin")
        os.makedirs(os.path.dirname(path))
        body = b"real-weights-not-bait\n"
        with open(path, "wb") as handle:
            handle.write(body)
        os.chmod(path, 0o600)
        paths = os.path.join(root, "paths.json")
        policy_path = os.path.join(root, "policy.json")
        rc = canary_cli.add_file([
            path, "--label", "myweights", "--armed", "--root", root,
            "--paths", paths, "--policy", policy_path,
        ], out=io.StringIO())
        check("add-file succeeds", rc == 0)
        store = path_canaries.load(paths)
        entry = path_canaries.by_label(store, "myweights")
        check("the default role is asset", entry is not None and entry["role"] == "asset",
              str(entry))
        record = _quarantine(root, path, entry)
        moved = record["moved_to"]
        check("the real file was moved", bool(moved) and os.path.isfile(moved), record["action"])
        check("real bytes survived the default role", open(moved, "rb").read() == body)


def test_a_hard_link_to_a_real_file_is_not_truncated():
    with tempfile.TemporaryDirectory() as root:
        real = os.path.join(root, "models", "real.bin")
        os.makedirs(os.path.dirname(real))
        body = b"crown-jewel-bytes\n"
        with open(real, "wb") as handle:
            handle.write(body)
        os.chmod(real, 0o600)
        decoy = os.path.join(root, "decoys", "weights.bin")
        _fields, _token, digest = path_canaries.write_decoy(decoy, "weights")
        os.remove(decoy)
        os.link(real, decoy)
        store = path_canaries.load(os.path.join(root, "missing.json"))
        entry = path_canaries.add_path(
            store, decoy, "weights-decoy", state=path_canaries.ARMED, role="decoy",
            root=root, decoy_hash=digest)
        record = _quarantine(root, decoy, entry)
        check("the real file still has its bytes", open(real, "rb").read() == body)
        moved = record["moved_to"]
        check("the quarantined name was not emptied",
              bool(moved) and os.path.isfile(moved) and open(moved, "rb").read() == body,
              record["action"])


def test_a_lone_decoy_that_still_matches_is_emptied():
    with tempfile.TemporaryDirectory() as root:
        decoy = os.path.join(root, "decoys", "weights.bin")
        _fields, _token, digest = path_canaries.write_decoy(decoy, "weights")
        store = path_canaries.load(os.path.join(root, "missing.json"))
        entry = path_canaries.add_path(
            store, decoy, "weights-decoy", state=path_canaries.ARMED, role="decoy",
            root=root, decoy_hash=digest)
        record = _quarantine(root, decoy, entry)
        moved = record["moved_to"]
        check("a matching single-link decoy is emptied",
              bool(moved) and os.path.isfile(moved) and open(moved, "rb").read() == b"",
              record["action"])


def main():
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print()
    if failures:
        print("FAIL (%d): %s" % (len(failures), ", ".join(failures)))
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
