"""Where a sentinel may listen, and what a drill mark does to a sighting.

A public address is refused before a socket exists. An RFC1918 address is the
operator's choice for an isolated lab. 127.0.0.1 still serves nothing.

    python3 tests/test_sentinel_bind.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardian_sensor import breach, hub  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print("%s %s%s" % ("ok  " if condition else "FAIL", name, "" if condition else "  <- " + detail))
    if not condition:
        failures.append(name)


def test_public_and_wildcard_binds_are_refused():
    wildcard = ".".join(("0", "0", "0", "0"))
    empty = "x"[:0]
    for host in (wildcard, "8.8.8.8", "1.1.1.1", "169.254.1.1", "::1", "evil.test", empty):
        try:
            breach.Sentinel(host=host, port=0)
        except breach.BreachError:
            check("refused %r" % host, True)
        else:
            check("refused %r" % host, False, "the socket was created")


def test_rfc1918_passes_the_policy_check():
    """10.254.254.9 is not assigned here. Passing the policy check raises OSError on bind."""
    try:
        sentinel = breach.Sentinel(host="10.254.254.9", port=0)
    except breach.BreachError as exc:
        check("rfc1918 is not refused as a public address", False, str(exc))
        return
    except OSError:
        check("rfc1918 is not refused as a public address", True)
        return
    sentinel._sock.close()
    check("rfc1918 is not refused as a public address", True)


def test_policy_file_rejects_a_public_sentinel():
    folder = tempfile.mkdtemp(prefix="guardian-sentinel-")
    path = os.path.join(folder, "policy.json")
    try:
        policy = breach.empty_policy()
        policy["sentinel"]["host"] = "8.8.8.8"
        breach.save_policy(policy, path)
        try:
            breach.load_policy(path)
        except breach.BreachError:
            check("a saved public sentinel is refused", True)
        else:
            check("a saved public sentinel is refused", False)
        policy["sentinel"]["host"] = "10.9.9.9"
        breach.save_policy(policy, path)
        loaded = breach.load_policy(path)
        check("a saved rfc1918 sentinel loads", loaded["sentinel"]["host"] == "10.9.9.9")
    finally:
        os.remove(path)
        os.rmdir(folder)


def test_loopback_still_serves_nothing():
    sentinel = breach.Sentinel(host="127.0.0.1", port=0, on_connect=lambda event: seen.append(event))
    seen = []
    sentinel.start()
    try:
        import socket
        conn = socket.create_connection(("127.0.0.1", sentinel.port), timeout=2)
        payload = conn.recv(16)
        conn.close()
        deadline = __import__("time").time() + 2
        while not seen and __import__("time").time() < deadline:
            __import__("time").sleep(0.02)
        check("loopback callback fired", len(seen) == 1)
        check("loopback served no bytes", payload == b"")
    finally:
        sentinel.stop()


def test_a_drill_mark_is_the_sighting_source():
    record = breach.write_evidence(
        os.path.join(tempfile.mkdtemp(prefix="guardian-drill-"), "evidence.jsonl"),
        ["GP-0041"], "blocked", {"label": "lab", "via": "watcher"}, drill=True)
    # The value and the path are not fields the hub reads. Put a fake in detail
    # and require it to be absent from the document.
    record["detail"]["canary"] = "ak_live_notreally"
    document = hub.build_sightings([record], "lab-host", "b" + "a" * 12)
    encoded = __import__("json").dumps(document)
    check("drill evidence is source drill", document["sightings"][0]["source"] == "drill")
    check("the detail did not leave", "ak_live_notreally" not in encoded)
    check("the pattern is the only one", document["sightings"][0]["pattern"] == "GP-0041")


def main():
    test_public_and_wildcard_binds_are_refused()
    test_rfc1918_passes_the_policy_check()
    test_policy_file_rejects_a_public_sentinel()
    test_loopback_still_serves_nothing()
    test_a_drill_mark_is_the_sighting_source()
    print()
    if failures:
        print("FAIL (%d): %s" % (len(failures), ", ".join(failures)))
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
