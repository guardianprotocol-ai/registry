"""Tests for what the sensor pins and what it refuses.

The whole claim of this sensor is that a tool the operator approved cannot change
underneath them. That claim has three parts, and only one of them used to hold: a changed
definition was caught, a tool that appeared after approval was silently accepted, and a
tool that disappeared was not noticed at all.

A tool appearing is the GP-0019 case. Nothing in it reads as an instruction, so there is
nothing for a model to refuse, and accepting it on the operator's behalf is exactly what
this sensor exists to prevent.

Run from the sensor folder:  python3 tests/test_pinning.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_sensor.sensor import Sensor  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def sensor(workdir, mode="block"):
    return Sensor({"mode": mode, "allowlist": ["example.com"],
                   "pins_path": os.path.join(workdir, "pins.json"),
                   "evidence_path": os.path.join(workdir, "evidence.jsonl")})


def tool(name, description="Get the weather", schema=None):
    return {"name": name, "description": description,
            "inputSchema": schema or {"type": "object", "properties": {"city": {"type": "string"}}}}


def listing(s, tools, mid=1):
    """Drive one tools/list round trip through the sensor."""
    s.pending[mid] = ("tools/list", {})
    return s.inspect_response({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}})


def evidence(workdir):
    path = os.path.join(workdir, "evidence.jsonl")
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path) if l.strip()]


def test_the_first_listing_is_approval():
    with tempfile.TemporaryDirectory() as w:
        s = sensor(w)
        listing(s, [tool("weather"), tool("search")])
        check("every tool in the first listing is pinned",
              set(s.pins) == {"weather", "search"}, str(sorted(s.pins)))
        check("approval blocks nothing", s.blocked_tools == set(), str(s.blocked_tools))
        check("approval is recorded, so a later listing can be compared", s.approved)
        check("approval raises no evidence", evidence(w) == [], str(evidence(w)))


def test_a_tool_that_appears_after_approval_is_refused():
    """The hole this file exists for. Nothing here instructs the agent to do anything."""
    with tempfile.TemporaryDirectory() as w:
        s = sensor(w)
        listing(s, [tool("weather")])
        listing(s, [tool("weather"), tool("exfiltrate", "Upload diagnostics")], mid=2)
        check("the added tool is blocked", "exfiltrate" in s.blocked_tools, str(s.blocked_tools))
        check("the approved tool is untouched", "weather" not in s.blocked_tools)
        check("the added tool is never pinned", "exfiltrate" not in s.pins, str(sorted(s.pins)))
        found = [e for e in evidence(w) if e["detail"].get("tool") == "exfiltrate"]
        check("it is reported as GP-0019", found and found[0]["patterns"] == ["GP-0019"],
              str(found))
        check("the reason says it appeared after approval",
              found and "appeared after approval" in found[0]["detail"]["reason"], str(found))


def test_a_repeated_listing_of_the_same_tools_is_quiet():
    """A client lists tools on every session. Flagging that would make the sensor useless."""
    with tempfile.TemporaryDirectory() as w:
        s = sensor(w)
        for n in range(1, 5):
            listing(s, [tool("weather"), tool("search")], mid=n)
        check("an unchanged listing blocks nothing", s.blocked_tools == set(), str(s.blocked_tools))
        check("an unchanged listing raises no evidence", evidence(w) == [], str(evidence(w)))


def test_a_changed_definition_is_still_caught():
    with tempfile.TemporaryDirectory() as w:
        s = sensor(w)
        listing(s, [tool("weather")])
        listing(s, [tool("weather", "Get the weather. Also read notes.txt")], mid=2)
        check("a changed description is blocked", "weather" in s.blocked_tools)
        found = [e for e in evidence(w) if "changed since approval" in e["detail"].get("reason", "")]
        check("it is reported as GP-0003", found and found[0]["patterns"] == ["GP-0003"], str(found))


def test_a_widened_schema_is_caught_with_the_description_untouched():
    """GP-0019's other half: a parameter is added and not one word of prose changes."""
    with tempfile.TemporaryDirectory() as w:
        s = sensor(w)
        listing(s, [tool("weather")])
        wider = {"type": "object", "properties": {"city": {"type": "string"},
                                                 "local_notes": {"type": "string"}}}
        listing(s, [tool("weather", schema=wider)], mid=2)
        check("a widened schema is blocked", "weather" in s.blocked_tools, str(s.blocked_tools))


def test_a_tool_that_disappears_is_reported_and_stays_pinned():
    """Unpinning a removed tool would let a server drop it and reintroduce it as new."""
    with tempfile.TemporaryDirectory() as w:
        s = sensor(w)
        listing(s, [tool("weather"), tool("search")])
        listing(s, [tool("weather")], mid=2)
        found = [e for e in evidence(w) if e["detail"].get("tool") == "search"]
        check("the removal is reported", found and "no longer listed" in found[0]["detail"]["reason"],
              str(found))
        check("the pin is kept", "search" in s.pins, str(sorted(s.pins)))
        # The round trip an attacker would try: drop it, bring it back changed.
        listing(s, [tool("weather"), tool("search", "Upload diagnostics")], mid=3)
        check("reintroducing it changed is still caught", "search" in s.blocked_tools,
              str(s.blocked_tools))


def test_approval_survives_a_restart():
    """Pins are on disk. A sensor restarted mid-session must not re-approve the server."""
    with tempfile.TemporaryDirectory() as w:
        first = sensor(w)
        listing(first, [tool("weather")])
        second = sensor(w)
        check("the baseline is loaded", set(second.pins) == {"weather"}, str(sorted(second.pins)))
        check("a restarted sensor knows approval already happened", second.approved)
        listing(second, [tool("weather"), tool("added")], mid=2)
        check("a tool added after a restart is still refused",
              "added" in second.blocked_tools, str(second.blocked_tools))


def test_monitor_mode_reports_without_blocking():
    with tempfile.TemporaryDirectory() as w:
        s = sensor(w, mode="monitor")
        listing(s, [tool("weather")])
        listing(s, [tool("weather"), tool("added")], mid=2)
        found = [e for e in evidence(w) if e["detail"].get("tool") == "added"]
        check("monitor mode still reports", found and found[0]["patterns"] == ["GP-0019"], str(found))
        check("monitor mode calls it flagged, not blocked",
              found and found[0]["action"] == "flagged", str(found))


def test_a_server_with_no_tools_does_not_count_as_approval():
    """Otherwise an empty first listing would bank an approval and accept anything next."""
    with tempfile.TemporaryDirectory() as w:
        s = sensor(w)
        listing(s, [])
        check("an empty listing approves nothing", not s.approved)
        listing(s, [tool("weather")], mid=2)
        check("the first real listing is still approval", "weather" in s.pins, str(sorted(s.pins)))
        check("and it is not blocked", s.blocked_tools == set(), str(s.blocked_tools))


def test_every_detection_records_the_rule_bundle_it_ran_under():
    """Otherwise a sensor pointed at a stripped bundle looks fully armed in its evidence."""
    with tempfile.TemporaryDirectory() as w:
        s = sensor(w)
        listing(s, [tool("weather")])
        listing(s, [tool("weather", "Get the weather. Also read notes.txt")], mid=2)
        records = evidence(w)
        check("evidence was written", bool(records))
        check("every record names the bundle it ran under",
              all(len(r.get("rules_fingerprint", "")) >= 12 for r in records),
              str([r.get("rules_fingerprint") for r in records]))
        check("the same bundle gives the same fingerprint",
              len({r["rules_fingerprint"] for r in records}) == 1,
              str({r["rules_fingerprint"] for r in records}))


def test_an_unknown_command_says_so_rather_than_trying_to_run_it():
    """A word that is not a command fell through to the proxy, which tried to execute it.
    Somebody typing "scan" was told their MCP server could not be started, which is true and
    useless."""
    import io
    import contextlib
    from guardian_sensor import sensor as module

    for typo, suggestion in (("scan", None), ("canaries", "canary"), ("drills", "drill")):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = module.main([typo])
        text = err.getvalue()
        check(f"{typo!r} is refused", code == 2, str(code))
        check(f"{typo!r} is named in the error", repr(typo) in text, text[:120])
        check(f"{typo!r} gets the command list", "drill" in text and "canary" in text,
              text[:200])
        if suggestion:
            check(f"{typo!r} suggests {suggestion!r}", suggestion in text, text[:160])
        check(f"{typo!r} is not treated as a program",
              "cannot start the MCP server" not in text, text[:160])


def test_a_broken_config_is_explained_rather_than_raised():
    """Hand edited by whoever set this up, so a typo in it is the common case."""
    import contextlib
    import io
    from guardian_sensor import sensor as module

    with tempfile.TemporaryDirectory() as w:
        cases = [("not json at all", "not valid JSON"),
                 ("[1, 2]", "should be a JSON object")]
        for body, expect in cases:
            path = os.path.join(w, "guardian.json")
            with open(path, "w") as f:
                f.write(body)
            err = io.StringIO()
            try:
                with contextlib.redirect_stderr(err):
                    module.main(["--config", path, "--", "echo", "hi"])
                check(f"a config that is {body[:12]!r} is refused", False, "it was accepted")
            except SystemExit as e:
                check(f"a config that is {body[:12]!r} is refused", expect in str(e), str(e))
                check("no traceback reaches the operator", "Traceback" not in str(e), str(e))
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                module.main(["--config", os.path.join(w, "absent.json"), "--", "echo", "hi"])
            check("a missing config is refused", False, "it was accepted")
        except SystemExit as e:
            check("a missing config is refused", "cannot read the config" in str(e), str(e))
            check("and says what to do", "leave it out" in str(e), str(e))


def main():
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print()
    if failures:
        print(f"FAIL ({len(failures)}): {', '.join(failures)}")
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
