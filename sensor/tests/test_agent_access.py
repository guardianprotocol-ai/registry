"""Agent identity and access: token, directory and host posture, checked before a
tools/call is forwarded.

Synthetic issuers, secrets and agents only. No identity provider, no network.

Run from the sensor/ folder:  python3 tests/test_agent_access.py
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from guardian_sensor import agent_access  # noqa: E402
from guardian_sensor.agent_access import encode_hs256  # noqa: E402
from guardian_sensor.sensor import REFUSAL, Sensor  # noqa: E402

ISSUER = "https://idp.example.test"
OTHER_ISSUER = "https://other-idp.example.test"
AUDIENCE = "guardian-sensor:lab"
SECRET = "issuer-secret-for-tests-only-0123456789abcdef"
POSTURE_SECRET = "posture-secret-for-tests-only-0123456789abcdef"
NOW = 1_800_000_000


def call(name, arguments=None, mid=1):
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}}}


class Fixture:
    """A temporary host: secrets, a directory with one agent, a token and an attestation."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.path = lambda *p: os.path.join(tmp, *p)
        self.write("issuer.key", SECRET)
        self.write("posture.key", POSTURE_SECRET)
        self.directory = self.path("agents.json")
        agent_access.provision(self.directory, "agent-1", ISSUER, "agent:build-bot")
        self.set_token()
        self.set_attestation()

    def write(self, name, text):
        with open(self.path(name), "w") as f:
            f.write(text)

    def claims(self, **over):
        claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "agent:build-bot",
                  "iat": NOW - 10, "exp": NOW + 600}
        claims.update(over)
        return {k: v for k, v in claims.items() if v is not None}

    def set_token(self, secret=SECRET, **over):
        self.write("token", encode_hs256(self.claims(**over), secret))

    def set_attestation(self, secret=POSTURE_SECRET, **over):
        claims = {"host": "build-host-1", "iat": NOW - 30, "posture": "pass",
                  "checks": {"disk_encrypted": True, "os_patched": True}}
        claims.update(over)
        self.write("posture.jwt", encode_hs256(claims, secret))

    def config(self, **over):
        access = {
            "token_path": self.path("token"),
            "audience": AUDIENCE,
            "issuers": [{"issuer": ISSUER, "secret_path": self.path("issuer.key")}],
            "directory_path": self.directory,
            "log_path": self.path("access.jsonl"),
            "posture": {"attestation_path": self.path("posture.jwt"),
                        "secret_path": self.path("posture.key"),
                        "max_age_seconds": 300, "host": "build-host-1"},
        }
        access.update(over)
        return {"mode": "block", "allowlist": ["example.com"],
                "pins_path": self.path("pins.json"),
                "evidence_path": self.path("evidence.jsonl"),
                "canaries_path": self.path("canaries.json"),
                "path_canaries_path": self.path("path-canaries.json"),
                "breach_policy_path": self.path("breach-policy.json"),
                "agent_access": access}

    def sensor(self, **over):
        s = Sensor(self.config(**over))
        s.access.clock = lambda: NOW
        return s

    def log(self):
        with open(self.path("access.jsonl")) as f:
            return [json.loads(line) for line in f]


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.fx = Fixture(tmp.name)

    def assertForwarded(self, sensor, msg):
        self.assertIsNone(sensor.inspect_request(msg), sensor.access and self.fx.log()[-1])

    def assertDenied(self, sensor, msg, reason=None):
        out = sensor.inspect_request(msg)
        self.assertIsNotNone(out, "call was forwarded")
        self.assertTrue(out["result"]["isError"])
        self.assertEqual(out["result"]["content"][0]["text"], REFUSAL)
        self.assertEqual(out["id"], msg["id"])
        if reason:
            self.assertIn(reason, self.fx.log()[-1]["reason"])


class Tokens(Base):
    def test_valid_token_allows_ordinary_work(self):
        s = self.fx.sensor()
        self.assertForwarded(s, call("read_file", {"path": "notes.txt"}))
        record = self.fx.log()[-1]
        self.assertEqual(record["decision"], "allowed")
        self.assertEqual(record["agent"], "agent-1")
        self.assertFalse(record["sensitive"])

    def test_audience_may_be_a_list(self):
        self.fx.set_token(aud=["someone-else", AUDIENCE])
        self.assertForwarded(self.fx.sensor(), call("read_file"))

    def test_missing_token_denied(self):
        os.unlink(self.fx.path("token"))
        self.assertDenied(self.fx.sensor(), call("read_file"), "no token")

    def test_empty_token_denied(self):
        self.fx.write("token", "")
        self.assertDenied(self.fx.sensor(), call("read_file"), "no token")

    def test_expired_token_denied(self):
        self.fx.set_token(exp=NOW - 120)
        self.assertDenied(self.fx.sensor(), call("read_file"), "expired")

    def test_expiry_within_leeway_still_allowed(self):
        self.fx.set_token(exp=NOW - 30)
        self.assertForwarded(self.fx.sensor(), call("read_file"))

    def test_token_without_expiry_denied(self):
        self.fx.set_token(exp=None)
        self.assertDenied(self.fx.sensor(), call("read_file"), "no exp")

    def test_token_not_yet_valid_denied(self):
        self.fx.set_token(nbf=NOW + 3600)
        self.assertDenied(self.fx.sensor(), call("read_file"), "not yet valid")

    def test_wrong_audience_denied(self):
        self.fx.set_token(aud="guardian-sensor:some-other-server")
        self.assertDenied(self.fx.sensor(), call("read_file"), "audience")

    def test_missing_audience_denied(self):
        self.fx.set_token(aud=None)
        self.assertDenied(self.fx.sensor(), call("read_file"), "audience")

    def test_unknown_issuer_denied(self):
        self.fx.set_token(iss=OTHER_ISSUER)
        self.assertDenied(self.fx.sensor(), call("read_file"), "issuer")

    def test_known_issuer_wrong_key_denied(self):
        self.fx.set_token(secret="an-attacker-chosen-secret-0123456789abcdef")
        self.assertDenied(self.fx.sensor(), call("read_file"), "signature")

    def test_altered_claims_denied(self):
        header, body, sig = open(self.fx.path("token")).read().split(".")
        forged = agent_access._b64url_encode(json.dumps(
            self.fx.claims(sub="agent:someone-else")).encode())
        self.fx.write("token", ".".join([header, forged, sig]))
        self.assertDenied(self.fx.sensor(), call("read_file"), "signature")

    def test_alg_none_denied(self):
        header = agent_access._b64url_encode(b'{"alg":"none","typ":"JWT"}')
        body = agent_access._b64url_encode(json.dumps(self.fx.claims()).encode())
        self.fx.write("token", header + "." + body + ".")
        self.assertDenied(self.fx.sensor(), call("read_file"), "HS256")

    def test_garbage_token_denied(self):
        self.fx.write("token", "not a token at all")
        self.assertDenied(self.fx.sensor(), call("read_file"))

    def test_short_issuer_secret_refused(self):
        self.fx.write("issuer.key", "short")
        self.fx.set_token(secret="short")
        self.assertDenied(self.fx.sensor(), call("read_file"), "shorter")

    def test_token_refreshed_on_disk_is_picked_up(self):
        s = self.fx.sensor()
        self.fx.set_token(exp=NOW - 120)
        self.assertDenied(s, call("read_file"), "expired")
        self.fx.set_token()
        self.assertForwarded(s, call("read_file", mid=2))

    def test_token_never_written_to_the_log(self):
        s = self.fx.sensor()
        s.inspect_request(call("read_file"))
        token = open(self.fx.path("token")).read()
        with open(self.fx.path("access.jsonl")) as f:
            self.assertNotIn(token.split(".")[2], f.read())


class Directory(Base):
    def test_unprovisioned_agent_denied(self):
        self.fx.set_token(sub="agent:never-provisioned")
        self.assertDenied(self.fx.sensor(), call("read_file"), "not provisioned")

    def test_same_subject_from_another_issuer_is_another_agent(self):
        self.fx.write("other.key", SECRET)
        self.fx.set_token(iss=OTHER_ISSUER)
        s = self.fx.sensor(issuers=[
            {"issuer": ISSUER, "secret_path": self.fx.path("issuer.key")},
            {"issuer": OTHER_ISSUER, "secret_path": self.fx.path("other.key")}])
        self.assertDenied(s, call("read_file"), "not provisioned")

    def test_deprovisioned_agent_denied_on_its_next_call(self):
        s = self.fx.sensor()
        self.assertForwarded(s, call("read_file", mid=1))
        agent_access.deprovision(self.fx.directory, "agent-1")
        self.assertDenied(s, call("read_file", mid=2), "deprovisioned")

    def test_deleted_agent_denied_on_its_next_call(self):
        s = self.fx.sensor()
        self.assertForwarded(s, call("read_file", mid=1))
        agent_access.deprovision(self.fx.directory, "agent-1", delete=True)
        self.assertDenied(s, call("read_file", mid=2), "not provisioned")

    def test_reprovisioned_agent_allowed_again(self):
        s = self.fx.sensor()
        agent_access.deprovision(self.fx.directory, "agent-1")
        self.assertDenied(s, call("read_file", mid=1))
        agent_access.provision(self.fx.directory, "agent-1", ISSUER, "agent:build-bot")
        self.assertForwarded(s, call("read_file", mid=2))

    def test_scim_lifecycle(self):
        user = {"schemas": [agent_access.SCIM_USER_SCHEMA], "id": "agent-2",
                "userName": "agent:triage-bot", "active": True,
                "urn:guardianprotocol:agent": {"issuer": ISSUER}}
        agent_access.apply_scim(self.fx.directory, "POST", user)
        self.fx.set_token(sub="agent:triage-bot")
        s = self.fx.sensor()
        self.assertForwarded(s, call("read_file", mid=1))
        agent_access.apply_scim(self.fx.directory, "PATCH", {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}]},
            agent_id="agent-2")
        self.assertDenied(s, call("read_file", mid=2), "deprovisioned")
        agent_access.apply_scim(self.fx.directory, "PATCH", {
            "Operations": [{"op": "replace", "value": {"active": True}}]}, agent_id="agent-2")
        self.assertForwarded(s, call("read_file", mid=3))
        agent_access.apply_scim(self.fx.directory, "DELETE", agent_id="agent-2")
        self.assertDenied(s, call("read_file", mid=4), "not provisioned")

    def test_scim_put_inactive_is_provisioned_but_denied(self):
        agent_access.apply_scim(self.fx.directory, "PUT", {
            "schemas": [agent_access.SCIM_USER_SCHEMA], "id": "agent-1",
            "userName": "agent:build-bot", "active": False,
            "urn:guardianprotocol:agent": {"issuer": ISSUER}})
        self.assertDenied(self.fx.sensor(), call("read_file"), "deprovisioned")

    def test_scim_rejects_what_it_does_not_support(self):
        with self.assertRaises(ValueError):
            agent_access.apply_scim(self.fx.directory, "PATCH", {
                "Operations": [{"op": "add", "path": "emails", "value": []}]},
                agent_id="agent-1")
        with self.assertRaises(ValueError):
            agent_access.apply_scim(self.fx.directory, "POST", {"id": "x"})

    def test_one_subject_cannot_be_given_to_two_agents(self):
        with self.assertRaises(ValueError):
            agent_access.provision(self.fx.directory, "agent-9", ISSUER, "agent:build-bot")

    def test_corrupt_directory_fails_closed(self):
        self.fx.write("agents.json", "{not json")
        self.assertDenied(self.fx.sensor(), call("read_file"), "directory unreadable")

    def test_missing_directory_fails_closed(self):
        os.unlink(self.fx.directory)
        self.assertDenied(self.fx.sensor(), call("read_file"), "directory unreadable")


class Posture(Base):
    def test_sensitive_tool_allowed_with_a_good_attestation(self):
        s = self.fx.sensor()
        self.assertForwarded(s, call("delete_records", {"tag": "q3-export-stale"}))
        self.assertTrue(self.fx.log()[-1]["sensitive"])

    def test_sensitive_tool_denied_without_an_attestation(self):
        os.unlink(self.fx.path("posture.jwt"))
        self.assertDenied(self.fx.sensor(), call("delete_records"), "no attestation")

    def test_sensitive_tool_denied_with_a_stale_attestation(self):
        self.fx.set_attestation(iat=NOW - 3600)
        self.assertDenied(self.fx.sensor(), call("delete_records"), "stale")

    def test_sensitive_tool_denied_with_a_failing_posture(self):
        self.fx.set_attestation(posture="fail")
        self.assertDenied(self.fx.sensor(), call("delete_records"), "not pass")

    def test_sensitive_tool_denied_with_a_failing_check(self):
        self.fx.set_attestation(checks={"disk_encrypted": True, "os_patched": False})
        self.assertDenied(self.fx.sensor(), call("delete_records"), "failing check")

    def test_sensitive_tool_denied_with_a_forged_attestation(self):
        self.fx.set_attestation(secret="not-the-posture-key-0123456789abcdefghij")
        self.assertDenied(self.fx.sensor(), call("delete_records"), "signature")

    def test_attestation_for_another_host_denied(self):
        self.fx.set_attestation(host="some-other-host")
        self.assertDenied(self.fx.sensor(), call("delete_records"), "another host")

    def test_attestation_from_the_future_denied(self):
        self.fx.set_attestation(iat=NOW + 3600)
        self.assertDenied(self.fx.sensor(), call("delete_records"), "future")

    def test_sensitive_tool_denied_when_no_posture_policy(self):
        self.assertDenied(self.fx.sensor(posture={}), call("delete_records"),
                          "no posture policy")

    def test_ordinary_work_flows_with_a_failing_posture(self):
        self.fx.set_attestation(posture="fail")
        s = self.fx.sensor()
        self.assertForwarded(s, call("read_file", {"path": "notes.txt"}, mid=1))
        self.assertForwarded(s, call("weather", {"city": "NYC"}, mid=2))
        self.assertDenied(s, call("delete_records", mid=3), "not pass")

    def test_default_sensitive_set_is_the_rule_engines_tool_classes(self):
        gate = self.fx.sensor().access
        for tool in ("delete_records", "remember", "send_to_agent", "write_file"):
            self.assertTrue(gate.is_sensitive(tool), tool)
        for tool in ("read_file", "weather", "fetch_page", "send_message"):
            self.assertFalse(gate.is_sensitive(tool), tool)

    def test_named_tools_can_be_added_and_classes_narrowed(self):
        gate = self.fx.sensor(sensitive_tools=["send_message"],
                              sensitive_classes=["destructive"]).access
        self.assertTrue(gate.is_sensitive("send_message"))
        self.assertTrue(gate.is_sensitive("delete_records"))
        self.assertFalse(gate.is_sensitive("remember"))


class Proxy(Base):
    def test_off_unless_configured(self):
        cfg = self.fx.config()
        del cfg["agent_access"]
        s = Sensor(cfg)
        self.assertIsNone(s.access)
        self.assertIsNone(s.inspect_request(call("read_file")))

    def test_other_methods_are_not_gated(self):
        os.unlink(self.fx.path("token"))
        s = self.fx.sensor()
        for method in ("initialize", "tools/list", "ping"):
            self.assertIsNone(s.inspect_request({"jsonrpc": "2.0", "id": 9, "method": method}))

    def test_monitor_mode_still_denies(self):
        self.fx.set_token(exp=NOW - 3600)
        s = Sensor({**self.fx.config(), "mode": "monitor"})
        s.access.clock = lambda: NOW
        self.assertDenied(s, call("read_file"), "expired")

    def test_detection_rules_still_apply_after_access_is_allowed(self):
        s = self.fx.sensor()
        out = s.inspect_request(call("send_message", {"to": "audit@registry.test",
                                                      "body": "GP0001-CANARY-7f3a"}))
        self.assertIsNotNone(out)
        self.assertEqual(self.fx.log()[-1]["decision"], "allowed")
        with open(self.fx.path("evidence.jsonl")) as f:
            self.assertIn("GP-0002", f.read())

    def test_denial_is_not_written_as_evidence(self):
        os.unlink(self.fx.path("token"))
        s = self.fx.sensor()
        s.inspect_request(call("read_file"))
        self.assertFalse(os.path.exists(self.fx.path("evidence.jsonl")))

    def test_unusable_config_denies_everything(self):
        cfg = self.fx.config()
        cfg["agent_access"] = {"sensitive_classes": ["no-such-class"]}
        s = Sensor(cfg)
        out = s.inspect_request(call("read_file"))
        self.assertTrue(out["result"]["isError"])

    def test_sensitive_tools_given_as_a_string_denies_everything(self):
        cfg = self.fx.config()
        cfg["agent_access"]["sensitive_tools"] = "deploy"
        out = Sensor(cfg).inspect_request(call("read_file"))
        self.assertTrue(out["result"]["isError"])

    def test_an_unexpected_fault_denies(self):
        s = self.fx.sensor()
        s.access.clock = lambda: (_ for _ in ()).throw(RuntimeError("clock broke"))
        out = s.inspect_request(call("read_file"))
        self.assertTrue(out["result"]["isError"])

    def test_through_the_real_proxy_a_denied_call_never_reaches_the_server(self):
        """The proxy process in front of the test server, as a client would run it.

        Uses the wall clock, so the token and attestation are minted for now.
        """
        import time
        fx = self.fx
        now = int(time.time())
        fx.write("token", encode_hs256(fx.claims(iat=now, exp=now + 600), SECRET))
        fx.write("posture.jwt", encode_hs256(
            {"host": "build-host-1", "iat": now, "posture": "fail"}, POSTURE_SECRET))
        cfg_path = fx.path("guardian.json")
        with open(cfg_path, "w") as f:
            json.dump(fx.config(), f)
        env = {**os.environ, "PYTHONPATH": ROOT,
               "GUARDIAN_CALLS": fx.path("calls.jsonl"),
               "GUARDIAN_SINK": fx.path("sink.jsonl"),
               "GUARDIAN_RECORDS": fx.path("records.jsonl"),
               "GUARDIAN_MEMORY": fx.path("memory.jsonl"),
               "GUARDIAN_AGENT_INBOX": fx.path("inbox.jsonl")}
        cmd = [sys.executable, "-m", "guardian_sensor", "--config", cfg_path, "--",
               sys.executable, os.path.join(HERE, "fake_server.py")]
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, cwd=fx.tmp, env=env)
        replies = []
        try:
            for i, msg in enumerate([
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                    call("weather", {"city": "NYC"}, mid=3),
                    call("delete_records", {"tag": "q3-export-stale"}, mid=4)]):
                p.stdin.write(json.dumps(msg) + "\n")
                p.stdin.flush()
                replies.append(json.loads(p.stdout.readline()))
            agent_access.deprovision(fx.directory, "agent-1")
            p.stdin.write(json.dumps(call("weather", {"city": "NYC"}, mid=5)) + "\n")
            p.stdin.flush()
            replies.append(json.loads(p.stdout.readline()))
        finally:
            p.stdin.close()
            p.stderr.read()
            p.wait(timeout=10)
        by_id = {r["id"]: r for r in replies}
        self.assertFalse(by_id[3]["result"].get("isError"), by_id[3])
        self.assertTrue(by_id[4]["result"]["isError"])
        self.assertTrue(by_id[5]["result"]["isError"])
        with open(fx.path("calls.jsonl")) as f:
            reached = [json.loads(line)["tool"] for line in f]
        self.assertEqual(reached, ["weather"])


class CommandLine(Base):
    def test_provision_list_deprovision_attest(self):
        directory = self.fx.path("cli-agents.json")
        out = io.StringIO()
        self.assertEqual(agent_access.main(
            ["provision", "--directory", directory, "--id", "a1", "--issuer", ISSUER,
             "--subject", "agent:cli"], out=out), 0)
        agent_access.main(["list", "--directory", directory], out=out)
        self.assertIn("a1  active", out.getvalue())
        agent_access.main(["deprovision", "--directory", directory, "--id", "a1"], out=out)
        out = io.StringIO()
        agent_access.main(["list", "--directory", directory], out=out)
        self.assertIn("a1  inactive", out.getvalue())
        target = self.fx.path("cli-posture.jwt")
        self.assertEqual(agent_access.main(
            ["attest", "--secret-path", self.fx.path("posture.key"), "--host", "h1",
             "--posture", "pass", "--out", target], out=out), 0)
        import time
        claims = agent_access.verify_attestation(
            open(target).read().strip(), POSTURE_SECRET.encode(), time.time(), 60)
        self.assertEqual(claims["host"], "h1")
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
