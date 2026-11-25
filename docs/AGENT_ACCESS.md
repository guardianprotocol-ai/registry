# Agent identity and access (prototype)

An opt-in check in the MCP proxy sensor. With an `agent_access` block in `guardian.json`,
every `tools/call` is refused before it is forwarded unless:

1. the agent presents a valid OIDC-shaped token,
2. the token names an agent that is provisioned and active in a local directory, and
3. for a sensitive tool, the host presents a recent, passing, signed posture attestation.

Other methods (`initialize`, `tools/list`, `ping`, notifications) are not gated. Without
the block, nothing here runs and the sensor behaves exactly as before.

The code is `sensor/guardian_sensor/agent_access.py`. It is separate from
`identity.py`, which is the member key that signs sightings reports and has nothing to do
with agents.

## What each check is, and is not

**Token.** A compact JWT with `iss`, `aud`, `sub` and `exp` required, and `nbf` and `iat`
checked when present, with a leeway of 60 seconds by default. The header must say
`HS256` and nothing else, so `none` and algorithm substitution are refused. The signature
is an HMAC with a secret shared with a configured issuer; the issuer is looked up first
and an unknown issuer is refused without trying any key. Issuer secrets shorter than 32
bytes are refused.

This is an OIDC-shaped bearer token check that the Python standard library can do. It is
**not** a production identity provider integration: no RS256 or ES256, no discovery
document, no JWKS fetch, no key rotation, no token introspection, no revocation list.
Most identity providers sign ID and access tokens with RS256, so using this with one today
means a gateway the operator trusts verifies the provider's token and issues a short-lived
HS256 token for the sensor. Verifying RS256 directly needs a dependency, which decision 11
does not allow in the core yet.

**Directory.** A JSON file of agents, each with an `issuer`, a `subject` (the token's
`sub`) and `active`. The lifecycle is SCIM-style: provision, update, deprovision by setting
`active: false`, or delete. `apply_scim()` accepts the User resource shape and the
POST / PUT / PATCH / DELETE verbs a SCIM server would receive, so an integration can feed
it from one. It is **not** an RFC 7644 server: there is no HTTP endpoint, no filtering, no
bulk operations, no groups, and PATCH supports only `replace` of `active` and
`displayName`. The issuer is carried in a `urn:guardianprotocol:agent` extension because
SCIM has no field for it.

The directory is read again on every call. A deprovisioned or deleted agent is refused on
its next call, with no restart. A missing or unreadable directory refuses every call.

**Posture.** A compact HS256 token the host writes about itself, with `host`, `iat`,
`posture` and optionally `checks`, a map of named checks that must all be `true`. A
sensitive call needs one that verifies with the posture key, was issued within
`max_age_seconds` (900 by default), is not from the future, says `"posture": "pass"`, and,
if `host` is configured, names that host.

This is **not** MDM, endpoint management or device attestation. The sensor does not
inspect the machine. The attestation is a statement made by whatever process holds the
posture key, and it is exactly as trustworthy as that process and the checks it ran.
`guardian agents attest` writes one, signed, with the posture you pass it; it runs no
checks of its own.

**Sensitive tools.** By default, any tool whose name matches one of the tool classes the
shared rule engine already treats as sensitive in `signatures.json`: `destructive`,
`memory`, `agent` and `write`. `sensitive_classes` narrows that list and
`sensitive_tools` adds exact tool names. The match is on the tool's name, the same as the
rules, so a tool whose name does not say what it does is not caught by default; name it in
`sensitive_tools`.

## Where the token and attestation come from

From files the host names in config, read on every call. Not from MCP `_meta`, a session
field set at `initialize`, or anything else in the message.

- The proxy forwards each message line exactly as the client sent it, so a bearer token in
  the message would be handed to the MCP server on every call.
- Anything in the message is reachable by whatever steers the agent. Who the agent is must
  come from the host, as it does for delegated approvals
  ([DELEGATED_APPROVALS.md](DELEGATED_APPROVALS.md)).
- Reading the files on every call is what lets a host refresh a token before it expires,
  and lets an attestation age out.

One proxy process serves one client session, so one token file is one agent. The host must
keep the token, the attestation, the secrets and the directory out of reach of the agent's
own tools. An agent that can read its token file can hand its identity to anyone, and an
agent that can write the attestation or the directory can grant itself access.

## Configuration

```json
{
  "mode": "block",
  "allowlist": ["yourcompany.com"],
  "agent_access": {
    "token_path": "/run/guardian/agent.token",
    "audience": "guardian-sensor:files",
    "issuers": [
      {"issuer": "https://idp.example.test", "secret_path": "/etc/guardian/idp-hs256.key"}
    ],
    "directory_path": "/etc/guardian/agents.json",
    "leeway_seconds": 60,
    "posture": {
      "attestation_path": "/run/guardian/posture.jwt",
      "secret_path": "/etc/guardian/posture.key",
      "max_age_seconds": 900,
      "host": "build-host-1"
    },
    "sensitive_tools": ["deploy"],
    "sensitive_classes": ["destructive", "memory", "agent", "write"],
    "log_path": "/var/log/guardian/access.jsonl"
  }
}
```

Managing the directory:

```bash
python3 -m guardian_sensor agents provision --directory agents.json \
    --id build-bot --issuer https://idp.example.test --subject agent:build-bot
python3 -m guardian_sensor agents list --directory agents.json
python3 -m guardian_sensor agents deprovision --directory agents.json --id build-bot
python3 -m guardian_sensor agents deprovision --directory agents.json --id build-bot --delete
python3 -m guardian_sensor agents attest --secret-path posture.key \
    --host build-host-1 --posture pass --out posture.jwt
```

Writes are atomic (written whole, then renamed) and the file is owner-only.

## Behaviour

- **Fails closed.** Every other part of the sensor fails open on its own faults. This
  check does not: an unreadable token, directory, secret or attestation, or any
  unexpected error, refuses the call. An `agent_access` block that cannot be parsed
  refuses every call and says so on stderr at start-up.
- **Enforced in monitor mode.** `"mode": "monitor"` softens detections, not access.
- **Checked first.** Before delegated approvals and before the detection rules, so a
  refused agent cannot spend an approval. The detection rules still run on every call
  that is allowed.
- **The same refusal as every other rule.** The agent is told the call was stopped by
  local policy and nothing about which check failed.
- **Logged apart from evidence.** Each decision is one line in `access.jsonl` (under the
  Guardian data directory unless `log_path` says otherwise) with the time, tool, agent
  id, subject, whether the tool counted as sensitive, the decision and the reason. Never
  the token or the attestation. Access decisions are not attack detections and are never
  written to `evidence.jsonl`, so they can never become sightings.

## What has been tested

`python3 sensor/tests/test_agent_access.py`, also run by `python3 check.py`. Synthetic
issuers, secrets and agents only. It covers: a valid token allowed; missing, empty,
expired, not yet valid, no expiry, wrong or missing audience, unknown issuer, wrong key,
altered claims, `alg: none` and short secrets refused; a refreshed token picked up; an
unprovisioned agent refused; a provisioned agent allowed and refused on its next call once
deprovisioned or deleted, including through the SCIM-style verbs; a corrupt or missing
directory refusing; a sensitive tool allowed with a good attestation and refused with a
missing, stale, failing, forged, future-dated or other-host attestation; ordinary tools
still flowing while posture fails; monitor mode still refusing; detection rules still
applying after access is allowed; and one run of the real proxy process in front of the
test server, where the server's own call log shows that only the allowed call reached it.

It has not been run in front of a real identity provider, a real SCIM client, a real
posture agent, or inside a real MCP client.
