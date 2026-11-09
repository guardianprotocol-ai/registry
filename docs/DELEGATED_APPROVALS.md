# Delegated-operation approval prototype

An opt-in sensor policy requires a durable, single-use approval for **every** tool
call on a dedicated proxy, independent of taint and monitor mode. It supports one
structured tool per proxy; alternate tools are denied. Existing heuristic rules
still apply after approval and may independently refuse the call.

The delegated protocol permits only initialize, initialized/cancelled
notifications, ping, tools/list and tools/call. The trusted backend must keep
lifecycle/discovery methods non-mutating. Tool calls must contain exactly name,
arguments (an object), and the approval-ID metadata; additional metadata or
parameters are rejected because they were not approved. Duplicate JSON keys and
non-finite JSON constants terminate the relay. Other MCP extensions are not
supported by this dedicated gateway. Database initialization creates an
owner-only file and refuses existing paths; protect its parent directory too.

Trusted host configuration:

```json
{
  "delegated_approval": {
    "database": "/trusted/approvals.db",
    "subject": "user:example",
    "agent": "agent:session-123",
    "audience": "management-cluster:immutable-id",
    "tool": "capi_mutate"
  }
}
```

A trusted approval service calls `ApprovalStore.initialize` once, then `grant`
with the authenticated user, agent session, target audience, tool, complete
arguments, authenticated approver and expiration time. The call carries the
returned ID in MCP params `_meta["guardian/approval_id"]`. The ID is not authority
by itself: identities and exact arguments must match. Identity fields come from
host config, never request arguments. `revoke` disables an unused grant.

The component is a prototype authorization primitive, not an identity provider,
credential broker or Kubernetes executor. There is no approval UI or hosted
approval API yet. The supplied Python API is for a trusted integration.

## Required deployment boundary

Run the gateway and approval service outside the agent's security principal.
Protect the config, database, SQLite sidecar files and backend credentials from
agent access. The agent must have no direct Kubernetes credentials or alternate
route to the backend. Bind the configured audience to the backend's fixed API
server and validated TLS identity; a context name alone is insufficient.

The structured backend must validate a closed request schema and forbid arbitrary
shell commands, manifests, URLs and credential overrides. For CAPI operations,
include API group, resource, namespace, name, object UID and resourceVersion in
the approved arguments. The backend must enforce Kubernetes preconditions using
those values; hashing them alone does not prevent object replacement or races.
The gateway does not currently implement that backend or verify its behavior.

## Guarantees and limits

SHA-256 binds the exact JSON request and trusted identities; it is not a digital
signature. Database access is the authority. SQLite serializes consumption and
commits the audit receipt in the same transaction. Concurrent attempts and
process restarts cannot reuse a consumed grant. Audit writes contain digests and
approval IDs, not raw arguments. The local database is not tamper-proof.

Expiration uses the host wall clock; protect time synchronization. Failures deny
the call. Unexpected proxy exceptions close the pipe rather than relay unchecked
traffic. A grant is spent before forwarding: a subsequent detector refusal,
backend failure or crash may require new approval. This is at-most-once approval
consumption, **not exactly-once Kubernetes execution**. Backend idempotency and
reconciliation are separate responsibilities.

Run `python3 sensor/tests/test_approvals.py`. Tests cover identity and argument
substitution, expiry, revocation, replay after restart, concurrent consumption,
audit rollback, monitor-mode enforcement, alternate-tool denial, store failure
and fail-closed proxy faults. They use synthetic identities and no live cluster.
