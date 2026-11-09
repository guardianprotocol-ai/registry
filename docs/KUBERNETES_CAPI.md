# Kubernetes and Cluster API command detection

GP-0042 watches for infrastructure destruction after a tool result has tainted
the agent session. Cluster API (CAPI) lifecycle resources deserve special care:
removing a Machine or scaling a MachineDeployment down can delete underlying
infrastructure, not merely restart a workload.

The sensor now tokenizes literal shell commands and binds a destructive verb to
the resource operand in that same kubectl invocation. Global context and
namespace flags are supported, as are API-group-qualified resources,
type/name operands and comma-separated resource types. Node operations such as
`kubectl drain worker-17` take a node name directly.

Examples tested in `sensor/tests/test_rules.py`:

| Tainted-session command | GP-0042 |
| --- | --- |
| `kubectl --context management delete clusters.cluster.x-k8s.io demo` | Detect |
| `kubectl -n capi-system scale machinedeployment workers --replicas=0` | Detect |
| `kubectl delete machines.cluster.x-k8s.io/demo` | Detect |
| `kubectl delete pod cluster` | No finding |
| `kubectl get clusters; kubectl delete pod web` | No finding |
| `kubectl scale machinedeployment workers --replicas=3` | No finding |

Six added regression cases failed with the former whole-string matching rule.
These are deterministic detector tests: no cluster is contacted and no model
chooses an action. Run `python3 sensor/tests/test_rules.py` for the focused suite
and `python3 check.py` for repository checks.

## Boundaries

This is a draft heuristic, not a shell interpreter or admission controller.
It does not resolve shell variables, aliases, wrappers, indirect scripts,
manifest files, kubectl plugins or arbitrary API calls. Unknown flag forms may
not parse correctly. The resource vocabulary comes from the installed signature
bundle; it is not Kubernetes API discovery. GP-0042 still requires session
taint. A clean session is not proof that an operation is authorized or safe.
The rule does not calculate actual permissions, fleet size or provider effects.

Use least-privilege Kubernetes RBAC, separate management-cluster credentials,
and independent approval/admission controls for lifecycle operations. This
change improves an agent-tool checkpoint; it does not prove CAPI controllers
or a production deployment secure.

References:

- [CAPI machine deletion](https://cluster-api.sigs.k8s.io/tasks/automated-machine-management/machine_deletions.html)
- [CAPI scaling](https://main.cluster-api.sigs.k8s.io/tasks/automated-machine-management/scaling.html)
- [Kubernetes RBAC practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
