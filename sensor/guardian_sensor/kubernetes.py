"""What a tool call asks Kubernetes to do, read conservatively. Never executes anything.

An agent reaches a cluster three ways, and a rule that reads only one of them is a rule
about how the lab happened to be built:

1. A shell command, `kubectl delete cluster demo`, possibly behind `sudo` or a
   `KUBECONFIG=...` assignment.
2. A Kubernetes MCP server that takes the command as one string and adds `kubectl`
   itself, so the string starts at the verb.
3. A Kubernetes MCP server with structured arguments: the verb is the tool's name or an
   `operation` argument, the kind is a `kind` or `resourceType` argument, and scaling to
   zero is a number. No command string exists anywhere in the call.

All three are turned into the same thing, the words after `kubectl`, and judged once.

Cluster API gets its own care because the damage is indirect. Nothing is deleted by
`kubectl annotate machine ... cluster.x-k8s.io/delete-machine=yes`, by pausing a Cluster,
or by `clusterctl move`, and each of them changes which machines exist or who controls
them. And a management cluster holds an admin kubeconfig for every cluster it manages, as
an ordinary Secret, so reading one is reading the keys to a cluster the agent was never
given.

This is not a shell interpreter or a Kubernetes authorization boundary. Variables,
aliases, scripts, plugins and the contents of manifests are not resolved. See
docs/KUBERNETES_CAPI.md for what is and is not covered.
"""
import os
import re
import shlex


VALUE_FLAGS = {
    '--context', '--namespace', '-n', '--kubeconfig', '--cluster', '--user',
    '--server', '-s', '--token', '--certificate-authority', '--client-certificate',
    '--client-key', '--request-timeout', '--as', '--as-group', '--as-uid',
    '--cache-dir', '--v', '-v', '--output', '-o', '--selector', '-l',
    '--field-selector', '--timeout', '--grace-period', '--replicas',
    '--type', '--patch', '-p', '--patch-file',
    # A file name is not a resource. Without these, `kubectl delete -f cluster.yaml` was
    # flagged because of what the file happened to be called, and `-f prod.yaml` was not.
    '-f', '--filename', '-k', '--kustomize', '--template',
}

# Words that run a command without being it.
WRAPPERS = {'sudo', 'env', 'command', 'exec', 'nohup', 'time'}
ASSIGNMENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')

NODE_VERBS = {'drain', 'cordon', 'uncordon', 'taint'}
# Uncordon puts a node back into service. Stopping an agent from undoing a cordon is an
# outage the sensor would be causing, so it is recognised as a node verb and not flagged.
RESTORING = {'uncordon'}
# Output formats that print what a Secret is called and nothing it holds.
NAMES_ONLY = {'name', 'wide'}

# A value is only used as a verb or a kind if it is one plain word. Anything else is
# somebody's data, and data must never be read as the command.
WORD = re.compile(r'^[A-Za-z]+$')
KIND = re.compile(r'^[A-Za-z][A-Za-z0-9.-]*$')

NEVER = re.compile(r'(?!x)x')

# Defaults for a bundle older than this engine. A bundle may always be older than the
# engine reading it, and a missing key must not take the sensor down or change what the
# existing signatures mean.
DEFAULTS = {
    'tool': NEVER,
    'short_names': {},
    'kind_keys': ('kind', 'resourceType', 'resource_type'),
    'verb_keys': ('command', 'operation', 'action', 'subCommand', 'verb'),
    'count_keys': ('replicas', 'scale'),
    'name_keys': ('name', 'nodeName'),
    'lifecycle_annotation': NEVER,
    'clusterctl_destructive': NEVER,
    'fleet_credential_secret': NEVER,
}


class Vocabulary:
    """The bundle's Kubernetes words, compiled once."""

    def __init__(self, destructive, fleet, section=None, compile_entry=None):
        self.destructive = destructive
        self.fleet = fleet
        section = section or {}
        for key, default in DEFAULTS.items():
            value = section.get(key)
            if value is None:
                value = default
            elif isinstance(default, type(NEVER)):
                value = compile_entry(value)
            elif isinstance(default, tuple):
                value = tuple(value)
            setattr(self, key, value)
        self.short_names = {k.lower(): v for k, v in self.short_names.items()}


def _positionals(tokens):
    """Remove recognized option values without mistaking them for resources."""
    result = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == '--':
            result.extend(tokens[i + 1:])
            break
        if token in VALUE_FLAGS:
            i += 2
            continue
        if token.startswith('-'):
            i += 1
            continue
        result.append(token)
        i += 1
    return result


def _segments(command):
    """The command split into simple commands, as tokens. Empty if it does not parse."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=';&|()\n')
        lexer.whitespace = ' \t\r'
        lexer.whitespace_split = True
        segments = [[]]
        for token in lexer:
            if token and all(c in ';&|()\n' for c in token):
                segments.append([])
            else:
                segments[-1].append(token)
    except ValueError:
        return []
    return [tokens for tokens in segments if tokens]


def _unwrapped(tokens):
    """The tokens with leading `sudo`, `env` and NAME=value assignments removed.

    `KUBECONFIG=/path kubectl delete cluster demo` is how a management cluster is usually
    addressed, and it starts with a word that is not kubectl.
    """
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if ASSIGNMENT.match(token):
            i += 1
        elif token in WRAPPERS:
            i += 1
            while i < len(tokens) and tokens[i].startswith('-'):
                i += 1
        else:
            break
    return tokens[i:]


def _fleet_kind(resource, vocab):
    """The fleet scoped kind this operand names, in the bundle's own word, or None."""
    for kind in resource.split(','):
        kind = kind.split('/', 1)[0]
        # Resource names and flag values must never supply the scope.
        base = kind.split('.', 1)[0].lower()
        base = vocab.short_names.get(base, base)
        if vocab.fleet.fullmatch(base):
            return base
        if base.endswith('s') and vocab.fleet.fullmatch(base[:-1]):
            return base[:-1]
    return None


def _kubectl_fleet(tokens, vocab):
    """Judge the words after `kubectl`. Returns what was asked for, or None."""
    args = _positionals(tokens)
    if len(args) < 2:
        return None
    verb, resource = args[:2]
    if verb == 'annotate':
        kind = _fleet_kind(resource, vocab)
        if kind and any(vocab.lifecycle_annotation.search(a) for a in args[2:]):
            return 'annotate %s' % kind
        return None
    # Reconstruct only this invocation, with global flags removed from between kubectl
    # and the verb, for the bundle's destructive signature.
    normalized = 'kubectl ' + verb + ' ' + ' '.join(tokens)
    if not vocab.destructive.search(normalized):
        return None
    if verb in RESTORING:
        return None
    if verb in NODE_VERBS:
        return '%s node' % verb
    kind = _fleet_kind(resource, vocab)
    return '%s %s' % (verb, kind) if kind else None


def _output_format(tokens):
    """What `-o` asks for, or None if the command prints kubectl's default table."""
    for i, token in enumerate(tokens):
        if token in ('-o', '--output'):
            return tokens[i + 1] if i + 1 < len(tokens) else ''
        if token.startswith('--output='):
            return token.split('=', 1)[1]
        if token.startswith('-o') and len(token) > 2:
            return token[2:].lstrip('=')
        if token == '--template' or token.startswith('--template='):
            return 'template'
    return None


def _kubectl_credential(tokens, vocab):
    """Whether the words after `kubectl` print credentials a management cluster holds.

    Two reads count. A managed cluster's kubeconfig Secret by name, and every Secret at
    once, which includes all of them. Either only counts when the output is asked for in
    a form that prints the contents: the default table and `-o name` print what a Secret
    is called and nothing it holds, and checking that one exists is ordinary work.
    """
    args = _positionals(tokens)
    if len(args) < 2 or args[0] != 'get':
        return None
    output = _output_format(tokens)
    if output is None or output.split('=', 1)[0] in NAMES_ONLY:
        return None
    kind, _, name = args[1].partition('/')
    names = [name] if name else args[2:]
    if kind.split('.', 1)[0].lower() not in ('secret', 'secrets'):
        return None
    if not names:
        return 'every secret'
    if any(vocab.fleet_credential_secret.search(n) for n in names):
        return 'cluster kubeconfig secret'
    return None


def _clusterctl_fleet(tokens, vocab):
    args = _positionals(tokens)
    if not args or '--dry-run' in tokens:
        return None
    if vocab.clusterctl_destructive.search(args[0]):
        return 'clusterctl %s' % args[0]
    return None


def _clusterctl_credential(tokens, vocab):
    args = _positionals(tokens)
    if args[:2] == ['get', 'kubeconfig']:
        return 'clusterctl get kubeconfig'
    return None


JUDGES = {
    'fleet': {'kubectl': _kubectl_fleet, 'clusterctl': _clusterctl_fleet},
    'credential': {'kubectl': _kubectl_credential, 'clusterctl': _clusterctl_credential},
}


def _in_command(command, vocab, question, implied=False):
    """Ask one question of every kubectl or clusterctl invocation in a command string.

    `implied` is for a tool that adds `kubectl` itself: the first simple command is then
    kubectl's arguments even though the word is not there.
    """
    for index, tokens in enumerate(_segments(command)):
        tokens = _unwrapped(tokens)
        if not tokens:
            continue
        binary = os.path.basename(tokens[0])
        judge = JUDGES[question].get(binary)
        if judge:
            found = judge(tokens[1:], vocab)
        elif implied and index == 0:
            found = JUDGES[question]['kubectl'](tokens, vocab)
        else:
            found = None
        if found:
            return found
    return None


def _name_words(name):
    """`resources_delete` and `kubectlDelete` as lowercase words."""
    spaced = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', name or '')
    return [w.lower() for w in re.split(r'[^A-Za-z0-9]+', spaced) if w]


def _structured(name, args, vocab):
    """Every kubectl argument list a structured tool call could stand for.

    One per candidate verb: each word of the tool's name and each verb argument. Most
    are nonsense, `kubectl resources Cluster`, and nonsense matches nothing. The kind and
    the count come only from arguments named for them, and only when they are one plain
    word or a number, so a description or a manifest can never be read as the command.
    """
    if not isinstance(args, dict):
        return []
    words = _name_words(name)
    verbs = list(words)
    for key in vocab.verb_keys:
        value = args.get(key)
        if isinstance(value, str) and WORD.match(value):
            verbs.append(value.lower())
    # Only a call that is recognisably Kubernetes. `delete_node {"kind": ...}` is also how
    # a graph database removes a vertex.
    kubernetes = (vocab.tool.search(name or '') or 'apiVersion' in args
                  or any(v in NODE_VERBS for v in verbs))
    if not kubernetes:
        return []
    kinds = [args[k] for k in vocab.kind_keys
             if isinstance(args.get(k), str) and KIND.match(args[k])]
    names = [args[k] for k in vocab.name_keys
             if isinstance(args.get(k), str) and KIND.match(args[k])]
    counted = dict(args)
    if isinstance(args.get('flags'), dict):
        counted.update(args['flags'])
    counts = []
    for key in vocab.count_keys:
        value = counted.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
            try:
                counts.append(int(float(value)))
            except (ValueError, OverflowError):
                pass                    # NaN and infinity are numbers to a JSON parser
    extra = [a for a in args.get('args', []) if isinstance(a, str)] \
        if isinstance(args.get('args'), list) else []
    out = []
    for verb in verbs:
        for kind in kinds or [None]:
            if kind:
                tokens = [verb, kind] + names[:1] + extra
            elif verb in NODE_VERBS:
                tokens = [verb] + (names[:1] or ['node']) + extra
            else:
                # No kind argument, so the kind can only come from a list of kubectl
                # arguments. A name is never promoted to one: `pods_delete` of a pod
                # called `cluster` deletes a pod.
                tokens = [verb] + extra
            tokens += ['--replicas=%d' % c for c in counts]
            if verb == 'patch':
                tokens += ['-p', 'x']
            if verb == 'get':
                tokens += ['-o', 'yaml']     # a structured get returns the whole object
            out.append(tokens)
    return out


def _strings(name, args, commands, vocab):
    """(command string, whether kubectl is implied) for everything worth reading."""
    out = [(c, False) for c in commands]
    if vocab.tool.search(name or '') and isinstance(args, dict):
        # A kubectl tool adds the word itself, and one of them calls its one string `args`.
        out = [(c, True) for c in commands]
        if isinstance(args.get('args'), str):
            out.append((args['args'], True))
    return out


def _ask(question, name, args, commands, vocab):
    for command, implied in _strings(name, args, commands, vocab):
        found = _in_command(command, vocab, question, implied)
        if found:
            return {'operation': found, 'read_from': 'command'}
    for tokens in _structured(name, args, vocab):
        found = JUDGES[question]['kubectl'](tokens, vocab)
        if found:
            return {'operation': found, 'read_from': 'tool arguments'}
    return None


def fleet_operation(name, args, commands, vocab):
    """A destructive or lifecycle operation on cluster or fleet scoped infrastructure.

    Returns {"operation": "delete cluster", "read_from": "command" | "tool arguments"}
    or None. The operation is the verb and the kind in the bundle's words, never a name,
    so nothing about whose cluster it was travels with a sighting.
    """
    return _ask('fleet', name, args, commands, vocab)


def fleet_credential(name, args, commands, vocab):
    """A read of the kubeconfig a management cluster holds for a cluster it manages."""
    return _ask('credential', name, args, commands, vocab)


def destructive_fleet(command, destructive, fleet):
    """Whether one command string holds a destructive kubectl call on a fleet resource.

    Kept for callers that have a string and the two original signatures and nothing else.
    """
    return bool(_in_command(command, Vocabulary(destructive, fleet), 'fleet'))
