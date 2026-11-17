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
    '-f', '--filename', '-k', '--kustomize', '--template', '--raw',
}

# Words that run a command without being it, and the flags of theirs that take a value.
WRAPPERS = {'sudo', 'env', 'command', 'exec', 'nohup', 'time'}
WRAPPER_VALUE_FLAGS = {'-u', '-g', '-h', '-p', '-C', '-D', '-R', '-T', '-r', '-t',
                       '--user', '--group', '--host', '--chdir'}
CASCADE_VALUES = {'background', 'foreground', 'orphan', 'true', 'false'}
# A flag longer than this, or more of them than this, is not a flag anybody typed. The
# bundle's destructive signature is run over the flags of one invocation, and what it is
# given is bounded here so its cost is too.
MAX_FLAG_LENGTH = 64
MAX_FLAGS = 64
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

API_VERSION = re.compile(r'^v\d+((alpha|beta)\d+)?$')

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
    'fleet_kind_provider': NEVER,
    'manifest_keys': ('resource', 'manifest'),
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
        if token == '--cascade' and i + 1 < len(tokens) and tokens[i + 1] in CASCADE_VALUES:
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
        # A backslash at the end of a line continues it, which is how any long kubectl
        # command is written down.
        lexer = shlex.shlex(command.replace('\\\n', ' '), posix=True,
                            punctuation_chars=';&|()\n')
        lexer.whitespace = ' \t\r'
        lexer.whitespace_split = True
        # shlex would drop a comment together with the newline that ends it, joining the
        # next line onto this one. Comments are cut below instead, a line at a time.
        lexer.commenters = ''
        segments = [[]]
        for token in lexer:
            if token and all(c in ';&|()\n' for c in token):
                segments.append([])
            else:
                segments[-1].append(token)
    except ValueError:
        return []
    out = []
    for tokens in segments:
        for i, token in enumerate(tokens):
            if token.startswith('#'):
                tokens = tokens[:i]
                break
        if tokens:
            out.append(tokens)
    return out


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
                i += 2 if tokens[i] in WRAPPER_VALUE_FLAGS else 1
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
        # What an infrastructure provider calls its clusters and machines: an
        # AWSMachinePool is a node pool whatever the core kinds are called.
        for candidate in (base, base[:-1] if base.endswith('s') else base):
            if vocab.fleet_kind_provider.fullmatch(candidate):
                return candidate
    return None


def _raw_kind(path, vocab):
    """The fleet scoped kind a Kubernetes API path names, or None.

    /apis/<group>/<version>/namespaces/<namespace>/<resource>/<name>, with the group
    missing for the core API and the namespace missing for cluster scoped resources.
    A path that ends at a namespace is the namespace itself.
    """
    parts = [p for p in path.split('?', 1)[0].split('#', 1)[0].split('/') if p]
    # The shapes Kubernetes serves and nothing looser: /api/v1/ for the core group, and
    # /apis/<group>/<version>/ for the rest. Plenty of other services have an /api/.
    if 'apis' in parts:
        at = parts.index('apis')
        if len(parts) < at + 3 or not API_VERSION.match(parts[at + 2]):
            return None
        parts = parts[at + 3:]
    elif 'api' in parts:
        at = parts.index('api')
        if parts[at + 1:at + 2] != ['v1']:
            return None
        parts = parts[at + 2:]
    else:
        return None
    if len(parts) >= 3 and parts[0] == 'namespaces':
        parts = parts[2:]
    return _fleet_kind(parts[0], vocab) if parts else None


def _flag_value(tokens, names):
    for i, token in enumerate(tokens):
        if token in names and i + 1 < len(tokens):
            return tokens[i + 1]
        for name in names:
            if name.startswith('--') and token.startswith(name + '='):
                return token[len(name) + 1:]
            if not name.startswith('--') and token.startswith(name) and len(token) > len(name):
                return token[len(name):]
    return None


def _kubectl_fleet(tokens, vocab):
    """Judge the words after `kubectl`. Returns what was asked for, or None."""
    args = _positionals(tokens)
    raw = _flag_value(tokens, ('--raw',))
    if raw and args[:1] == ['delete']:
        # The API path, with no resource word for kubectl to parse.
        kind = _raw_kind(raw, vocab)
        return 'delete %s' % kind if kind else None
    if len(args) < 2:
        return None
    verb, resource = args[:2]
    if verb == 'delete' and '--all' in tokens and (
            '-A' in tokens or '--all-namespaces' in tokens):
        # Every object of a kind in every namespace. The kind can be a workload and the
        # reach is still the whole cluster.
        return 'delete across all namespaces'
    if verb == 'annotate':
        kind = _fleet_kind(resource, vocab)
        if kind and any(vocab.lifecycle_annotation.search(a) for a in args[2:]):
            return 'annotate %s' % kind
        return None
    if _dry_run(tokens):
        return None
    if not vocab.destructive.search(_normalized(verb, tokens)):
        return None
    if verb in RESTORING:
        return None
    if verb == 'taint' and args[2:] and all(a.endswith('-') for a in args[2:]):
        return None         # a trailing dash removes the taint, which restores the node
    if verb in NODE_VERBS:
        return '%s node' % verb
    kind = _fleet_kind(resource, vocab)
    return '%s %s' % (verb, kind) if kind else None


def _dry_run(tokens):
    """Whether kubectl was told to change nothing. `--dry-run=none` is a real run."""
    for token in tokens:
        if token == '--dry-run' or (token.startswith('--dry-run=')
                                    and token != '--dry-run=none'):
            return True
    return False


def _normalized(verb, tokens):
    """One invocation as the bundle's destructive signature expects to read it.

    The verb, then this invocation's flags and nothing else. Names and other words are
    left out because the signature does not need them and a long run of them is what
    makes a pattern slow. `--patch` is written as `-p`, which is the spelling the
    signature knows.
    """
    flags = []
    for i, token in enumerate(tokens):
        if len(flags) >= MAX_FLAGS:
            break
        if not token.startswith('-') or len(token) > MAX_FLAG_LENGTH or ' ' in token:
            continue
        if token == '--patch' or token.startswith('--patch=') or token == '--patch-file':
            token = '-p'
        flags.append(token)
        if token in ('--replicas', '--type') and i + 1 < len(tokens):
            value = tokens[i + 1]
            if len(value) <= MAX_FLAG_LENGTH and ' ' not in value:
                flags.append(value)
    return 'kubectl %s %s' % (verb, ' '.join(flags))


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
    if not _prints_contents(_output_format(tokens)):
        return None
    kinds, _, name = args[1].partition('/')
    names = [name] if name else args[2:]
    if not any(k.split('.', 1)[0].lower() in ('secret', 'secrets') for k in kinds.split(',')):
        return None
    if not names:
        return 'every secret'
    for candidate in names:
        if vocab.fleet_credential_secret.search(candidate):
            # A kubeconfig opens one cluster. A certificate authority key mints
            # credentials for it, which is worse and looks duller.
            return ('cluster kubeconfig secret' if candidate.endswith('-kubeconfig')
                    else 'cluster certificate secret')
    return None


def _prints_contents(output):
    """Whether this output format can print what a Secret holds."""
    if output is None:
        return False                        # kubectl's table: a name and an age
    form = output.split('=', 1)[0].lower()
    if form in NAMES_ONLY:
        return False
    if form.startswith(('custom-columns', 'jsonpath', 'go-template', 'template')):
        # An expression chooses the fields. One that never mentions data prints names.
        return bool(re.search(r'(^|[^a-z])(string)?data', output.lower()))
    return True


def _clusterctl_fleet(tokens, vocab):
    args = _positionals(tokens)
    if not args or '--dry-run' in tokens:
        return None
    if vocab.clusterctl_destructive.search(args[0]):
        return 'clusterctl %s' % args[0]
    return None


def _curl_fleet(tokens, vocab):
    """A DELETE sent straight to the Kubernetes API, with no kubectl in it at all."""
    method = _flag_value(tokens, ('-X', '--request'))
    if not method or method.upper() != 'DELETE':
        return None
    for token in tokens:
        if '://' in token:
            kind = _raw_kind(token.split('://', 1)[1].partition('/')[2], vocab)
            if kind:
                return 'delete %s' % kind
    return None


def _clusterctl_credential(tokens, vocab):
    args = _positionals(tokens)
    if args[:2] == ['get', 'kubeconfig']:
        return 'clusterctl get kubeconfig'
    return None


JUDGES = {
    'fleet': {'kubectl': _kubectl_fleet, 'clusterctl': _clusterctl_fleet,
              'curl': _curl_fleet},
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
    # A node verb only counts when the call also names a node. `drain_queue` drains a
    # queue, and a `command` argument of `drain` may be a program to run in a pod.
    names_a_node = 'node' in words or 'nodes' in words or 'nodeName' in args
    kubernetes = (vocab.tool.search(name or '') or 'apiVersion' in args
                  or (names_a_node and any(v in NODE_VERBS for v in verbs)))
    if not kubernetes:
        return []
    output = next((args[k] for k in ('output', 'outputFormat')
                   if isinstance(args.get(k), str) and len(args[k]) <= MAX_FLAG_LENGTH), 'yaml')
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
            if verb == 'list' and kind:
                # A structured list returns whole objects, every one of the kind.
                out.append(['get', kind, '-o', output])
                continue
            if kind:
                tokens = [verb, kind] + names[:1] + extra
            elif verb in NODE_VERBS:
                if not names_a_node:
                    continue
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
                # A structured get returns the whole object unless it is asked not to.
                tokens += ['-o', output]
            out.append(tokens)
    return out


TOP_LEVEL_KIND = re.compile(r'^kind:[ \t]*["\']?([A-Za-z][A-Za-z0-9]*)["\']?[ \t]*$')
TOP_LEVEL_KEY = re.compile(r'^[A-Za-z]')
ZERO_REPLICAS = re.compile(r'^[ \t-]+replicas:[ \t]*0[ \t]*$')
PAUSED = re.compile(r'^[ \t]+paused:[ \t]*true[ \t]*$')
MAX_MANIFEST = 200000
MAX_DEPTH = 12


def _yaml_document(lines):
    """(kind, zero replicas, paused) from the lines of one YAML document.

    Only what is under `spec:` counts. `status.replicas: 0` describes a pool that has not
    come up yet, and says nothing about what the manifest asks for.
    """
    kind, zero, paused, in_spec = None, False, False, False
    for line in lines:
        if TOP_LEVEL_KEY.match(line):
            in_spec = line.startswith('spec:')
            found = TOP_LEVEL_KIND.match(line)
            if found:
                kind = found.group(1)
        elif in_spec:
            zero = zero or bool(ZERO_REPLICAS.match(line))
            paused = paused or bool(PAUSED.match(line))
    return kind, zero, paused


def _json_zero_replicas(node, depth=0):
    """Whether `replicas` is zero anywhere under a spec, a topology included."""
    if depth > MAX_DEPTH:
        return False
    if isinstance(node, dict):
        value = node.get('replicas')
        if value == 0 and not isinstance(value, bool):
            return True
        return any(_json_zero_replicas(v, depth + 1) for v in node.values())
    if isinstance(node, list):
        return any(_json_zero_replicas(v, depth + 1) for v in node)
    return False


def _manifest_documents(text):
    """(kind, zero replicas, paused) for each document in a manifest string.

    JSON is parsed. YAML is not: the standard library has no parser, so three things are
    looked for by line, a top level `kind:`, and under `spec:` a `replicas: 0` or a
    `paused: true`. That reads the manifests a tool is ordinarily handed and nothing
    cleverer: anchors, flow style and a field spelled another way are not seen.
    """
    text = text.strip()
    if text.startswith(('{', '[')):
        import json
        try:
            loaded = json.loads(text)
        except (ValueError, RecursionError):
            return
        for doc in loaded if isinstance(loaded, list) else [loaded]:
            if isinstance(doc, dict) and isinstance(doc.get('kind'), str):
                spec = doc.get('spec') if isinstance(doc.get('spec'), dict) else {}
                yield (doc['kind'], _json_zero_replicas(spec), spec.get('paused') is True)
        return
    document = []
    for line in text.split('\n'):
        if line.rstrip() == '---':
            kind, zero, paused = _yaml_document(document)
            if kind:
                yield kind, zero, paused
            document = []
        else:
            document.append(line.rstrip('\r'))
    kind, zero, paused = _yaml_document(document)
    if kind:
        yield kind, zero, paused


APPLYING = {'apply', 'create', 'update', 'replace'}


def _manifest_fleet(name, args, vocab):
    """A manifest handed to a tool that scales a fleet resource to zero or pauses it.

    Applying a manifest is how a declarative agent does everything, so most of them are
    ordinary. Only the two changes that are a lifecycle operation by another route count.
    """
    if not isinstance(args, dict):
        return None
    # Only a tool that sends the manifest to a cluster. Writing one to a file changes
    # nothing until something applies it, and that call is the one to judge.
    if not (vocab.tool.search(name or '') or APPLYING & set(_name_words(name))):
        return None
    for key in vocab.manifest_keys:
        text = args.get(key)
        if not isinstance(text, str) or len(text) > MAX_MANIFEST:
            continue
        for kind, zero, paused in _manifest_documents(text):
            fleet = KIND.match(kind) and _fleet_kind(kind, vocab)
            if fleet and zero:
                return 'apply %s with zero replicas' % fleet
            if fleet and paused:
                return 'apply %s paused' % fleet
    return None


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
    if question == 'fleet':
        found = _manifest_fleet(name, args, vocab)
        if found:
            return {'operation': found, 'read_from': 'manifest'}
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
