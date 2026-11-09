"""Conservative parsing of literal kubectl commands; never executes shell input.

This is not a shell interpreter or Kubernetes authorization boundary. Dynamic
expansion, aliases, scripts and manifest contents require separate controls.
"""
import os
import shlex


VALUE_FLAGS = {
    '--context', '--namespace', '-n', '--kubeconfig', '--cluster', '--user',
    '--server', '-s', '--token', '--certificate-authority', '--client-certificate',
    '--client-key', '--request-timeout', '--as', '--as-group', '--as-uid',
    '--cache-dir', '--v', '-v', '--output', '-o', '--selector', '-l',
    '--field-selector', '--timeout', '--grace-period', '--replicas',
    '--type', '--patch', '-p', '--patch-file',
}


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


def destructive_fleet(command, destructive, fleet):
    """Bind the verb and resource to the same literal kubectl invocation.

    Existing bundle signatures remain the vocabulary. Node verbs take node
    names directly; other verbs take resource types (optionally type/name).
    """
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
        return False
    for tokens in segments:
        if not tokens or os.path.basename(tokens[0]) != 'kubectl':
            continue
        args = _positionals(tokens[1:])
        if len(args) < 2:
            continue
        verb, resource = args[:2]
        # Reconstruct only this invocation, with global flags removed from
        # between kubectl and the verb, for the bundle's destructive signature.
        normalized = 'kubectl ' + verb + ' ' + ' '.join(tokens[1:])
        if not destructive.search(normalized):
            continue
        if verb in {'drain', 'cordon', 'uncordon', 'taint'}:
            return True
        for kind in resource.split(','):
            kind = kind.split('/', 1)[0]
            # Resource names and flag values must never supply the scope.
            base = kind.split('.', 1)[0]
            if fleet.fullmatch(base) or (base.endswith('s') and fleet.fullmatch(base[:-1])):
                return True
    return False
