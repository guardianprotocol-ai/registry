"""Take credentials out of text before this lab prints it or writes it down.

The lab mints a service account token and reads a kubeconfig, and both can ride out in a
failed assertion or an error message: into a CI log every fork can read, or into the
outcome file beside the report.

Two layers. The sensor's own secret signatures, so the lab is scrubbed by the rules the
sensor enforces. And the credentials Kubernetes itself hands out, which those signatures
do not know: a service account token is a JWT and a kubeconfig carries a key as base64,
and neither looks like anything in the sensor's list. Relying on the first layer alone
left this lab's own token unredacted, which is the gap this file closes.
"""
import re

#: What Kubernetes hands out. A JWT is three base64url parts, and the first two start
#: `eyJ` because they are JSON objects. The kubeconfig fields are the ones that hold a
#: key, a certificate or a token inline.
KUBERNETES_CREDENTIALS = (
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"\b(client-key-data|client-certificate-data|certificate-authority-data|token)"
               r"(\s*[:=]\s*)[A-Za-z0-9+/_=.-]{16,}"),
    re.compile(r"\b(Bearer)(\s+)[A-Za-z0-9+/_=.-]{16,}"),
)
REDACTED = "<redacted>"


def scrub(text, secret_expressions=()):
    """`text` with credentials replaced. `secret_expressions` are the sensor's own."""
    out = str(text if text is not None else "")
    for expression in secret_expressions:
        out = expression.sub(REDACTED, out)
    out = KUBERNETES_CREDENTIALS[0].sub(REDACTED, out)
    for expression in KUBERNETES_CREDENTIALS[1:]:
        out = expression.sub(lambda m: m.group(1) + m.group(2) + REDACTED, out)
    return out
