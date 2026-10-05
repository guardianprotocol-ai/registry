# Security policy

Guardian Protocol exists to share defenses, so we handle live attacks and vulnerabilities with care.

## What to report privately

- An attack seen in the wild against a real organization or product
- A weakness specific to one vendor's model, agent, tool or MCP server
- A way to evade a sensor or a detection in this repository
- A vulnerability in the sensor, scanner, hooks or any code here

Please don't open a public issue or pull request for any of these.

## How to report

Use GitHub's private vulnerability reporting: the **Security** tab of this repository, then **Report a vulnerability**. Only maintainers can see the report, it carries an audit trail, and it can issue a CVE.

Include what you saw, how to reproduce it with harmless data, and who is affected if you know.

Please don't report a vulnerability in a public issue, a pull request or a discussion.

## What happens next

1. A maintainer acknowledges the report within 3 business days.
2. If a third party is affected (a model maker, a tool maintainer, a vendor), we notify them privately and agree on a fix timeline. Our default is 90 days, shorter if the attack is being used actively.
3. Where a registry pattern fits, we draft it privately. Tests stay harmless: canary data and reserved `.test` destinations only.
4. After a fix, or when the timeline ends, we publish an advisory with a registry ID and credit you unless you prefer to stay anonymous.

Evasion techniques that would help attackers more than defenders stay private, shared only with sensor maintainers.

## Publishing measured results

The registry publishes attack success rates against named models and harnesses, in
[results/](results/) and the generated [docs/MATRIX.md](docs/MATRIX.md). Numbers about
someone else's product carry an obligation, so there are three rules.

**Publish freely when the technique is already public.** A result for a publicly documented
attack technique may be published as soon as it passes the checks in
[results/README.md](results/README.md). Measuring a known attack against a shipping product
is ordinary security research and we do not sit on it.

**Report first when it is not.** A new technique, or a severe result that is not already
public for that model or harness, goes to the model maker or the tool maintainer through the
process above before it is published. It is published after a fix, or when the disclosure
window ends, whichever comes first. If you are unsure which case you are in, report it
privately and ask; nobody has ever regretted that order.

**Say what you measured, never what you concluded about a vendor.** A row is a statement
about one version on one date, with its run count and interval attached. It is not a
statement that a product is insecure, and the matrix is written so that no row can imply
one. A result with no interval and no run count is not evidence, and the checks refuse it.

A measurement carries the name of whoever took it. That is the point: it is a claim someone
is willing to put their name on, not an anonymous score.

## What is public and what is not

Two repositories, and the line between them is about whose data it is.

**Public, `guardianprotocol-ai/registry`:** code, patterns, detections, documents,
proposals, and results that have been approved for publication. Everything in this
repository is readable by anyone, forever, and should be written on that assumption.

**Private, `guardianprotocol-ai/research`, members only:** raw experiment data from
members' own companies, anything naming a participating company, findings waiting on
coordinated disclosure, and paper drafts. On publication, the anonymized data, the results
and the paper move to the public repository.

**Never in the public repository**, even in an issue or a pull request comment: a member
company's name alongside its results, raw evidence logs, or a finding that has not been
through the disclosure process above. If something has already been posted by mistake,
report it the private way described at the top of this page rather than deleting it
quietly, because the history stays.

Anonymized sightings are built from an allow-list of fields and contain no tool names,
arguments, URLs, paths or message text. That is checked by tests, not by review. See
`ARCHITECTURE.md`.

## Scope of this code

The sensor, scanner and hooks are prototypes. Don't rely on them for production data yet.
