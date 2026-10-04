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

## Scope of this code

The sensor, scanner and hooks are prototypes. Don't rely on them for production data yet.
