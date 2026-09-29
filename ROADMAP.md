# Roadmap

The next twelve months, by quarter. This is a statement of intent, reviewed in public and updated as the community grows. Proposals to change it go through the process in `GOVERNANCE.md`.

## Q4 2026: foundation

- Registry v0.1: pattern format, contribution checks, first verified patterns mapped to OWASP and MITRE ATLAS
- Full MITRE ATLAS coverage map, reviewed by the community
- Reference sensor for MCP, with tests
- Scanner v0: runs each pattern's test many times and reports an attack success rate
- Client hooks for agents' built-in tools, starting with Claude Code
- Free public scan
- OpenSSF Security Baseline Level 1 and an OpenSSF Scorecard check
- Application to the OpenSSF Sandbox

## Q1 2027: trust

- Registry v0.2: 50 or more verified patterns, with measured false-alarm rates
- Signed releases (Sigstore) and signed rule updates (TUF)
- Monitor-before-block rollout for new rules
- Maintainers from several organizations
- Canary tokens built into the scan

## Q2 2027: network preview

- Anonymized signature sharing between organizations, with STIX 2.1 and TAXII 2.1
- Give-to-get embargo for members who share
- Coordinated disclosure process with model makers and tool maintainers
- Proposal to the Linux Foundation's Agentic AI Foundation

## Q3 2027: beyond actions

- Words-domain detectors: reasoning monitors and checks on what agents say against what they do
- Research track on thoughts-domain probes for self-hosted models, published openly
- Model gateway and network egress integrations
