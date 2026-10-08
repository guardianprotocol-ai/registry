# Start here

Open tests, detections and measurements for attacks on AI agents, mapped to MITRE ATLAS.

Get set up and oriented in about 15 minutes, then pick your first task. No dependencies beyond Python 3.9+.

> **The repository is public and you need nothing from anyone to start.** Fork it, open a pull request, and the automatic checks run on your first one. The project is early: eighteen patterns, a reference sensor and a scanner that measures four of them end to end against a real agent. Plenty is unfinished, and that is where the work is.

**What we are working on right now:** [PROGRAM.md](PROGRAM.md) sets out Season 1, October 5 to October 29, 2026, its six phases and what ships at the end. [docs/STATUS.md](docs/STATUS.md) shows how far along each one is.

## 1. Get it running (3 minutes)

First, fork the repository: open it on GitHub and click **Fork**. Then:

```bash
git clone https://github.com/YOUR-USERNAME/registry.git
cd registry
git remote add upstream https://github.com/guardianprotocol-ai/registry.git
python3 check.py
```

`check.py` validates every pattern and runs every test. It's the same check every pull request runs automatically, so if it passes on your machine, it should pass on GitHub too.

## 2. See it work (2 minutes)

```bash
cd demo
python3 demo.py
```

A test agent is asked to summarize a page that hides an instruction. You'll see the attack land, then the sensor stop it, side by side in a report. Everything is local and harmless: the "secret" is a canary token and the destination is a reserved `.test` address.

## 3. Read the essentials (10 minutes)

1. [README.md](README.md): what the registry is and how a pattern moves from `draft` to `enforced`
2. [ARCHITECTURE.md](ARCHITECTURE.md): the registry, scan, sensor and network, and how they fit
3. [patterns/GP-0001.yaml](patterns/GP-0001.yaml): one complete pattern, start to finish
4. [TRACKS.md](TRACKS.md): the areas of work

## 4. Pick a task

Open the [issues labeled `good first issue`](https://github.com/guardianprotocol-ai/registry/labels/good%20first%20issue), or browse by track (`track:patterns`, `track:scanner`, `track:sensor`, `track:coverage`, `track:research`). Comment on the issue to claim it so nobody duplicates your work. If you have your own idea, open an issue first so we can agree on the approach.

## 5. Make the change

```bash
git fetch upstream && git checkout -b my-change upstream/main

# Writing a new attack pattern? Let the scaffold take the ID and the boilerplate:
python3 check.py new-pattern "Hidden instructions in a calendar invite"

# edit, then:
python3 check.py
git commit -s -m "Add scanner scenario for GP-0011"
git push origin my-change
```

`check.py new-pattern` picks the next free ID, which is never reused, and fills in the
status, the version and the date, then tells you which fields are left.

The `-s` adds your sign-off under the [Developer Certificate of Origin](CONTRIBUTING.md#developer-certificate-of-origin). Every commit needs one.

Then open a pull request from your fork to `guardianprotocol-ai/registry`. The automatic
checks run on it, and the template walks you through the rest. On your **first** pull
request a maintainer has to approve the workflow run before the checks start, which is
GitHub's protection against untrusted code from forks. It is not a judgment on your
change, and it only happens once. Paste the output that shows
your change works, such as `check.py` results or a scanner run, so reviewers can see the
proof. A track label is applied for you, based on the files you touched.

### Two things the checks will tell you if you miss them

**Every pattern maps to MITRE ATLAS, or says why not.** Put at least one technique ID in
`maps_to.atlas`, and it has to be a real one from `coverage/atlas-coverage.csv`. If no
technique genuinely fits, leave `atlas` empty and write `maps_to.custom_reason`: the
closest technique you considered and what it misses. That is allowed on purpose, because
attacks on agents often appear before ATLAS catalogs them, but it has to be argued.

**New patterns are always `draft`.** Only a maintainer moves a pattern to `verified` or
`enforced`, in a separate pull request, once the scan has measured it. A pull request that
adds a non-draft pattern, or changes any pattern's status, is refused.

## How credit works

Everything you contribute is credited to you, publicly and permanently, and none of it is
maintained by hand. The credit list is generated from the `Signed-off-by` lines in the
history, joined with `CONTRIBUTORS.md` and the `credits` in pattern files, and it is
ordered by the date of each person's first contribution.

Add yourself to [CONTRIBUTORS.md](CONTRIBUTORS.md) in your first pull request. That is
where you say how you want to be shown: your display name, your GitHub handle if you want
one, and your organization if you want it listed. Leave the organization blank and none is
listed for you. Nothing reads your commit email domain.

- **Patterns:** add yourself to the `credits` field of any pattern you write or substantially improve, with your name and organization.
- **[CONTRIBUTORS.md](CONTRIBUTORS.md):** add yourself in your first pull request.
- **Releases:** every release's notes name the people who contributed to it, starting with v0.1.

## Roles

Three of them, and you start in the first one.

| Role | What you can do | How you get there |
| --- | --- | --- |
| Contributor | Fork, open pull requests, comment, review without binding effect | Nothing to ask for. Open a pull request |
| Reviewer | Binding approval in your area | About five good merged pull requests, nominated by a maintainer |
| Maintainer | Merge, cut releases, promote patterns | Sustained good reviewing, same nomination |

The full rules, including who holds the keys and what changes at public launch, are in
[GOVERNANCE.md](GOVERNANCE.md). Who holds which role today is in
[MAINTAINERS.md](MAINTAINERS.md).

## Where to talk

- **[GitHub Discussions](https://github.com/guardianprotocol-ai/registry/discussions)** for questions. Anyone can post, and the answer stays where the next person will find it.
- **GitHub issues** for anything that decides something: a design choice, a new pattern, a change of scope. Decisions made in issues leave a public record that new contributors can read later.
- **Slack** for working group coordination, if you are in it. Nothing needed to contribute depends on being there.
- **Never in public:** live attacks, real vulnerabilities, or anything specific to one vendor's product. Use [SECURITY.md](SECURITY.md).

## The safety rules, in short

- Tests use canary tokens and reserved `.test` domains only. No real malware, credentials or personal data.
- Describe attacks at the level a defender needs to reproduce them safely. Anything that would help attackers more than defenders goes through `SECURITY.md`, not a pull request.

The full rules are in [CONTRIBUTING.md](CONTRIBUTING.md).
