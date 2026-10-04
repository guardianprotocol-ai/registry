# Start here

Get set up and oriented in about 15 minutes, then pick your first task. No dependencies beyond Python 3.9+.

> **Private preview.** The repository is private while the project prepares its first public release. To get access, send your GitHub username to Frank Albanese in the working group Slack. You'll get read access, and you contribute through your own fork.

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
# edit, then:
python3 check.py
git commit -s -m "Add scanner scenario for GP-0011"
git push origin my-change
```

The `-s` adds your sign-off under the [Developer Certificate of Origin](CONTRIBUTING.md#developer-certificate-of-origin). Every commit needs one.

Then open a pull request from your fork to `guardianprotocol-ai/registry`. The automatic checks run on it, and the template walks you through the rest. Paste the output that shows your change works, such as `check.py` results or a scanner run, so reviewers can see the proof.

## How credit works

Everything you contribute is credited to you, publicly and permanently.

- **Patterns:** add yourself to the `credits` field of any pattern you write or substantially improve, with your name and organization.
- **[CONTRIBUTORS.md](CONTRIBUTORS.md):** add yourself in your first pull request.
- **Releases:** every release's notes name the people who contributed to it, starting with v0.1.

## Where to talk

- **Slack** for quick questions and coordination.
- **GitHub issues** for anything that decides something: a design choice, a new pattern, a change of scope. Decisions made in issues leave a public record that new contributors can read later.
- **Never in public:** live attacks, real vulnerabilities, or anything specific to one vendor's product. Use [SECURITY.md](SECURITY.md).

## The safety rules, in short

- Tests use canary tokens and reserved `.test` domains only. No real malware, credentials or personal data.
- Describe attacks at the level a defender needs to reproduce them safely. Anything that would help attackers more than defenders goes through `SECURITY.md`, not a pull request.

The full rules are in [CONTRIBUTING.md](CONTRIBUTING.md).
