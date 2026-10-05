# Maintaining Guardian Protocol

For maintainers. If you are contributing, start with [START_HERE.md](../START_HERE.md).

This document should be enough for a second maintainer to run the project without asking
anyone. If something here is wrong or missing, fixing it is a good pull request.

## Reviewing and merging

1. Wait for the checks. Every pull request runs `check.py` on Python 3.9, 3.12 and 3.13,
   plus the sign-off check, the status guard and the rule gate. A red check is not a
   discussion point; ask for it to be green first.
2. Read the rule gate summary on the run. It says what the change does to detection:
   attacks no longer caught, ordinary work newly flagged, new corpus cases. A change that
   flags ordinary work needs a reason, not just a passing test.
3. Check the evidence in the pull request body. The template asks for it: `check.py`
   output, a scanner run, or the corpus cases added.
4. Approve in your area, or ask the right code owner to.
5. Merge. **Nobody merges their own change.** With one maintainer that is not yet
   possible: the founding maintainer merges using the administrator override, which GitHub
   records on the pull request. Say so in the pull request rather than pretending
   otherwise. The moment a second maintainer exists, the override stops being used.

Use **Rebase and merge**. History stays linear and every commit keeps its sign-off, which
`scripts/check_signoff.py` depends on.

## Promoting a pattern

Patterns move `draft` to `verified` to `enforced`. Contributors only ever add `draft`;
`scripts/check_status_changes.py` enforces that, reading the author from the pull request
event and the maintainer list from the Maintainers table in `MAINTAINERS.md`.

Promotion is always its own pull request, opened by a maintainer.

| To | What must be true |
| --- | --- |
| `verified` | The scan has run the pattern's test against both reference agents, many times, and reported an attack success rate. The checks pass. Two reviewers have approved |
| `enforced` | Everything above, plus a measured false-alarm rate on the benign corpus, and approval from two maintainers at different organizations |

`enforced` means a sensor will block real traffic on it. See
[RULE_SAFETY.md](RULE_SAFETY.md) for the monitor-before-block rules.

## Patterns that map to no ATLAS technique

A pattern may map to no MITRE ATLAS technique if it says why, in `maps_to.custom_reason`:
the closest technique considered and what it misses. This is deliberate. Attacks on agents
often appear before ATLAS catalogs them, and the registry should lead rather than lag.

The guardrail is that the number stays visible. `check.py` prints a count on every run, the
rule gate summary lists them, and the labeler puts `custom-mapping` on any pull request
that adds one.

**Monthly, and whenever MITRE publishes a release:**

1. Run `python3 check.py` and read the custom count.
2. For each custom pattern, check the latest ATLAS release for a technique that now fits.
   If one does, open a pull request mapping it and deleting `custom_reason`.
3. For a custom pattern with good evidence behind it, consider proposing it to MITRE ATLAS
   as a new technique. The registry leading ATLAS is the point; the registry permanently
   diverging from it is not.
4. If the count is growing without any of them being proposed upstream, raise it with the
   maintainers. That is the failure mode this step exists to catch.

## Adding a reviewer or a maintainer

Reviewers give binding approval in an area. Maintainers merge, cut releases and promote
patterns. The criteria are in [GOVERNANCE.md](../GOVERNANCE.md).

To add someone, in this order:

1. Nominate them in an issue labelled `proposal`. Wait 7 days for objections.
2. Add them to the right table in `MAINTAINERS.md`, through a pull request. Keep the row
   format: the GitHub handle is a link whose text is `@handle`, because
   `scripts/check_status_changes.py` parses it.
3. Add them to `.github/CODEOWNERS` for the paths they own.
4. Give them the GitHub permission: **Write** for a reviewer, **Maintain** for a
   maintainer. GitHub only counts an approval as binding from someone with Write, and a
   code owner must have Write, which is why the roles line up with the permissions.

To remove someone, reverse it, and say why in the pull request.

## GitHub settings checklist

Settings a maintainer should know are set, and who can set them. Several cannot be set
through the API and have to be clicked.

| Setting | Where | State |
| --- | --- | --- |
| Two-factor authentication required | Org, Settings, Authentication security | On |
| Base repository permission is Read | Org, Settings, Member privileges | On |
| Members may fork private repositories | Org, Settings, Member privileges | On |
| Run workflows from fork pull requests, read-only token, no secrets | Org and repo, Settings, Actions, General | On |
| Forking allowed on the repository | Repo, Settings, General | On |
| Discussions | Repo, Settings, General | On |
| Delete branch on merge | Repo, Settings, General | On |
| Require sign-off on web commits | Repo, Settings, General | On |
| Require approval for fork pull request workflows | Repo, Settings, Actions, General | On |
| Branch protection on `main` | Repo, Settings, Branches | On: a pull request is required, with the `check`, `signoff`, `status-guard` and `rule-safety` checks, linear history, and no force pushes or deletions |
| Secret scanning and push protection | Repo, Settings, Code security | On |
| Private vulnerability reporting | Repo, Settings, Code security | On |
| Dependabot alerts and security updates | Repo, Settings, Code security | On |
| Code scanning (CodeQL) | `.github/workflows/codeql.yml` | On, for `python` and `actions` |
| OpenSSF Scorecard | `.github/workflows/scorecard.yml` | On, weekly and on every push to `main` |

### Still to do

1. **Require a code owner review**, the moment there is a second maintainer. One approval
   is already required. With a single maintainer that approval cannot come from anyone, so
   the founding maintainer merges using the administrator override, which GitHub records on
   the pull request for anyone to see. The moment a second person can approve, that override
   stops being used and `enforce_admins` below should go on.
2. **Consider `enforce_admins`.** Branch protection currently does not apply to
   administrators, which is deliberate while there is one maintainer and no second pair of
   hands in an emergency. Turn it on once there are two.

## The project board

A board makes the queue visible, which matters more as contributors grow.

1. Repo, Projects, New project, Board.
2. Columns: **New**, **In review**, **Approved**, **Merged**.
3. Add a workflow so new issues and pull requests land in New, and merged pull requests
   move to Merged. GitHub's built-in project workflows do both.
4. Keep it honest: an item in Approved that nobody merges is a queue, not progress.

## The Season 1 board

A second, separate board for the Map phase, so 63 technique issues do not bury the normal
pull request queue.

1. Create the issues first, once: `bash scripts/create_season_one_issues.sh`. It is safe to
   run again; it reads every existing title and skips anything already there.
2. Repo, Projects, New project, Board. Name it **Season 1**.
3. Columns: **Open**, **Claimed**, **In review**, **Done**.
4. Set the board's filter to `label:season-1`, so it only ever shows Season 1 work.
5. Add a workflow: new issues with that label land in **Open**, closed issues move to
   **Done**.
6. Move an issue to **Claimed** when someone comments to claim it, and assign them. Nobody
   is assigned work they did not ask for.

The board is for people. The number that matters is generated instead: `docs/STATUS.md` is
built from the repository by `python3 scripts/build_status.py`, and `check.py` fails if it
is stale, so progress cannot drift from what the board claims.

**An issue claimed and quiet for 7 days** gets one friendly comment on the issue. After 14
days it is unassigned and returned to **Open**. Never chase in direct messages.

## Before the weekly meeting

```bash
python3 scripts/shipped.py --since 2026-10-04
```

It prints what landed on `main` since that date, grouped by the person who signed off, and
lists the patterns added and changed. Paste it into Slack. The people it names are the ones
who demo.

Pass the date of the last meeting. A bare date is fine: the script pins it to the start of
that day, because `git log --since` with a bare date silently skips everything committed on
the day itself.

## Credit

`scripts/build_contributors.py` builds `contributors.json` from the `Signed-off-by` lines in
the history, `CONTRIBUTORS.md` and the `credits` in pattern files. CI runs it on every push
to `main` and uploads the result as a build artifact for the website.

Nothing is committed by a bot, and nothing is maintained by hand. If someone is missing,
the fix is in `CONTRIBUTORS.md`, which is the opt-in for a display name, a GitHub handle
and whether to list an organization.

## Cutting a rule release

Sensors update from a published release, and check every file against a manifest of
SHA-256 hashes before they use any of it. Making the release is three commands.

```bash
python3 check.py
python3 scripts/build_release_manifest.py --out dist --rules-version r2026.10.29
gh release create v0.1 dist/* --title "Protocol v0.1" --notes-file RELEASE_NOTES.md
```

`build_release_manifest.py` copies `signatures.json`, writes `pattern-status.json` from the
pattern files, and writes `manifest.json` covering both with their hashes. Upload all three.
A member then runs:

```bash
python3 -m guardian_sensor update --base https://github.com/guardianprotocol-ai/registry/releases/download/v0.1
```

which fetches `manifest.json` first and refuses the whole update if any file does not match.

Two things to get right:

- **Rebuild the manifest last.** It hashes whatever is in the folder at the time. If you
  edit a file afterwards, every sensor will refuse the release, which is the correct
  behaviour and an embarrassing way to discover it.
- **The version string goes in the manifest**, and that is what members record in their
  `updates.jsonl` and report in their sightings. Use the same string in the git tag so a
  sighting can be traced to a commit.

This is integrity, not authenticity: it proves the files are the ones the manifest
describes, not that the release came from us. See `THREAT_MODEL.md`. Signing is v0.2.

## Releases

Not yet. The first is v0.1, targeted for October 29, 2026, per
[ROADMAP.md](../ROADMAP.md). When it happens the release notes name everyone who
contributed to it, taken from `contributors.json` rather than written by hand.
