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
5. Merge. **Nobody merges their own change.** During the private preview that means the
   founding maintainer's changes wait for a second pair of eyes once a second maintainer
   exists; until then, say so in the pull request rather than pretending otherwise.

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

## Releases

Not yet. The first is v0.1, targeted for November 20, 2026, per
[ROADMAP.md](../ROADMAP.md). When it happens the release notes name everyone who
contributed to it, taken from `contributors.json` rather than written by hand.
