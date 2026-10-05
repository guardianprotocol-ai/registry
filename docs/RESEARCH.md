# Research and authorship policy

How this project publishes research, and how someone becomes an author on it.

The group's name is **Guardian Protocol Research Group**. That name is **proposed, not
decided**: the group confirms or changes it at the kickoff. Until then every document here
says it is proposed.

This policy exists before the first paper on purpose. Authorship disputes are easy to avoid
in advance and miserable to settle afterwards.

## Byline

> by the Guardian Protocol Research Group

followed by the full author list with affiliations, in the order described below.

The group is a working group of YC founders and researchers. That is a description of who
takes part, not part of the name. **Y Combinator's name does not appear in the group's name
or in any byline without Y Combinator's written permission**, and neither does any member
company's.

## Who is an author

An author is someone who has done all three of these for that publication:

1. Made a substantive contribution: design, measurement, analysis or writing.
2. Approved the final draft.
3. Is accountable for it, and is willing to answer questions about the part they did.

Everyone else who helped is **acknowledged** by name, which is not a lesser thing: running
the infrastructure, reviewing a draft, or contributing a pattern the study used are all
worth naming.

Contributing a measurement that a study relies on is a substantive contribution. If your
result files are in the data, you are an author unless you ask not to be.

## Order

Alphabetical by last name, unless the authors agree otherwise **in writing** before
submission. Alphabetical is the default because it is the only order that needs no argument.

## Conflicts of interest

Every author discloses relevant affiliations, including any company building on the
protocol. A company affiliation does not disqualify anyone from authorship; hiding it does.

Where a study measures a product sold by an author's employer, that is stated in the paper
near the result, not in a footnote at the end.

## Approval

Every author approves the final version before it is submitted anywhere. Each author is
responsible for checking with their own employer before their name appears. Nobody adds a
name on someone's behalf.

## Results

Only numbers that pass the checks in [../results/README.md](../results/README.md) may be
published: run counts and intervals attached, arithmetic recomputed. The publication rules
in [../SECURITY.md](../SECURITY.md) apply before anything goes out, so a result that should
have been reported privately first does not reach a preprint instead.

Every publication names the registry commit its data came from, so a reader can check the
numbers against the matrix as it stood that day.

## Where we publish

The project site and arXiv first, so the work is readable by anyone the day it exists.
Workshops and conferences after that, where the venue allows a preprint, which almost all
of them now do.

## Licensing

Text under **CC BY 4.0**. Code and data under the repository's license, Apache 2.0. A
publication must be readable and reusable without asking anyone's permission, including
ours.

## Where work lives while it is unfinished

Raw experiment data from members' companies, anything naming a participating company,
findings waiting on coordinated disclosure, and drafts live in the private
`guardianprotocol-ai/research` repository, which only members can read. On publication the
anonymized data, the results and the paper move to the public registry.

Nothing about a named company goes in the public repository before that company has agreed
to it, and no finding is published before the disclosure process in
[../SECURITY.md](../SECURITY.md) has run. A company can withdraw at any time and have its
data removed before publication.

## Roles

The group has one role so far, and it is an organizing one rather than a scientific one.

**Organizer, Guardian Protocol Research Group.** Keeps the work visible and moving: one
public list of tasks, a generated status page, a predictable weekly rhythm, fast reviews,
and credit given loudly. Not "lead researcher" and not "director": the organizer does not
set the findings, and taking part needs no permission from them.

On each paper, a **corresponding author** coordinates it and handles contact afterwards.
That is a job on one paper, not a standing title, and author order follows the rule above.

The group may create further roles. When it does, they are recorded in
[../GOVERNANCE.md](../GOVERNANCE.md) rather than here.

## How to propose a publication

Open an issue labelled `proposal` with the question, what would be measured, and what would
make the result worth publishing. The group sets the research agenda, as described in
[../GOVERNANCE.md](../GOVERNANCE.md).
