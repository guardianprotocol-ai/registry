## What and why

<!-- One or two sentences. Link the issue this closes, e.g. "Closes #12". -->

## Evidence

<!-- Paste the output that shows this works: check.py results, a scanner run with its attack success rate, or the corpus cases you added. -->

## Checklist

- [ ] `python3 check.py` passes
- [ ] Every commit is signed off (`git commit -s`)
- [ ] One idea per pull request
- [ ] If this changes what the sensor detects: a test or corpus case shows what it catches and what it leaves alone
- [ ] Payloads are harmless: canary tokens and `.test` destinations only
- [ ] Credit added: `credits` field for patterns, and `CONTRIBUTORS.md` if this is your first pull request
