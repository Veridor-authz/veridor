<!--
Security fixes go through SECURITY.md, not a public pull request.
-->

## What this changes, and why

<!-- The diff says what. Use this space for the reasoning that is not
recoverable from the code: what was wrong before and how you saw it, the
alternative rejected, the failure that motivated a guard. -->

## What you ran

- [ ] `python3.12 scripts/run_tests.py --tier fast`
- [ ] `python3.12 scripts/run_tests.py --tier slow`
- [ ] `python3.12 scripts/e2e_validation.py`
- [ ] If you touched the Action, a workflow, a CI template, the chart or the
      Kustomize base: the end-to-end check for it (CONTRIBUTING.md,
      "End-to-end checks"), and `actionlint` / `shellcheck` for workflow and
      shell changes
- [ ] If you changed a version string: `python3.12 scripts/release_check.py versions`
- [ ] If the test count changed: `python3.12 scripts/sync_doc_counts.py`

<!-- Say which of these you did NOT run, and why. A skipped check is fine;
an unstated one is not. -->

## Tests

<!-- Which new test covers this, and how do you know it bites? Say what you
broke to see it fail. Several tests here record exactly that, and it is the
habit that catches vacuous assertions. -->

## Claims

- [ ] This change makes no claim stronger than the evidence supports

<!-- If it touches a report, a message, a badge or a document, say which of
these it stays inside:

  coverage is ASSERTED, never ENFORCED
  a candidate is a hypothesis, never a finding
  a mutation score measures the declaration, not the target
  blast radius counts operations, not objects
  the marker oracle proves data flow, never policy
  drift reports what moved, never why

If it deliberately changes one of these, say so plainly: that is a real
decision and worth discussing, not a box to tick. -->
