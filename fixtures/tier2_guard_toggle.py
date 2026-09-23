#!/usr/bin/env python3
"""The worked example for Veridor's tier-2 target-mutation hook.

Tier 2 does not know your language and does not generate your mutation. You
supply two commands -- one that produces a build with a named guard removed, one
that puts the target back -- and Veridor runs the real suite in between. This
file is the smallest honest instance of that contract, in the exact argv shape a
real ``./scripts/mutate.sh`` would take::

    hook = TargetMutationHook(
        name="drop-tenant-filter",
        removes="the tenant predicate on /api/orders/{id}",
        apply_command=[sys.executable, "fixtures/tier2_guard_toggle.py",
                       "remove", guard],
        restore_command=[sys.executable, "fixtures/tier2_guard_toggle.py",
                         "restore", guard],
    )
    report = run_target_mutations(config_path, [hook], output_dir=out)

The guard here is a file that ``veridor_mutation_fixture`` reads on every
request: while it exists the tenant predicate runs and the outsider gets 404,
and while it is gone the owner's record is served to the outsider, marker and
all. A real hook does the same job with ``git apply`` and a rebuild, or by
flipping a policy flag in a staging deployment. The shape is identical, and so
is the discipline:

* exit ``0`` on success and non-zero on failure, because the exit status is the
  only thing Veridor reads -- stdout and stderr are discarded, since a build log
  is exactly the kind of artifact that carries a token;
* ``restore`` must be idempotent and must succeed even if ``remove`` failed
  part-way through, because Veridor runs it on every path including that one;
* ``remove`` should take out ONE guard. A build with three guards removed tells
  you the suite noticed something, not which something.

Run it by hand to see both halves::

    python3 fixtures/tier2_guard_toggle.py remove /tmp/tenant-guard
    python3 fixtures/tier2_guard_toggle.py restore /tmp/tenant-guard
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

#: Written by ``restore``. The fixture only checks for the file's existence, so
#: the contents are documentation for whoever finds it in a temp directory.
GUARD_CONTENT = "present\n"


def remove_guard(path: Path) -> int:
    """Remove the guard. Non-zero if it was not there to remove.

    Failing when the guard is already absent is deliberate: a mutate command
    that silently does nothing produces a "surviving" hook that only means the
    mutation never happened, and Veridor would have no way to tell that from a
    suite that genuinely missed the guard.
    """
    if not path.exists():
        print(f"guard {path} is already absent", file=sys.stderr)
        return 1
    path.unlink()
    return 0


def restore_guard(path: Path) -> int:
    """Put the guard back. Idempotent, and safe after a half-finished remove."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(GUARD_CONTENT, encoding="utf-8")
    except OSError as error:
        print(f"could not restore guard {path}: {error}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="tier-2 worked example")
    parser.add_argument("action", choices=("remove", "restore"))
    parser.add_argument("guard", help="path to the guard file")
    arguments = parser.parse_args(argv)
    path = Path(arguments.guard)
    if arguments.action == "remove":
        return remove_guard(path)
    return restore_guard(path)


if __name__ == "__main__":
    raise SystemExit(main())
