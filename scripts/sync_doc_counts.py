#!/usr/bin/env python3.12
"""Write the real test-tier counts into README.md.

``tests/test_docs.TierTableTest`` asserts that table against the counts the
runner actually discovers, because it went stale three times in three days and
a number nobody derives is a number nobody checks. The consequence is that
adding a test turns the suite red until the table is updated, which is correct
but tedious to do by hand -- so this does it::

    python3.12 scripts/sync_doc_counts.py [--check] [PATH ...]

Each PATH names another document carrying the same table, relative to the
current directory, to sync alongside README.md. Naming one that is missing, or
that has no table, is an error and nothing is written.

It touches nothing but the digits in those tables and prints what it changed.
With ``--check`` it writes nothing and exits 1 if a document is stale, so CI can
use it as a check rather than a fixer.
"""

from __future__ import annotations

import argparse
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import source_path  # noqa: E402,F401 -- src/ first unless VERIDOR_TEST_AGAINST=installed

from tiers import ALL, FAST, SLOW, filter_suite, iter_tests  # noqa: E402

#: Every place a tier count is written down. Each pattern captures the prose
#: around the number so only the digits move.
PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(\| `fast` \| )[\d,]+( \|)", "fast"),
    (r"(\| `slow` \| )[\d,]+( \|)", "slow"),
    (r"(\| both \| )[\d,]+( \|)", "all"),
    (r"(--tier fast` \| )[\d,]+( \|)", "fast"),
    (r"(--tier slow` \| )[\d,]+( \|)", "slow"),
    (r"(\(both\) \| )[\d,]+( \|)", "all"),
    (r"(\*\*)[\d,]+( tests passing\*\*)", "all"),
)

README = "README.md"


def counts() -> dict[str, int]:
    """Discover exactly the way ``scripts/run_tests.py`` does."""
    discovered = unittest.TestLoader().discover(
        str(ROOT / "tests"), top_level_dir=str(ROOT / "tests")
    )
    return {
        "fast": len(list(iter_tests(filter_suite(discovered, FAST)))),
        "slow": len(list(iter_tests(filter_suite(discovered, SLOW)))),
        "all": len(list(iter_tests(filter_suite(discovered, ALL)))),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift and exit 1 without writing anything",
    )
    parser.add_argument(
        "documents",
        nargs="*",
        metavar="PATH",
        help="another document carrying the tables, synced alongside README.md",
    )
    args = parser.parse_args(argv)

    totals = counts()
    if totals["fast"] + totals["slow"] != totals["all"]:
        print(
            f"the tiers do not partition the suite: "
            f"{totals['fast']} + {totals['slow']} != {totals['all']}",
            file=sys.stderr,
        )
        return 2

    print(f"measured: fast {totals['fast']:,} · slow {totals['slow']:,} · both {totals['all']:,}")
    targets = [(README, ROOT / README), *((name, Path(name)) for name in args.documents)]
    originals = {}
    for name, path in targets:
        # Refuse before writing anything. Skipping a document it was told to sync
        # would report success for a sync that never ran, and one with no table
        # would read as already carrying the real counts.
        if not path.is_file():
            print(f"missing document {name}", file=sys.stderr)
            return 2
        originals[name] = path.read_text(encoding="utf-8")
        if not any(re.search(pattern, originals[name]) for pattern, _ in PATTERNS):
            print(f"no tier table in {name}", file=sys.stderr)
            return 2

    stale = False
    for name, path in targets:
        original = originals[name]
        text = original
        for pattern, key in PATTERNS:
            text = re.sub(pattern, rf"\g<1>{totals[key]:,}\g<2>", text)
        if text == original:
            continue
        stale = True
        if args.check:
            print(f"STALE: {name}")
        else:
            path.write_text(text, encoding="utf-8")
            print(f"updated {name}")

    if not stale:
        print("every document already carries the real counts")
    return 1 if (stale and args.check) else 0


if __name__ == "__main__":
    raise SystemExit(main())
