"""Which Veridor the suite tests: this checkout's ``src/``, or the installed one.

Every test module used to do ``sys.path.insert(0, ROOT / "src")`` itself, and
``scripts/run_tests.py`` did it again. So "build the wheel, install it, run the
suite" -- the CI step that exists to prove the PACKAGE works -- imported the
checkout every time and proved nothing about the wheel. The insert now happens
here, once, and one environment variable decides it:

``VERIDOR_TEST_AGAINST=source`` (the default)
    ``src/`` goes first on ``sys.path``, and child processes the suite spawns
    get ``PYTHONPATH=src``.

``VERIDOR_TEST_AGAINST=installed``
    ``sys.path`` is left alone, so ``import veridor`` resolves to the package
    installed in this interpreter, and child processes get no ``PYTHONPATH``.

Any other value is refused rather than read as one of the two. Run
``python tests/source_path.py`` to print which one the current settings pick.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
ENV_VAR = "VERIDOR_TEST_AGAINST"
MODES = ("source", "installed")

MODE = os.environ.get(ENV_VAR, "source") or "source"
if MODE not in MODES:
    sys.stderr.write(
        f"{ENV_VAR}={MODE!r} is neither 'source' nor 'installed'; refusing to guess "
        "which Veridor the suite should test.\n"
    )
    raise SystemExit(2)


def use() -> None:
    """Put ``src/`` first on sys.path, unless testing the installed package."""
    if MODE == "source" and (not sys.path or sys.path[0] != str(SRC)):
        sys.path.insert(0, str(SRC))


def child_env(base: dict[str, str] | None = None, **extra: str) -> dict[str, str]:
    """An environment for a subprocess that must import the same Veridor."""
    env = dict(os.environ if base is None else base)
    if MODE == "source":
        env["PYTHONPATH"] = str(SRC)
    else:
        env.pop("PYTHONPATH", None)
    env.update(extra)
    return env


use()

if __name__ == "__main__":
    import veridor

    print(f"{ENV_VAR}={MODE} -> {Path(veridor.__file__).resolve().parent}")
