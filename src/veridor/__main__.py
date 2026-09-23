"""``python -m veridor``: the same entry point as the ``veridor`` console script.

It lets Veridor run from a source checkout (``PYTHONPATH=src``) with no console
script installed, and it keeps the process exit code identical to the script's.
"""

from veridor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
