#!/usr/bin/env python3
"""Build ``dist/veridor-<version>.pyz``: Veridor as one file, run by any Python 3.11+.

    python3.12 scripts/build_zipapp.py                  # -> dist/veridor-0.1.0.pyz
    python3.12 scripts/build_zipapp.py --output-dir out
    python3.11 dist/veridor-0.1.0.pyz --version

The runtime is the standard library only, so the package plus a ``__main__``
is the whole program. The archive is the format ``zipapp`` writes -- a
``#!/usr/bin/env python3`` line followed by a zip -- but it is written here
entry by entry, because ``zipapp.create_archive`` stamps each entry with the
file's mtime and walks the directory in filesystem order. Here the entries are
sorted, every timestamp is 1980-01-01 00:00:00 (the zip epoch), permissions are
fixed, and nothing is compressed, so two builds of the same tree are
byte-identical and a published checksum can be reproduced from a checkout.

Stored rather than deflated on purpose. Measured 2026-09-24 with deflate: the
same tree gave one sha256 on macOS arm64 and Linux amd64 and a different one on
Linux arm64 (python:3.12-slim), because the deflate stream depends on the zlib
build. Stored entries depend only on the bytes.

It contains ``src/veridor`` (``*.py`` and the viewer's ``web/`` assets, never
``__pycache__``), a top-level ``__main__.py`` equivalent to
``python -m veridor``, and ``LICENSE`` and ``NOTICE``. Nothing else.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import stat
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "veridor"
SHEBANG = b"#!/usr/bin/env python3\n"
EPOCH = (1980, 1, 1, 0, 0, 0)
MAIN = (
    b'"""veridor.pyz: the same entry point as `python -m veridor`."""\n'
    b"import sys\n"
    b"if sys.version_info < (3, 11):\n"
    b"    sys.stderr.write('veridor needs Python 3.11 or newer; this is %d.%d (%s).\\n'\n"
    b"                     % (sys.version_info[0], sys.version_info[1], sys.executable))\n"
    b"    raise SystemExit(2)\n"
    b"from veridor.cli import main\n"
    b"raise SystemExit(main())\n"
)
#: Suffixes that belong in the archive. Anything else under src/veridor is refused
#: rather than silently packed or silently dropped.
SHIPPED = {".py", ".html", ".js", ".css", ".svg"}
SKIPPED_DIRS = {"__pycache__"}


def version() -> str:
    text = (PACKAGE / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', text, re.MULTILINE)
    if not match:
        raise SystemExit("build_zipapp: no __version__ in src/veridor/__init__.py")
    return match.group(1)


def entries() -> list[tuple[str, bytes]]:
    """(archive name, bytes) for every file, sorted by name."""
    found: list[tuple[str, bytes]] = []
    for path in sorted(PACKAGE.rglob("*")):
        relative = path.relative_to(PACKAGE.parent)
        if any(part in SKIPPED_DIRS for part in relative.parts):
            continue
        if path.is_dir():
            continue
        if path.suffix not in SHIPPED:
            raise SystemExit(
                f"build_zipapp: {relative} has a suffix this build does not ship "
                f"({path.suffix or 'none'}); add it to SHIPPED or remove the file."
            )
        found.append((relative.as_posix(), path.read_bytes()))
    for name in ("LICENSE", "NOTICE"):
        found.append((name, (ROOT / name).read_bytes()))
    found.append(("__main__.py", MAIN))
    return sorted(found)


def build() -> bytes:
    buffer = io.BytesIO()
    buffer.write(SHEBANG)
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries():
            info = zipfile.ZipInfo(name, date_time=EPOCH)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.create_system = 3  # unix, so the mode above is the one read back
            archive.writestr(info, data)
    return buffer.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--output-dir", default=str(ROOT / "dist"),
                        help="directory to write veridor-<version>.pyz into (default: dist/)")
    args = parser.parse_args(argv)
    data = build()
    output = Path(args.output_dir) / f"veridor-{version()}.pyz"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    output.chmod(0o755)
    print(f"{hashlib.sha256(data).hexdigest()}  {output}")
    return 0


if __name__ == "__main__":
    if sys.version_info < (3, 11):
        sys.stderr.write("build_zipapp.py needs Python 3.11 or newer.\n")
        raise SystemExit(2)
    raise SystemExit(main())
