#!/usr/bin/env python3
"""Starting the release image, and running it, must compile no Python module from source.

    python3 scripts/image_bytecode_check.py [--platform PLATFORM] IMAGE

The python base image ships no bytecode, and the image's user (uid 10001,
with PYTHONDONTWRITEBYTECODE set) cannot write any, so a module the build did
not compile is compiled from source every time it is imported. The Dockerfile
compiles what the CLI's verbs import at build time. Before it did, the only
bytecode was what pip wrote for its own imports: 6 modules the CLI needs
(difflib, http.server, secrets, xml.etree) compiled on every start, and moving
one ENV line made it 109, with the image, workflow and CI-config tests passing
(measured).

This asks the interpreter rather than the filesystem. It runs the image twice
under PYTHONVERBOSE=1, where CPython logs ``# code object from '<file>.pyc'``
for a module loaded from bytecode and ``# code object from <file>.py`` for one
it compiled from source:

* ``veridor --version``, the image's own entrypoint;
* ``veridor run`` of fixtures/veridor.demo.json against scripts/demo_server.py
  --vulnerable, started from the same image on a private docker network. It
  must exit 1, the demo's expected result. ``run`` imports modules ``import
  veridor.cli`` does not: when this checked ``--version`` alone and the build
  compiled only what ``veridor.cli`` imports, it passed while every ``run``
  compiled encodings.utf_16_le and utf_16_be from source (measured, 3 runs of
  3). tests/test_packaging.py holds the build's warm step to what every verb
  imports on the test machine; this holds the image to it for these two.

A .pyc that exists but no longer matches its source (a later step touched the
file) is compiled from source too, which a check for the file alone would pass.

Exit 0: neither compiled anything from source, each log shows veridor.cli
loaded from bytecode (so it is the CLI's verbose import log at all), and the
run loaded modules ``--version`` did not (so it is a run's).
Exit 1: a module was compiled from source, or a log does not show that.
Exit 2: usage; docker could not run the image; or the run did not exit 1, so
its log shows nothing either way.
"""

from __future__ import annotations

import argparse
import re
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO_SERVER = ROOT / "scripts" / "demo_server.py"
DEMO_CONFIG = ROOT / "fixtures" / "veridor.demo.json"
DEMO_PORT = 8765
#: What `veridor run` of the demo config exits against the vulnerable demo.
RUN_EXIT = 1

#: CPython's verbose import lines (importlib._bootstrap_external, 3.12): the
#: bytecode path is logged with repr(), the source path without quotes.
FROM_BYTECODE = re.compile(r"^# code object from '(?P<path>[^']+\.pyc)'$", re.M)
FROM_SOURCE = re.compile(r"^# code object from (?P<path>[^'\s][^\n]*\.py)$", re.M)
CLI_BYTECODE = re.compile(r"/veridor/__pycache__/cli\.cpython-\d+\.pyc$")


def problems(log: str, when: str = "start") -> list[str]:
    """What the verbose log of one start shows was wrong, or [] if nothing."""
    found = [f"compiled from source on every {when}: {m['path']}" for m in FROM_SOURCE.finditer(log)]
    if not any(CLI_BYTECODE.search(m["path"]) for m in FROM_BYTECODE.finditer(log)):
        found.append("the log never shows veridor.cli loaded from bytecode, so it is not the verbose "
                     "import log of the CLI and shows nothing either way")
    return found


def loaded(log: str) -> set[str]:
    return {m["path"] for m in FROM_BYTECODE.finditer(log)}


def verdict(version_log: str, run_log: str) -> list[str]:
    """Everything wrong with a --version log and a run log, or []."""
    found = [f"--version: {problem}" for problem in problems(version_log)]
    found += [f"run: {problem}" for problem in problems(run_log, "run")]
    if not found and not loaded(run_log) - loaded(version_log):
        found.append("run: the log loads no module that --version does not, so it is not the import "
                     "log of a run and shows nothing about one")
    return found


def _docker(*args: str, timeout: float = 300) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)


def run_demo(image: str, platform: list[str]) -> subprocess.CompletedProcess:
    """`veridor run` of the demo config against the vulnerable demo, on a
    private network, under PYTHONVERBOSE=1. Removes what it started."""
    name = f"veridor-bytecode-{secrets.token_hex(4)}"
    try:
        for args in (("network", "create", name),
                     ("run", "-d", "--name", f"{name}-demo", "--network", name, "--network-alias", "demo",
                      *platform, "-v", f"{DEMO_SERVER}:/demo/demo_server.py:ro", "--entrypoint", "python3",
                      image, "/demo/demo_server.py", "--host", "0.0.0.0", "--port", str(DEMO_PORT),
                      "--vulnerable")):
            started = _docker(*args)
            if started.returncode != 0:
                raise OSError(f"`docker {' '.join(args[:2])}` exited {started.returncode}: "
                              f"{started.stderr.strip()[-500:]}")
        return _docker("run", "--rm", "--name", f"{name}-run", "--network", name, *platform,
                       "-e", "PYTHONVERBOSE=1", "-v", f"{DEMO_CONFIG}:/config/veridor.json:ro", image,
                       "run", "--config", "/config/veridor.json", "--base-url", f"http://demo:{DEMO_PORT}",
                       "--wait-for-target", "60", "--require-complete", "--output-dir", "/tmp/veridor")
    finally:
        _docker("rm", "-f", f"{name}-run", f"{name}-demo", timeout=60)
        _docker("network", "rm", name, timeout=60)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--platform", help="run the image as this platform, e.g. linux/arm64")
    parser.add_argument("image")
    try:
        args = parser.parse_args(argv[1:])
    except SystemExit as exc:
        return 2 if exc.code else 0
    image = args.image
    platform = ["--platform", args.platform] if args.platform else []
    try:
        version = _docker("run", "--rm", *platform, "-e", "PYTHONVERBOSE=1", image, "--version", timeout=120)
        if version.returncode != 0:
            print(version.stdout + version.stderr[-2000:], file=sys.stderr)
            print(f"image_bytecode_check: `docker run {image} --version` exited {version.returncode}",
                  file=sys.stderr)
            return 2
        run = run_demo(image, platform)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"image_bytecode_check: could not run docker: {exc}", file=sys.stderr)
        return 2
    if run.returncode != RUN_EXIT:
        print(run.stdout[-2000:] + run.stderr[-4000:], file=sys.stderr)
        print(f"image_bytecode_check: `veridor run` of the demo in {image} exited {run.returncode}, expected "
              f"{RUN_EXIT} against the vulnerable demo, so its log shows nothing either way", file=sys.stderr)
        return 2
    version_log, run_log = version.stdout + version.stderr, run.stdout + run.stderr
    found = verdict(version_log, run_log)
    for problem in found:
        print(f"image_bytecode_check: {image}: {problem}", file=sys.stderr)
    if found:
        return 1
    print(f"image_bytecode_check: {image}: --version loaded {len(loaded(version_log))} modules from bytecode "
          f"and a run {len(loaded(run_log))}, 0 compiled from source")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
