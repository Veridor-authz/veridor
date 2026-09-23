"""Two test tiers, and the guard that stops the boundary between them rotting.

Veridor is meant to run on every commit. A suite that takes two and a
half minutes is not a suite you run on every commit -- it is a suite you run
before merge, sometimes, and that is how the full suite stopped being run
reliably while this product was being built. So the suite is split:

``fast``
    Pure unit tests. Config validation, fingerprints, parsing, scoring
    arithmetic, report rendering, documentation contracts. No sockets, no
    DNS, no subprocesses -- enforced, see below. Sleeping is not blocked: the
    rate-limiter tests sleep on a real clock, and what bounds them is the
    per-test budget in scripts/run_tests.py, not this guard. Runs on every
    commit.

``slow``
    Anything that stands up an HTTP server, drives a real loopback target, or
    spawns a subprocess. Runs before merge.

A tier split is only worth having if it stays true, and the usual failure is
silent: someone adds a server-backed test, forgets the marker, and the fast
tier quietly grows a socket. So membership is not a convention here, it is
enforced. :func:`install_fast_tier_guard` replaces every route to the network
or to a new process with a function that raises, and the fast tier runs with
the guard installed. An unmarked test that touches the network fails
immediately, by name, with the marker it is missing quoted in the message.

The routes (:func:`_guarded`): on ``socket.socket`` -- ``bind``, ``listen``
(which binds an unbound socket to every interface), ``connect``,
``connect_ex``, ``sendto``, ``sendmsg``; in ``socket`` -- ``getaddrinfo``,
``gethostbyname``, ``gethostbyname_ex``, ``gethostbyaddr``, ``getnameinfo``,
``create_connection``, ``create_server``; ``subprocess.Popen``; in ``os`` --
``system``, ``posix_spawn``, ``posix_spawnp``, ``fork``, ``forkpty`` and every
``exec*`` (``spawn*`` and ``popen`` go through these);
``_posixsubprocess.fork_exec`` (how multiprocessing's spawn and forkserver
start a process) and ``multiprocessing``'s ``Process.start``. Behind those, an
audit hook refuses the same operations at the C level --
``_socket.socket().connect`` never touches the patched Python class -- for as
long as a guard is installed.

It used to patch three of these: ``bind``, ``connect`` and ``Popen``. With it
installed, ``connect_ex`` reached the kernel, a UDP ``sendto`` went out, DNS
resolved, and ``os.system``, ``os.posix_spawn`` and ``os.fork`` started
processes (measured). A guard that stops the obvious call and not its sibling
is a tier boundary in name only.

What it cannot see: a C extension, or ``ctypes``, calling libc directly.

The guard is deliberately one-directional. A test wrongly marked ``slow``
costs a little time in the fast tier and nothing else; a test wrongly left in
the fast tier breaks the build. That is the right way round.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import unittest
from typing import Any, Callable, Iterator, TypeVar

# Every slow test imports this module for @slow, so importing loopback here
# puts its serve_forever guard in every process that runs one
# (loopback.install_server_guard).
import loopback  # noqa: F401,E402

#: Both tier names, plus the pseudo-tier that selects everything.
FAST = "fast"
SLOW = "slow"
ALL = "all"
TIERS = (FAST, SLOW, ALL)

#: The attribute :func:`slow` sets, read by :func:`tier_of`.
ATTRIBUTE = "veridor_test_tier"

#: Environment variable consulted by ``scripts/run_tests.py`` for its default.
ENV_VAR = "VERIDOR_TEST_TIER"

_T = TypeVar("_T")


class TierViolation(RuntimeError):
    """A fast-tier test reached for the network or a subprocess."""


def slow(reason: str) -> Callable[[_T], _T]:
    """Mark a test case class or test method as belonging to the slow tier.

    The reason is not decoration. It is the one place a reader can find out
    what a test actually costs without running it, and writing it down is what
    stops ``@slow`` being applied to a test that is merely awkward::

        @slow("stands up a loopback API and runs the engine against it")
        class TeardownTest(unittest.TestCase):
            ...

    Applied to a class, it covers every test method in the class, including
    ones inherited from it. Applied to a method, it covers that method only,
    which is what a mostly-pure class with one live-target test needs.
    """
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("@slow requires a non-empty reason")

    def decorate(obj: _T) -> _T:
        setattr(obj, ATTRIBUTE, SLOW)
        setattr(obj, ATTRIBUTE + "_reason", reason)
        return obj

    return decorate


def fast(reason: str) -> Callable[[_T], _T]:
    """Mark a test method as fast even though its class is marked slow.

    Live-target test classes usually hold one or two tests that never contact
    the target -- they assert on the configuration the class would have sent,
    or on the shape of a document. Those belong in the fast tier, and saying so
    on the method is both shorter and more informative than marking every one
    of its siblings slow.

    The guard still applies. A method marked fast that reaches the network
    fails the fast tier like any other, so this cannot be used to smuggle a
    live test past the boundary.
    """
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("@fast requires a non-empty reason")

    def decorate(obj: _T) -> _T:
        setattr(obj, ATTRIBUTE, FAST)
        setattr(obj, ATTRIBUTE + "_reason", reason)
        return obj

    return decorate


def tier_of(test: unittest.TestCase) -> str:
    """Return the tier a loaded test belongs to.

    A method marker wins over a class marker, so a slow class can hold a fast
    method and the other way round. Anything unmarked is fast -- the guard,
    not this default, is what makes that safe.
    """
    method = getattr(test, test._testMethodName, None)
    marker = getattr(method, ATTRIBUTE, None)
    if marker is None:
        marker = getattr(type(test), ATTRIBUTE, None)
    return SLOW if marker == SLOW else FAST


def iter_tests(suite: unittest.TestSuite) -> Iterator[unittest.TestCase]:
    """Flatten a suite, yielding leaf test cases in discovery order."""
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from iter_tests(item)
        else:
            yield item


def filter_suite(suite: unittest.TestSuite, tier: str) -> unittest.TestSuite:
    """Return the tests in ``suite`` that belong to ``tier``.

    Loader errors -- a module that failed to import -- are synthesised by
    unittest as ``_FailedTest`` cases. They are kept in every tier, because a
    suite that cannot be loaded must fail whichever tier you asked for.
    """
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}; expected one of {', '.join(TIERS)}")
    if tier == ALL:
        return suite
    selected = unittest.TestSuite()
    for test in iter_tests(suite):
        if type(test).__module__ == "unittest.loader" or tier_of(test) == tier:
            selected.addTest(test)
    return selected


def _blocked(what: str, hint: str) -> Callable[..., None]:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise TierViolation(
            f"the fast tier {what}. {hint} Mark this test "
            f'@slow("...") -- see tests/tiers.py -- or make it a pure unit test.'
        )

    return refuse


_NETWORK = ("does not make network connections", "Something here drove a live target.")
_LISTEN = ("does not open listening sockets", "Something here stood up a server.")
_DATAGRAM = ("does not send datagrams", "Something here sent a packet.")
_DNS = ("does not resolve host names", "Something here did a DNS lookup.")
_SPAWN = ("does not spawn subprocesses", "Something here shelled out.")
_FORK = ("does not fork", "Something here started a copy of the test process.")
_EXEC = ("does not exec", "Something here tried to replace the test process.")

_EXEC_FUNCTIONS = ("execv", "execve", "execl", "execle", "execlp", "execlpe", "execvp", "execvpe")


def _guarded() -> list[tuple[Any, str, tuple[str, str]]]:
    """``(owner, attribute, (what, hint))`` for every route the guard closes.

    Built at install time, and only from what exists on this platform, so a
    missing ``os.forkpty`` is not an ``AttributeError`` in the guard itself.
    """
    import multiprocessing.process  # noqa: PLC0415

    routes: list[tuple[Any, str, tuple[str, str]]] = [
        (socket.socket, "bind", _LISTEN),
        (socket.socket, "listen", _LISTEN),
        (socket.socket, "connect", _NETWORK),
        (socket.socket, "connect_ex", _NETWORK),
        (socket.socket, "sendto", _DATAGRAM),
        (socket.socket, "sendmsg", _DATAGRAM),
        (socket, "create_connection", _NETWORK),
        (socket, "create_server", _LISTEN),
        (socket, "getaddrinfo", _DNS),
        (socket, "gethostbyname", _DNS),
        (socket, "gethostbyname_ex", _DNS),
        (socket, "gethostbyaddr", _DNS),
        (socket, "getnameinfo", _DNS),
        (subprocess.Popen, "__init__", _SPAWN),
        (os, "system", _SPAWN),
        (os, "posix_spawn", _SPAWN),
        (os, "posix_spawnp", _SPAWN),
        (os, "fork", _FORK),
        (os, "forkpty", _FORK),
        (multiprocessing.process.BaseProcess, "start", _SPAWN),
    ]
    routes += [(os, name, _EXEC) for name in _EXEC_FUNCTIONS]
    try:
        import _posixsubprocess  # noqa: PLC0415
    except ImportError:  # not POSIX
        pass
    else:
        routes.append((_posixsubprocess, "fork_exec", _SPAWN))
    return [route for route in routes if hasattr(route[0], route[1])]


#: The same operations as audit events (PEP 578), raised by the C code itself.
#: This is what catches a route around the patched Python objects.
_AUDIT_EVENTS: dict[str, tuple[str, str]] = {
    "socket.bind": _LISTEN,
    "socket.connect": _NETWORK,
    "socket.sendto": _DATAGRAM,
    "socket.sendmsg": _DATAGRAM,
    "socket.getaddrinfo": _DNS,
    "socket.gethostbyname": _DNS,
    "socket.gethostbyaddr": _DNS,
    "socket.getnameinfo": _DNS,
    "subprocess.Popen": _SPAWN,
    "os.system": _SPAWN,
    "os.posix_spawn": _SPAWN,
    "os.spawn": _SPAWN,
    "os.fork": _FORK,
    "os.forkpty": _FORK,
    "os.exec": _EXEC,
}

#: How many guards are installed. An audit hook cannot be removed, so the one
#: hook stays registered and does nothing while this is zero.
_ACTIVE_GUARDS = 0
_AUDIT_HOOK_ADDED = False


def _audit(event: str, _args: tuple[object, ...]) -> None:
    if _ACTIVE_GUARDS and event in _AUDIT_EVENTS:
        what, hint = _AUDIT_EVENTS[event]
        _blocked(what, f"{hint} (audit event {event})")()


def install_fast_tier_guard() -> Callable[[], None]:
    """Make network, DNS and process creation raise for the rest of the process.

    Returns a callable that undoes the patches, so a caller running both tiers
    in one process can lift the guard before the slow tier. Guards nest: the
    callable restores what was there when this guard was installed, so undo
    them in reverse order.
    """
    global _ACTIVE_GUARDS, _AUDIT_HOOK_ADDED

    saved: list[tuple[Any, str, object, bool]] = []
    for owner, name, (what, hint) in _guarded():
        # Whether the attribute lived on the owner itself or was inherited
        # (socket.socket inherits connect_ex from _socket.socket) decides how
        # it is put back: an inherited one is deleted again, not pinned.
        saved.append((owner, name, getattr(owner, name), name in vars(owner)))
        setattr(owner, name, _blocked(what, hint))
    if not _AUDIT_HOOK_ADDED:
        sys.addaudithook(_audit)
        _AUDIT_HOOK_ADDED = True
    _ACTIVE_GUARDS += 1
    lifted = False

    def restore() -> None:
        global _ACTIVE_GUARDS
        nonlocal lifted
        if lifted:
            return
        lifted = True
        _ACTIVE_GUARDS -= 1
        for owner, name, original, own in reversed(saved):
            if own:
                setattr(owner, name, original)
            else:
                delattr(owner, name)

    return restore


def default_tier() -> str:
    """The tier named by :data:`ENV_VAR`, or ``all``."""
    tier = os.environ.get(ENV_VAR, ALL).strip().lower() or ALL
    if tier not in TIERS:
        raise ValueError(
            f"{ENV_VAR}={tier!r} is not a tier; expected one of {', '.join(TIERS)}"
        )
    return tier
