"""Loopback servers for the tests, started one way, and ports nobody else gets.

**Every test server starts here.** ``socketserver.BaseServer.serve_forever``
checks for a shutdown request once per ``poll_interval``, 0.5 s by default, and
``shutdown()`` blocks until that check. The select restarts after every
request, so a test that stops its server right after its last request waited
out nearly the whole half second: 486 ms, against 35 ms at 0.05 s (one request
then ``shutdown()``, median of 15, python3.12, 2026-09-27). The slow tier stops
hundreds of servers. ``tests/test_loopback.py`` refuses a ``serve_forever``
anywhere else under ``tests/``, so the default cannot come back one call site
at a time. That scan reads source, so a server reached another way --
``operator.methodcaller("serve_forever")``, a name built at run time, a
stdlib helper such as ``http.server.test`` -- passed it (measured). So
importing this module also replaces ``BaseServer.serve_forever`` in the test
process (:func:`install_server_guard`; ``tests/tiers.py`` imports this module,
so every process that runs a slow test has it): a server that would poll more
slowly than :data:`POLL_INTERVAL` is refused with a ``RuntimeError`` naming
this module, unless :func:`serve` started it.

**Ports.** A test that binds port 0, closes the socket and uses the number
later has released the port to the kernel, which hands it to the next
``bind(0)`` or outgoing ``connect()`` in any process -- another slow-tier shard
included. :func:`unallocated_port` returns a free port from outside the
kernel's ephemeral range instead, which neither call ever draws from. Holding
a bound socket that is not listening would not do: Linux refuses a connection
to it, but macOS leaves the SYN unanswered, so the client times out instead of
being refused, and a connect started before a late ``listen()`` succeeds on its
retransmit (measured on Darwin 25 and Linux 6.12). The kernel reserves
nothing for the caller, though, and a random pick in another process can
return the same number: two processes seeded alike picked the same port
(measured). Under ``--jobs``, each
worker draws from its own share of the candidates (:data:`WORKER_ENV`), so
no two workers of one run pick the same port, and a ``--jobs`` run started
inside a worker splits only that worker's share (:func:`worker_share`).
"""

from __future__ import annotations

import os
import random
import re
import socket
import sys
import threading
from pathlib import Path
from socketserver import BaseServer
from typing import Callable

#: How often a test server checks for shutdown. The stdlib default is 0.5 s.
POLL_INTERVAL = 0.05

#: Where :func:`unallocated_port` looks: below Linux's default ephemeral range
#: (32768-60999) and IANA's dynamic range (49152-65535, macOS and the BSDs).
_CANDIDATES = range(20000, 32768)

_LINUX_RANGE = Path("/proc/sys/net/ipv4/ip_local_port_range")

#: Set by ``scripts/run_tests.py --jobs`` for each worker, and inherited by
#: what it starts: ``INDEX/COUNT``. :func:`unallocated_port` draws from every
#: COUNT-th candidate, starting at INDEX, so two workers' shares never meet.
WORKER_ENV = "VERIDOR_TEST_WORKER"


def serve(server: BaseServer) -> None:
    """Serve on the calling thread until ``server.shutdown()``."""
    server.serve_forever(poll_interval=POLL_INTERVAL)


def install_server_guard() -> Callable[[], None]:
    """Make ``BaseServer.serve_forever`` refuse to poll more slowly than
    :data:`POLL_INTERVAL` unless :func:`serve` called it; return a function
    that puts the stdlib's back. Installing it twice wraps nothing twice."""
    current = BaseServer.serve_forever
    if getattr(current, "_loopback_guard", False):
        return lambda: None
    stdlib = current

    def serve_forever(self: BaseServer, poll_interval: float = 0.5) -> None:
        caller = sys._getframe(1).f_code  # noqa: SLF001
        started_here = caller.co_name == "serve" and caller.co_filename == serve.__code__.co_filename
        if poll_interval > POLL_INTERVAL and not started_here:
            # Closed first, so a client is refused at once rather than left
            # waiting on a listener nothing will ever answer.
            self.server_close()
            # And marked shut down, because the stdlib's serve_forever never
            # ran: BaseServer creates this Event unset and only serve_forever's
            # `finally` sets it, so an owner's shutdown() -- in a cleanup, say
            # -- would wait on it for ever. Measured: a refused server with
            # addCleanup(server.shutdown) hung the serial slow tier, and under
            # --jobs failed only when the 1200 s shard timeout fired.
            self._BaseServer__is_shut_down.set()  # noqa: SLF001
            raise RuntimeError(
                f"{type(self).__name__}.serve_forever(poll_interval={poll_interval}) in a test process: "
                f"it checks for shutdown every {poll_interval} s, so every shutdown() waits that long. "
                "Start test servers with loopback.start(server) or loopback.serve(server) "
                "(tests/loopback.py)."
            )
        return stdlib(self, poll_interval)

    serve_forever._loopback_guard = True  # type: ignore[attr-defined]
    serve_forever.__wrapped__ = stdlib  # type: ignore[attr-defined]
    BaseServer.serve_forever = serve_forever  # type: ignore[method-assign]

    def restore() -> None:
        BaseServer.serve_forever = stdlib  # type: ignore[method-assign]

    return restore


def start(server: BaseServer) -> threading.Thread:
    """Serve on a daemon thread; return the thread, already started."""
    thread = threading.Thread(target=serve, args=(server,), daemon=True)
    thread.start()
    return thread


def ephemeral_range() -> tuple[int, int]:
    """The ports this kernel hands out for ``bind(0)`` and ``connect()``."""
    try:
        low, high = _LINUX_RANGE.read_text(encoding="ascii").split()
        return int(low), int(high)
    except (OSError, ValueError):
        return 49152, 65535


Share = tuple[tuple[int, int], ...]


def worker_share() -> Share:
    """This process's share of the test ports, as a path of (INDEX, COUNT)
    levels read from :data:`WORKER_ENV`: ``((0, 1),)`` outside a worker,
    ``((1, 4),)`` for worker 2 of 4, and ``((1, 4), (0, 2))`` for worker 1 of
    2 in a ``--jobs`` run that worker 2 of 4 started.

    A path, because the suite runs ``--jobs`` inside ``--jobs``
    (ShardedRunTest, PlantedRunTest), and the runner used to OVERWRITE the
    variable: a nested worker's ``1/2`` split every candidate port again, so
    it overlapped the outer workers' shares (measured 2026-09-27: seed 7 gave
    port 25305 under both ``1/4`` and ``1/2``). The runner now appends a level,
    and each level splits only the one before it. A level that is not
    INDEX/COUNT with INDEX below COUNT is refused: the runner and this module
    would disagree about who owns which port."""
    value = os.environ.get(WORKER_ENV, "")
    if not value:
        return ((0, 1),)
    levels = []
    for level in value.split(","):
        match = re.fullmatch(r"(\d+)/(\d+)", level)
        if match is None or not int(match[1]) < int(match[2]):
            raise RuntimeError(f"{WORKER_ENV}={value!r}: {level!r} is not INDEX/COUNT with INDEX below COUNT")
        levels.append((int(match[1]), int(match[2])))
    return tuple(levels)


def candidate_ports(low: int, high: int, share: Share | tuple[int, int] = ((0, 1),)) -> list[int]:
    """The ports :func:`unallocated_port` may pick: outside the ephemeral range
    ``low``-``high``, and within this worker's ``share``, level by level. A
    single (INDEX, COUNT) is one level."""
    levels: Share = (share,) if share and isinstance(share[0], int) else share  # type: ignore[assignment]
    ports = [port for port in _CANDIDATES if not low <= port <= high]
    for index, count in levels:
        ports = ports[index::count]
    return ports


def unallocated_port() -> int:
    """A loopback port that is free now and that the kernel gives to nobody.

    Closed when returned, so connecting to it is refused until the caller
    binds it. No other process can be handed it by ``bind(0)`` or as the
    source port of a connection, because it lies outside the ephemeral range.
    Nothing reserves it, so another process's own pick can match it. A
    ``--jobs`` worker picks only from its own share (:func:`worker_share`), so
    no two workers of one run pick the same port, and a nested run's workers
    split only the share of the worker that started them. That worker and the
    nested run share one share, which is safe while it waits on the run.
    """
    low, high = ephemeral_range()
    candidates = candidate_ports(low, high, worker_share())
    if not candidates:
        raise RuntimeError(
            f"the ephemeral port range {low}-{high} covers every candidate port "
            f"({_CANDIDATES.start}-{_CANDIDATES.stop - 1}); a released port could be "
            "handed to another process, so there is no race-free choice here"
        )
    for port in random.sample(candidates, min(64, len(candidates))):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    raise RuntimeError(f"no free loopback port among 64 tries in {_CANDIDATES}")


install_server_guard()
