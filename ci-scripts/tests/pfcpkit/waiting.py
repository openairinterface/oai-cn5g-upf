# SPDX-License-Identifier: MIT
"""Polling helper for state that settles asynchronously.

Most UPF state does *not* need this: ``call_datapath`` runs the SessionManager
CRUD function on the N4 handler's own thread before the PFCP response is sent, so
BPF map writes and ``tc`` commands have already completed by the time a response
arrives. Assert directly wherever that holds -- an unnecessary poll just makes a
real failure take longer to report.

Reach for :func:`wait_until` only where something genuinely is asynchronous:
the UPF's ARP-update threads are detached, and ``docker logs`` can lag the
process by a few milliseconds.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")

DEFAULT_INTERVAL = 0.1


def wait_until(
    predicate: Callable[[], bool],
    *,
    timeout: float,
    interval: float = DEFAULT_INTERVAL,
) -> bool:
    """Poll ``predicate`` until it is true or ``timeout`` elapses.

    Returns whether it became true. Never raises on timeout: the caller records
    the outcome as a check, so a timeout reads as a normal assertion failure
    rather than an error.
    """
    deadline = time.monotonic() + timeout
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(min(interval, max(0.0, deadline - time.monotonic())))


def wait_for(
    supplier: Callable[[], T | None],
    *,
    timeout: float,
    interval: float = DEFAULT_INTERVAL,
) -> T | None:
    """Poll ``supplier`` until it returns a non-None value, or time out."""
    deadline = time.monotonic() + timeout
    while True:
        value = supplier()
        if value is not None:
            return value
        if time.monotonic() >= deadline:
            return None
        time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
