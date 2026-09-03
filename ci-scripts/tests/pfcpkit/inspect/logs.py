# SPDX-License-Identifier: MIT
"""Windowed log inspection.

Counting occurrences of a log line is often the only way to observe how many times
a UPF did something internally. The *patterns* are implementation-specific and
belong in an adapter; the windowing mechanics are not, so only the mechanics are
here.

``docker logs`` is a host-side operation, so this takes its own runner rather than
the ``docker exec`` one used for in-container tools.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass

from .runner import CommandRunner

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LogMark:
    """A position in the log, as a line count."""

    line_count: int

    def describe(self) -> str:
        return f"line {self.line_count}"


class LogInspector:
    """Reads and windows a container's logs."""

    def __init__(self, runner: CommandRunner, container: str) -> None:
        self._runner = runner
        self._container = container

    # -- reading -----------------------------------------------------------
    def all_lines(self) -> list[str]:
        """Every log line, stdout and stderr interleaved in write order.

        ``merge_stderr`` matters and is not a detail: the UPF logs through spdlog
        to stdout while libbpf writes diagnostics to stderr. Capturing the two
        separately and concatenating them puts every stderr line after every
        stdout line, so a line-count mark taken earlier no longer points where you
        think it does -- windows then silently include unrelated history and
        exclude the lines you were measuring. Merging at the fd level preserves
        chronology.
        """
        result = self._runner.run(
            ["docker", "logs", self._container], merge_stderr=True
        ).check()
        return result.stdout.splitlines()

    def mark(self) -> LogMark:
        """Capture the current end of the log, to window a later read."""
        mark = LogMark(len(self.all_lines()))
        logger.debug("log mark at %s", mark.describe())
        return mark

    def since(self, mark: LogMark) -> list[str]:
        """Lines written after ``mark``."""
        return self.all_lines()[mark.line_count :]

    # -- matching ----------------------------------------------------------
    def find_since(self, mark: LogMark, pattern: str) -> list[str]:
        """Lines after ``mark`` matching a regular expression."""
        regex = re.compile(pattern)
        return [line for line in self.since(mark) if regex.search(line)]

    def count_since(self, mark: LogMark, pattern: str) -> int:
        """How many lines after ``mark`` match a regular expression.

        Counts what is visible *now*. ``docker logs`` lags the process by a few
        hundred milliseconds, so counting immediately after a PFCP response can
        legitimately return zero for work that has already happened. Prefer
        :meth:`stable_count_since` when the count is the assertion.
        """
        return len(self.find_since(mark, pattern))

    def stable_count_since(
        self,
        mark: LogMark,
        pattern: str,
        *,
        settle: float = 0.5,
        timeout: float = 8.0,
        interval: float = 0.15,
    ) -> int:
        """Count matches, waiting until the count stops changing.

        Polls until the match count has held steady for ``settle`` seconds, or
        ``timeout`` elapses. This is deliberately pattern-scoped rather than
        waiting for the whole log to go quiet, so unrelated traffic (heartbeats,
        another session's activity) cannot keep it spinning.

        Measuring this way rather than sleeping a fixed amount keeps the assertion
        honest: a genuinely-zero count settles immediately instead of being
        indistinguishable from a count that had not appeared yet.
        """
        deadline = time.monotonic() + timeout
        last = self.count_since(mark, pattern)
        steady_since = time.monotonic()

        while time.monotonic() < deadline:
            time.sleep(interval)
            current = self.count_since(mark, pattern)
            if current != last:
                last = current
                steady_since = time.monotonic()
                continue
            if time.monotonic() - steady_since >= settle:
                return current

        logger.warning(
            "log count for %r never settled within %.1fs (last=%d)",
            pattern,
            timeout,
            last,
        )
        return last

    def errors_since(self, mark: LogMark, *, ignore: tuple[str, ...] = ()) -> list[str]:
        """``[error]`` lines after ``mark``, minus any matching ``ignore``.

        Useful as a broad regression guard -- "this modification logged nothing
        at error level" catches problems no targeted pattern anticipated. It only
        works against a clean baseline, which is why the environment includes a
        gNB stand-in: without it every downlink FAR logs an ARP failure and this
        would need a permanent allowlist.
        """
        ignored = [re.compile(p) for p in ignore]
        return [
            line
            for line in self.find_since(mark, r"\[error\]")
            if not any(r.search(line) for r in ignored)
        ]
