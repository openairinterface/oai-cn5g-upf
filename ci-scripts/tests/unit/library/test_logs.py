# SPDX-License-Identifier: MIT
"""Tests for the generic log window.

The library supplies *windowing* -- mark a position, then query only what arrived
after it. Which strings mean what is an adapter's business; the OAI patterns are
tested in :mod:`unit.oai.test_logs`.
"""

from __future__ import annotations

from pfcpkit.inspect.logs import LogInspector, LogMark
from unit.fakes import FakeRunner

_LOG_TEXT = "\n".join(
    [
        "line one",
        "widget created",
        "widget created",
        "line four",
        "[upf_app] [error] something broke",
        "[upf_app] [error] retrieveNextHopMAC: ARP unresolved for 192.168.72.141",
        "trailing line",
    ]
)


def _logs(text: str = _LOG_TEXT) -> LogInspector:
    return LogInspector(FakeRunner({"docker logs": (0, text, "")}), "upf-test")


def test_log_reads_request_merged_streams() -> None:
    """Regression: windows break unless stderr is merged in write order.

    The UPF logs to stdout and libbpf to stderr. Capturing them separately and
    concatenating puts all stderr after all stdout, so a line-count mark taken
    earlier points into the wrong place -- observed live as one scenario counting
    20 rebuilds and another counting 0 for the same operation, and as a
    tc-failure assertion passing with six failures sitting in the log.
    """
    runner = FakeRunner({"docker logs": (0, _LOG_TEXT, "")})
    LogInspector(runner, "upf-test").all_lines()
    assert runner.merge_flags == [True], "docker logs must be read with merge_stderr"


def test_mark_and_since_window_the_log() -> None:
    inspector = _logs()
    assert inspector.since(LogMark(0)) == _LOG_TEXT.splitlines()
    assert inspector.since(LogMark(5)) == _LOG_TEXT.splitlines()[5:]


def test_mark_records_the_current_length() -> None:
    assert _logs().mark() == LogMark(len(_LOG_TEXT.splitlines()))


def test_count_since_is_scoped_to_the_window() -> None:
    inspector = _logs()
    assert inspector.count_since(LogMark(0), r"widget created") == 2
    assert inspector.count_since(LogMark(3), r"widget created") == 0


def test_find_since_returns_the_matching_lines() -> None:
    found = _logs().find_since(LogMark(0), r"widget created")
    assert found == ["widget created", "widget created"]


def test_a_mark_past_the_end_yields_nothing() -> None:
    """A window opened after a log rotation must be empty, not the whole log."""
    assert _logs().since(LogMark(9999)) == []


def test_stable_count_settles_on_a_static_log() -> None:
    """With no new lines arriving, the polled count equals the immediate one."""
    inspector = _logs()
    assert inspector.stable_count_since(LogMark(0), r"widget created") == 2


def test_errors_since_can_ignore_known_noise() -> None:
    inspector = _logs()
    assert len(inspector.errors_since(LogMark(0))) == 2
    filtered = inspector.errors_since(LogMark(0), ignore=(r"ARP unresolved",))
    assert len(filtered) == 1
    assert "something broke" in filtered[0]
