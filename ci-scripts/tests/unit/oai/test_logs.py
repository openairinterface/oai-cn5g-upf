# SPDX-License-Identifier: MIT
"""Tests for the OAI UPF's log patterns.

"""

from __future__ import annotations

from pfcpkit.inspect.logs import LogInspector, LogMark
from unit.fakes import FakeRunner
from upf_test.logs import OaiLogs

_LOG_TEXT = "\n".join(
    [
        "line one",
        "[eBPF] Modify Pipeline - Updating pipeline for session 0x1",
        "[eBPF] Modify Pipeline - Updating pipeline for session 0x1",
        "[eBPF] Modify Pipeline - Updating pipeline for session 0x2",
        "[eBPF] Create Pipeline - Creating pipeline for session 0x1",
        "[upf_app] [error] something broke",
        "[upf_app] [error] retrieveNextHopMAC: ARP unresolved for 192.168.72.141",
        "  QoS ENFORCEMENT SETUP  ",
        "  Failed to create PDU session class 1:2",
        "libbpf: prog 'upf_ingress': Exclusivity flag on, cannot modify",
    ]
)


def _logs(text: str = _LOG_TEXT) -> OaiLogs:
    return OaiLogs(LogInspector(FakeRunner({"docker logs": (0, text, "")}), "upf-test"))


def test_rebuild_count_is_per_session() -> None:
    """The SEID is part of the pattern, so two sessions never cross-count."""
    logs = _logs()
    assert logs.pipeline_rebuilds_since(LogMark(0), 0x1) == 2
    assert logs.pipeline_rebuilds_since(LogMark(0), 0x2) == 1
    assert logs.pipeline_rebuilds_since(LogMark(0), 0x3) == 0


def test_rebuild_count_respects_the_mark() -> None:
    """A window starting after those lines sees only later rebuilds."""
    assert _logs().pipeline_rebuilds_since(LogMark(3), 0x1) == 0


def test_the_seid_pattern_tolerates_zero_padding() -> None:
    """The UPF formats with ``SEID_FMT``; the pattern must not depend on that."""
    padded = "[eBPF] Modify Pipeline - Updating pipeline for session 0x0000000000000001"
    assert _logs(text=padded).pipeline_rebuilds_since(LogMark(0), 1) == 1


def test_the_seid_pattern_does_not_match_a_longer_seid() -> None:
    """0x1 must not match 0x11 -- a word boundary, not a prefix."""
    other = "[eBPF] Modify Pipeline - Updating pipeline for session 0x11"
    assert _logs(text=other).pipeline_rebuilds_since(LogMark(0), 1) == 0


def test_stable_count_settles_on_a_static_log() -> None:
    assert _logs().stable_pipeline_rebuilds_since(LogMark(0), 0x1) == 2


def test_pipeline_creates_are_counted_separately_from_rebuilds() -> None:
    """The UPF creates HTB classes only in Modify, never Create -- so the two
    counts have to be distinguishable."""
    logs = _logs()
    assert logs.pipeline_creates_since(LogMark(0), 0x1) == 1
    assert logs.pipeline_creates_since(LogMark(0), 0x2) == 0


def test_qos_setup_and_tc_failures_are_detected() -> None:
    logs = _logs()
    assert logs.qos_setups_since(LogMark(0)) == 1
    assert len(logs.tc_failures_since(LogMark(0))) == 1


def test_attach_refusals_are_detected() -> None:
    """The signature of programs accumulating without teardown."""
    assert len(_logs().attach_refusals_since(LogMark(0))) == 1


def test_errors_since_can_ignore_known_noise() -> None:
    logs = _logs()
    assert len(logs.errors_since(LogMark(0))) == 2
    filtered = logs.errors_since(LogMark(0), ignore=(r"ARP unresolved",))
    assert len(filtered) == 1
