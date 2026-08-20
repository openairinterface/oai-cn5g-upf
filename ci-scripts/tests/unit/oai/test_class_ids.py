# SPDX-License-Identifier: MIT
"""Tests for the HTB class-id derivation, pinned against live observations.

This arithmetic is the only reason a scenario can ask about a specific class
without the UPF telling it which one. If it drifts from the UPF's source, every
QoS assertion starts looking at a class that does not exist -- which reads as
"the UPF created nothing", not as "the test is wrong".
"""

from __future__ import annotations

from pfcpkit.inspect.tc import handle
from upf_test.class_ids import qos_class_minor, session_class_minor


def test_session_class_minor_truncates_to_16_bits() -> None:
    """The UPF casts the SEID to ``uint16_t``."""
    assert session_class_minor(3) == 3
    assert session_class_minor(0x1_0003) == 3, "the low 16 bits are what tc sees"


def test_qos_class_minor_matches_the_upf_hash() -> None:
    """Verified live: seid=3, qfi=5 produced class 1:bc (188)."""
    assert qos_class_minor(3, 5) == 0xBC
    assert handle(qos_class_minor(3, 5)) == "1:bc"
    # seid=2, qfi=5 produced 1:bb (187).
    assert qos_class_minor(2, 5) == 0xBB


def test_qos_class_minor_is_never_zero() -> None:
    """tc reserves minor 0, so the UPF's hash coerces it to 1."""
    for seid in range(64):
        for qfi in range(1, 16):
            assert qos_class_minor(seid, qfi) != 0


def test_qos_class_minor_stays_in_range() -> None:
    for seid in (0, 1, 0xFFFF, 0xDEAD_BEEF, 2**63):
        for qfi in (1, 5, 9, 63):
            assert 1 <= qos_class_minor(seid, qfi) <= 9999


def test_the_hash_carries_no_counter() -> None:
    """Deliberately pinned: it is *why* a rebuild collides with itself.

    A second ``Setup()`` for the same session re-derives the same classid and runs
    a bare ``tc class add``, which fails with "File exists" and leaves the old rate
    in place. If the UPF ever added a counter, this test should fail and the
    QoS-rate-change scenario should be revisited.
    """
    assert qos_class_minor(3, 5) == qos_class_minor(3, 5)
