# SPDX-License-Identifier: MIT
"""Tests for the generic ``tc`` inspector.

The fixtures are verbatim output from a running UPF (iproute2 5.15.0), not
invented. That matters most for the text format: ``-j`` is *silently ignored* for
``class show`` on that version, so the text parser is the path actually used in
practice and needs pinning against the real thing. A JSON fixture covers newer
iproute2, which does honour it.

Nothing here knows how any UPF derives its class ids -- that arithmetic belongs to
an adapter, and is tested in :mod:`unit.oai.test_class_ids`.
"""

from __future__ import annotations

import json

import pytest

from pfcpkit.errors import CommandFailed, InspectionError
from pfcpkit.inspect.runner import CommandResult
from pfcpkit.inspect.tc import TcInspector, handle
from unit.fakes import FakeRunner

#: `tc class show dev n3` -- plain text, because -j is ignored for classes.
TC_CLASSES_TEXT = (
    "class htb 1:bb parent 1:2 prio 0 rate 20Mbit ceil 40Mbit "
    "burst 1600b cburst 1600b \n"
    "class htb 1:2 root rate 10Gbit ceil 10Gbit burst 1680b cburst 1680b\n"
    "class htb 1:bc parent 1:3 prio 0 rate 50Mbit ceil 100Mbit "
    "burst 1600b cburst 1600b \n"
)

#: `tc -j qdisc show dev n3` -- qdiscs *do* honour -j.
TC_QDISC_JSON = json.dumps(
    [
        {
            "kind": "htb",
            "handle": "1:",
            "root": True,
            "refcnt": 15,
            "options": {"r2q": 1000, "default": "0x65535"},
        }
    ]
)


def _tc(text: str = TC_CLASSES_TEXT, qdisc: str = TC_QDISC_JSON) -> TcInspector:
    return TcInspector(
        FakeRunner({"class show": (0, text, ""), "qdisc show": (0, qdisc, "")})
    )


# ---------------------------------------------------------------------------
# CommandResult
# ---------------------------------------------------------------------------
def test_command_result_check_raises_with_context() -> None:
    result = CommandResult(("bpftool", "map"), 1, "", "boom")
    with pytest.raises(CommandFailed, match="boom"):
        result.check()


def test_command_result_rejects_empty_json() -> None:
    """Empty output must not be read as an empty result set."""
    result = CommandResult(("tc",), 0, "   ", "")
    with pytest.raises(InspectionError, match="empty output"):
        result.json()


def test_command_result_rejects_unparseable_json() -> None:
    result = CommandResult(("tc",), 0, "not json at all", "")
    with pytest.raises(InspectionError, match="could not parse JSON"):
        result.json()


# ---------------------------------------------------------------------------
# Handles
# ---------------------------------------------------------------------------
def test_handle_formats_the_minor_in_hex() -> None:
    """tc prints and parses class minors in hex, so the formatter must too."""
    assert handle(0xBC) == "1:bc"
    assert handle(2) == "1:2"
    assert handle(5, major=2) == "2:5"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def test_classes_parse_from_text() -> None:
    classes = _tc().classes("n3")
    assert [c.handle for c in classes] == ["1:bb", "1:2", "1:bc"]


def test_text_rates_convert_to_bits_per_second() -> None:
    leaf = _tc().class_by_handle("n3", "1:bb")
    assert leaf is not None
    assert leaf.rate == 20_000_000
    assert leaf.ceil == 40_000_000
    assert (leaf.rate_kbps, leaf.ceil_kbps) == (20_000, 40_000)


def test_gigabit_rate_parses() -> None:
    root = _tc().class_by_handle("n3", "1:2")
    assert root is not None
    assert root.rate == 10_000_000_000
    assert root.parent == "root"


def test_parent_is_captured() -> None:
    leaf = _tc().class_by_handle("n3", "1:bc")
    assert leaf is not None
    assert leaf.parent == "1:3"


def test_handles_compare_numerically_in_hex() -> None:
    """tc prints hex, so '1:bb' and '1:0bb' are the same class."""
    inspector = _tc()
    assert inspector.class_by_handle("n3", "1:0bb") is not None
    assert inspector.class_by_handle("n3", "1:BB") is not None


def test_rate_ceil_returns_a_pair() -> None:
    assert _tc().rate_ceil("n3", "1:bc") == (50_000_000, 100_000_000)


def test_rate_ceil_of_an_absent_class_is_none() -> None:
    assert _tc().rate_ceil("n3", "1:999") is None


def test_class_minors_are_sorted_decimal() -> None:
    assert _tc().class_minors("n3") == [2, 187, 188]


def test_no_classes_is_an_empty_list_not_an_error() -> None:
    assert _tc(text="").classes("n3") == []


def test_classes_parse_from_json_when_offered() -> None:
    """Newer iproute2 does emit JSON for classes; both paths must work."""
    payload = json.dumps(
        [
            {
                "class": "htb",
                "handle": "1:5",
                "parent": "1:2",
                "options": {"rate": 1_000_000, "ceil": 2_000_000},
            }
        ]
    )
    classes = _tc(text=payload).classes("n3")
    assert len(classes) == 1
    assert classes[0].rate == 1_000_000
    assert classes[0].ceil_kbps == 2_000


def test_qdiscs_detect_the_htb_root() -> None:
    assert _tc().has_htb_root("n3") is True


def test_missing_htb_root_is_reported() -> None:
    inspector = _tc(qdisc=json.dumps([{"kind": "noqueue", "handle": "0:"}]))
    assert inspector.has_htb_root("n3") is False


def test_tc_failure_raises_rather_than_returning_empty() -> None:
    inspector = TcInspector(FakeRunner({"class show": (1, "", "Cannot find device")}))
    with pytest.raises(InspectionError, match="Cannot find device"):
        inspector.classes("nope")
