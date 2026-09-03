# SPDX-License-Identifier: MIT
"""Tests for the OAI adapter: the capability protocols over bpftool and tc.

This is the seam every conformance scenario runs through, so it gets tested against
captured output from a live UPF. Two behaviours matter most and are easy to get
wrong silently:

* the UE-IP map is keyed in network byte order, so a lookup that got the endianness
  wrong would return ``None`` -- indistinguishable from "the session is not
  installed";
* the class a QoS assertion looks at is *derived*, not discovered, so the derivation
  and the lookup have to agree.
"""

from __future__ import annotations

import json
import struct

from pfcpkit.capabilities import Capability, LogSource, QosState, RuleState
from pfcpkit.inspect.bpftool import BpfMapInspector
from pfcpkit.inspect.logs import LogInspector
from pfcpkit.inspect.tc import TcInspector
from unit.fakes import FakeRunner
from upf_test import layouts
from upf_test.inspector import CAPABILITIES, OaiQosState, OaiRuleState
from upf_test.logs import OaiLogs

# ---------------------------------------------------------------------------
# Captured fixtures
# ---------------------------------------------------------------------------

#: `bpftool --json map dump name session_by_ue_i` -- BTF-formatted, UE 12.1.1.2.
UE_IP_DUMP = json.dumps(
    [{"key": 0x0C010102, "value": {"teid_ul": 286326784, "teid_dl": 0, "seid": 1}}]
)

_RULE_PDR1 = list(struct.pack("<H6xQ", 1, 1))
_RULE_PDR2 = list(struct.pack("<H6xQ", 2, 1))
_RULE_OTHER = list(struct.pack("<H6xQ", 1, 99))
RULES_DUMP = json.dumps(
    [
        {"key": _RULE_PDR1, "value": [0] * 8},
        {"key": _RULE_PDR2, "value": [0] * 8},
        {"key": _RULE_OTHER, "value": [0] * 8},
    ]
)

_SDF_QFI9 = list(struct.pack("<QB7x", 1, 9))
_SDF_QFI5 = list(struct.pack("<QB7x", 1, 5))
_SDF_OTHER = list(struct.pack("<QB7x", 99, 5))
SDF_DUMP = json.dumps(
    [
        {"key": _SDF_QFI9, "value": [0] * 8},
        {"key": _SDF_QFI5, "value": [0] * 8},
        {"key": _SDF_OTHER, "value": [0] * 8},
    ]
)

PDRS_PER_SESSION_DUMP = json.dumps([{"key": 1, "value": [0] * 8}])
RULES_ENABLED_DUMP = json.dumps([{"key": 1, "value": layouts.RULE_QER_ENABLED}])

#: `tc class show dev n3` for seid=3 qfi=5 (class 1:bc) plus its session class 1:3.
TC_CLASSES_TEXT = (
    "class htb 1:bc parent 1:3 prio 0 rate 50Mbit ceil 100Mbit "
    "burst 1600b cburst 1600b \n"
    "class htb 1:3 parent 1:2 rate 50Mbit ceil 100Mbit burst 1600b cburst 1600b\n"
    "class htb 1:2 root rate 10Gbit ceil 10Gbit burst 1680b cburst 1680b\n"
)
TC_QDISC_JSON = json.dumps([{"kind": "htb", "handle": "1:", "root": True}])


def _rules(dump: str) -> OaiRuleState:
    return OaiRuleState(
        BpfMapInspector(
            FakeRunner({"map dump": (0, dump, "")}), layouts.MAPS, bpftool="bpftool"
        )
    )


def _qos(text: str = TC_CLASSES_TEXT) -> OaiQosState:
    runner = FakeRunner(
        {"class show": (0, text, ""), "qdisc show": (0, TC_QDISC_JSON, "")}
    )
    return OaiQosState(TcInspector(runner), "n3")


# ---------------------------------------------------------------------------
# The adapter satisfies the protocols it claims
# ---------------------------------------------------------------------------
def test_the_adapter_implements_every_capability_it_advertises() -> None:
    """A structural check, since the protocols are ``runtime_checkable``.

    Advertising a capability the adapter cannot actually serve would surface as an
    ``AttributeError`` in the middle of a live run instead of here.
    """
    assert isinstance(_rules(RULES_DUMP), RuleState)
    assert isinstance(_qos(), QosState)
    assert isinstance(
        OaiLogs(LogInspector(FakeRunner({"docker logs": (0, "", "")}), "upf")),
        LogSource,
    )
    assert frozenset(
        {Capability.RULE_STATE, Capability.QOS_STATE, Capability.LOG_WINDOW}
    ) == CAPABILITIES


# ---------------------------------------------------------------------------
# RuleState
# ---------------------------------------------------------------------------
def test_installed_pdr_ids_are_scoped_to_the_session() -> None:
    state = _rules(RULES_DUMP)
    assert state.installed_pdr_ids(1) == [1, 2]
    assert state.installed_pdr_ids(99) == [1]
    assert state.installed_pdr_ids(12345) == []


def test_installed_qfis_come_from_the_sdf_map_and_are_sorted() -> None:
    state = _rules(SDF_DUMP)
    assert state.installed_qfis(1) == [5, 9]
    assert state.installed_qfis(12345) == []


def test_seid_for_ue_ip_matches_either_byte_order() -> None:
    """The map is keyed in network byte order; both orders are accepted.

    Rather than reproducing the conversion and risking an endianness mistake that
    would look exactly like an absent session, each key is compared both ways.
    """
    assert _rules(UE_IP_DUMP).seid_for_ue_ip("12.1.1.2") == 1


def test_seid_for_ue_ip_returns_none_when_absent() -> None:
    assert _rules(UE_IP_DUMP).seid_for_ue_ip("10.0.0.1") is None


def test_session_installed_reads_pdrs_per_session() -> None:
    state = _rules(PDRS_PER_SESSION_DUMP)
    assert state.session_installed(1) is True
    assert state.session_installed(2) is False


def test_rules_enabled_decodes_the_bitmask() -> None:
    state = _rules(RULES_ENABLED_DUMP)
    assert state.rules_enabled(1) == layouts.RULE_QER_ENABLED
    assert "QER" in state.describe_rules_enabled(1)
    assert state.rules_enabled(2) is None
    assert state.describe_rules_enabled(2) == "absent"


# ---------------------------------------------------------------------------
# QosState
# ---------------------------------------------------------------------------
def test_flow_lookup_uses_the_derived_class_id() -> None:
    """seid=3, qfi=5 -> 1:bc, which is in the captured fixture."""
    qos = _qos()
    assert qos.flow_handle(3, 5) == "1:bc"
    assert qos.flow_exists(3, 5) is True
    assert qos.flow_rate_kbps(3, 5) == (50_000, 100_000)


def test_an_absent_flow_reports_no_rate_rather_than_zero() -> None:
    """``None`` and ``(0, 0)`` mean different things to a rate assertion."""
    qos = _qos()
    assert qos.flow_exists(3, 9) is False
    assert qos.flow_rate_kbps(3, 9) is None


def test_session_shaper_is_found_by_the_truncated_seid() -> None:
    qos = _qos()
    assert qos.session_shaper_exists(3) is True
    assert qos.session_shaper_exists(0x1_0003) is True, "low 16 bits only"
    assert qos.session_shaper_exists(4) is False


def test_the_shared_root_is_reported_separately_from_the_classes() -> None:
    """Teardown leaves the root in place, so it has to be asked about on its own."""
    assert _qos().shaper_root_exists() is True
    assert _qos(text="").shaper_root_exists() is True
    assert _qos(text="").flow_exists(3, 5) is False
