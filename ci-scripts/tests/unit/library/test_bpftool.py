# SPDX-License-Identifier: MIT
"""Tests for the generic BPF map inspector.

Dumps are captured from a live UPF, covering both shapes ``bpftool`` produces: a
BTF build emits decoded keys and values, a BTF-less build emits raw byte arrays.
"""

from __future__ import annotations

import json
import struct

import pytest

from pfcpkit.errors import MapNotFound
from pfcpkit.inspect.bpftool import BpfMapInspector
from pfcpkit.inspect.layouts import MapSpec, StructLayout
from unit.fakes import FakeRunner

# ---------------------------------------------------------------------------
# A catalogue local to this test
# ---------------------------------------------------------------------------
RULE_KEY = StructLayout("<H6xQ", ("pdr_id", "seid"))
IDS_VALUE = StructLayout("<IIQ", ("teid_ul", "teid_dl", "seid"))

CATALOGUE = {
    "rules_match_pdr_map": MapSpec(
        "rules_match_pdr_map", seid_source="key", key_layout=RULE_KEY
    ),
    "session_by_ue_ip_map": MapSpec(
        "session_by_ue_ip_map", seid_source="value", value_layout=IDS_VALUE
    ),
    "counts_map": MapSpec("counts_map", seid_source="key", seid_field=None),
}

#: A BTF build's output: key and value already decoded.
BTF_DUMP = json.dumps(
    [{"key": 0x0C010102, "value": {"teid_ul": 286326784, "teid_dl": 0, "seid": 1}}]
)

#: A BTF-less build's output: raw byte arrays needing the struct layout.
_RAW_PDR1 = list(struct.pack("<H6xQ", 1, 1))
_RAW_PDR2 = list(struct.pack("<H6xQ", 2, 1))
_RAW_OTHER = list(struct.pack("<H6xQ", 1, 99))
RAW_DUMP = json.dumps(
    [
        {"key": _RAW_PDR1, "value": [0] * 8},
        {"key": _RAW_PDR2, "value": [0] * 8},
        {"key": _RAW_OTHER, "value": [0] * 8},
    ]
)


def _bpf(dump: str, *, show: str | None = None) -> BpfMapInspector:
    responses = {
        "map dump": (0, dump, ""),
        "map show": (
            0,
            show if show is not None else json.dumps([{"name": "rules_match_pdr"}]),
            "",
        ),
    }
    return BpfMapInspector(FakeRunner(responses), CATALOGUE, bpftool="bpftool")


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------
def test_btf_formatted_value_is_used_directly() -> None:
    entries = _bpf(BTF_DUMP).dump("session_by_ue_ip_map")
    assert len(entries) == 1
    assert entries[0].value_field("seid") == 1
    assert entries[0].value_field("teid_ul") == 286326784


def test_raw_keys_decode_through_the_struct_layout() -> None:
    entries = _bpf(RAW_DUMP).dump("rules_match_pdr_map")
    assert len(entries) == 3
    assert entries[0].key_field("pdr_id") == 1
    assert entries[0].key_field("seid") == 1


# ---------------------------------------------------------------------------
# SEID filtering
# ---------------------------------------------------------------------------
def test_entries_are_filtered_by_seid() -> None:
    inspector = _bpf(RAW_DUMP)
    assert inspector.count_for_seid("rules_match_pdr_map", 1) == 2
    assert inspector.count_for_seid("rules_match_pdr_map", 99) == 1
    assert inspector.count_for_seid("rules_match_pdr_map", 12345) == 0


def test_pdr_ids_for_seid_are_sorted() -> None:
    assert _bpf(RAW_DUMP).pdr_ids_for_seid("rules_match_pdr_map", 1) == [1, 2]


def test_seid_can_be_read_from_the_value() -> None:
    """A map keyed by something else still has to be filterable by session."""
    assert _bpf(BTF_DUMP).count_for_seid("session_by_ue_ip_map", 1) == 1
    assert _bpf(BTF_DUMP).count_for_seid("session_by_ue_ip_map", 2) == 0


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------
def test_missing_map_raises_rather_than_returning_empty() -> None:
    """"No map" and "no entries" mean very different things.

    Conflating them turns every absence assertion into a pass.
    """
    inspector = BpfMapInspector(
        FakeRunner({"map dump": (255, "", "Error: bpf obj get: No such file")}),
        CATALOGUE,
        bpftool="bpftool",
    )
    with pytest.raises(MapNotFound):
        inspector.dump("rules_match_pdr_map")


def test_an_uncatalogued_map_is_a_key_error() -> None:
    with pytest.raises(KeyError, match="unknown map"):
        _bpf("[]").dump("no_such_map")


# ---------------------------------------------------------------------------
# Name truncation, end to end
# ---------------------------------------------------------------------------
def test_map_exists_uses_the_truncated_name() -> None:
    inspector = _bpf("[]", show=json.dumps([{"name": "session_by_ue_i"}]))
    assert inspector.map_exists("session_by_ue_ip_map") is True
    assert inspector.map_exists("rules_match_pdr_map") is False


def test_dump_asks_bpftool_for_the_truncated_name() -> None:
    runner = FakeRunner({"map dump": (0, "[]", "")})
    BpfMapInspector(runner, CATALOGUE, bpftool="bpftool").dump("session_by_ue_ip_map")
    argv = " ".join(runner.calls[0])
    assert "session_by_ue_i" in argv
    assert "session_by_ue_ip_map" not in argv, "the kernel never sees the full name"
