# SPDX-License-Identifier: MIT
"""Tests for the OAI UPF's BPF map catalogue.

Every expected value here was confirmed against a running UPF rather than read off
the headers alone -- the truncated names via ``bpftool map show``, the struct sizes
by decoding real dumps. Both are the kind of fact that makes an *absence*
assertion pass for the wrong reason when it drifts, so they are pinned rather than
trusted.

The machinery these apply to is tested in :mod:`unit.library.test_layouts`.
"""

from __future__ import annotations

import struct

import pytest

from pfcpkit.inspect import layouts as generic
from upf_test import layouts
from upf_test.layouts import (
    MAPS,
    PDRS_PER_SESSION,
    SESSION_ID,
    SESSION_QFI,
    describe_rules_enabled,
    spec_for,
)


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("logical", "expected"),
    [
        ("session_by_ue_ip_map", "session_by_ue_i"),
        ("rules_match_pdr_map", "rules_match_pdr"),
        ("pdrs_per_session_map", "pdrs_per_sessio"),
        ("eth_rules_match_pdr_map", "eth_rules_match"),
        ("session_rules_enabled_map", "session_rules_e"),
        ("sdf_filters_map", "sdf_filters_map"),
    ],
)
def test_catalogued_names_match_the_kernel_form(logical: str, expected: str) -> None:
    assert MAPS[logical].name == expected


def test_every_catalogued_map_name_fits() -> None:
    for spec in MAPS.values():
        assert len(spec.name) <= generic.MAP_NAME_MAX


# ---------------------------------------------------------------------------
# Struct layouts
# ---------------------------------------------------------------------------
def test_pdrs_per_session_is_padded_to_sixteen_bytes() -> None:
    """``{u16 pdr_id; u64 seid;}`` is 16 bytes, not 10 -- 6 bytes of padding."""
    assert PDRS_PER_SESSION.size == 16
    assert PDRS_PER_SESSION.fields == ("pdr_id", "seid")


def test_session_qfi_is_padded_to_sixteen_bytes() -> None:
    """``{u64 seid; u8 qfi;}`` pads out to 16."""
    assert SESSION_QFI.size == 16
    assert SESSION_QFI.fields == ("seid", "qfi")


def test_session_id_is_sixteen_bytes() -> None:
    """``{u32 teid_ul; u32 teid_dl; u64 seid;}`` needs no interior padding."""
    assert SESSION_ID.size == 16
    assert SESSION_ID.fields == ("teid_ul", "teid_dl", "seid")


def test_pdrs_per_session_round_trip() -> None:
    raw = struct.pack("<H6xQ", 2, 0x1122334455667788)
    assert PDRS_PER_SESSION.unpack(raw) == {"pdr_id": 2, "seid": 0x1122334455667788}


def test_session_qfi_round_trip() -> None:
    raw = struct.pack("<QB7x", 0xDEAD, 5)
    assert SESSION_QFI.unpack(raw) == {"seid": 0xDEAD, "qfi": 5}


def test_session_id_round_trip() -> None:
    raw = struct.pack("<IIQ", 0x1111, 0x2222, 7)
    assert SESSION_ID.unpack(raw) == {"teid_ul": 0x1111, "teid_dl": 0x2222, "seid": 7}


# ---------------------------------------------------------------------------
# Catalogue consistency
# ---------------------------------------------------------------------------
def test_seid_location_is_declared_for_every_map() -> None:
    for logical, spec in MAPS.items():
        assert spec.seid_source in ("key", "value"), logical
        if spec.seid_field is not None:
            layout = spec.key_layout if spec.seid_source == "key" else spec.value_layout
            if layout is not None:
                assert spec.seid_field in layout.fields, logical


def test_session_by_ue_ip_reads_the_seid_from_the_value() -> None:
    """It is keyed by UE IP, so the SEID can only come from the value."""
    spec = spec_for("session_by_ue_ip_map")
    assert spec.seid_source == "value"
    assert spec.value_layout is SESSION_ID


def test_scalar_keyed_maps_declare_no_seid_field() -> None:
    """pdrs_per_session_map and session_rules_enabled_map are keyed by bare SEID."""
    for logical in ("pdrs_per_session_map", "session_rules_enabled_map"):
        spec = spec_for(logical)
        assert spec.seid_field is None
        assert spec.key_layout is None


def test_spec_for_rejects_an_unknown_map() -> None:
    with pytest.raises(KeyError, match="unknown map"):
        spec_for("no_such_map")


# ---------------------------------------------------------------------------
# rules_enabled bitmask
# ---------------------------------------------------------------------------
def test_describe_rules_enabled() -> None:
    assert "QER" in describe_rules_enabled(layouts.RULE_QER_ENABLED)
    assert "none" in describe_rules_enabled(0)
    combined = describe_rules_enabled(
        layouts.RULE_QER_ENABLED | layouts.RULE_URR_ENABLED
    )
    assert "QER" in combined
    assert "URR" in combined
