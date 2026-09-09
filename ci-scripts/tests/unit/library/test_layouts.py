# SPDX-License-Identifier: MIT
"""Tests for the generic layout machinery.

Two mechanics are pinned here, both silently dangerous when wrong because both
failure modes make an *absence* assertion pass for the wrong reason: the kernel's
15-character name truncation, and C struct padding.

The catalogue these mechanics get applied to belongs to an adapter; the OAI one is
tested in :mod:`unit.oai.test_layouts`.
"""

from __future__ import annotations

import struct

import pytest

from pfcpkit.inspect import layouts
from pfcpkit.inspect.layouts import MapSpec, StructLayout, bpf_name, spec_for


# ---------------------------------------------------------------------------
# Name truncation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("logical", "expected"),
    [
        # Verified against `bpftool map show` on a live UPF.
        ("session_by_ue_ip_map", "session_by_ue_i"),
        ("rules_match_pdr_map", "rules_match_pdr"),
        ("pdrs_per_session_map", "pdrs_per_sessio"),
        # Exactly 15 characters, so it survives intact.
        ("sdf_filters_map", "sdf_filters_map"),
        # Shorter than the limit: untouched.
        ("arp_table_map", "arp_table_map"),
    ],
)
def test_names_truncate_to_the_kernel_form(logical: str, expected: str) -> None:
    assert bpf_name(logical) == expected


def test_truncation_length_matches_the_kernel_constant() -> None:
    assert layouts.MAP_NAME_MAX == 15
    assert layouts.BPF_OBJ_NAME_LEN == 16, "includes the terminating NUL"


def test_map_spec_exposes_the_truncated_name() -> None:
    assert MapSpec("session_by_ue_ip_map").name == "session_by_ue_i"


# ---------------------------------------------------------------------------
# Struct layouts
# ---------------------------------------------------------------------------
def test_mixed_width_layout_accounts_for_interior_padding() -> None:
    """``{u16 a; u64 b;}`` is 16 bytes, not 10 -- six bytes of padding."""
    layout = StructLayout("<H6xQ", ("a", "b"))
    assert layout.size == 16
    assert layout.fields == ("a", "b")


def test_layout_round_trip() -> None:
    layout = StructLayout("<H6xQ", ("a", "b"))
    raw = struct.pack("<H6xQ", 2, 0x1122334455667788)
    assert layout.unpack(raw) == {"a": 2, "b": 0x1122334455667788}


def test_unpack_tolerates_a_longer_buffer() -> None:
    """bpftool pads to the map's key size, which may exceed the struct."""
    layout = StructLayout("<H6xQ", ("a", "b"))
    raw = struct.pack("<H6xQ", 1, 9) + b"\x00" * 8
    assert layout.unpack(raw)["b"] == 9


def test_unpack_rejects_a_short_buffer() -> None:
    """Silently misdecoding a truncated key would be far worse than failing."""
    layout = StructLayout("<H6xQ", ("a", "b"))
    with pytest.raises(ValueError, match="needs 16 bytes"):
        layout.unpack(b"\x01\x00")


def test_layout_rejects_mismatched_field_names() -> None:
    """Caught at construction, not on the first decode of real data."""
    with pytest.raises(ValueError, match="field name"):
        StructLayout("<HQ", ("only_one",))


# ---------------------------------------------------------------------------
# Catalogue lookup
# ---------------------------------------------------------------------------
def test_spec_for_finds_a_catalogued_map() -> None:
    catalogue = {"a_map": MapSpec("a_map")}
    assert spec_for(catalogue, "a_map").logical_name == "a_map"


def test_spec_for_lists_what_the_catalogue_holds_when_it_misses() -> None:
    """The error has to be actionable -- usually the caller made a typo."""
    catalogue = {"a_map": MapSpec("a_map"), "b_map": MapSpec("b_map")}
    with pytest.raises(KeyError, match="a_map, b_map"):
        spec_for(catalogue, "c_map")
