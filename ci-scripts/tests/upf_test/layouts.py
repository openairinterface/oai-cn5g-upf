# SPDX-License-Identifier: MIT
"""The OAI UPF's BPF map catalogue and key/value layouts.

This is the OAI-specific half of what used to be one module: the generic
machinery (name truncation, ``StructLayout``, ``MapSpec``) lives in
:mod:`pfcpkit.inspect.layouts`; the knowledge of *which* maps exist and how their
keys are laid out is here, because it is true only of this UPF.

Every value below was confirmed against a running UPF rather than read off the
headers alone -- the truncated names via ``bpftool map show``, the struct sizes via
decoding real dumps.

Structs mirror ``src/upf_app/kernel/include/``.
"""

from __future__ import annotations

from pfcpkit.inspect.layouts import MapSpec, StructLayout
from pfcpkit.inspect.layouts import spec_for as _spec_for

# ---------------------------------------------------------------------------
# Key / value layouts
# ---------------------------------------------------------------------------

#: ``struct pdrs_per_session {u16 pdr_id; u64 seid;}`` -- pipeline_types.h.
#: Six bytes of padding align the u64; total 16, not 10.
PDRS_PER_SESSION = StructLayout("<H6xQ", ("pdr_id", "seid"))

#: ``struct session_qfi {u64 seid; u8 qfi;}`` -- sdf_types.h. Trailing pad to 16.
SESSION_QFI = StructLayout("<QB7x", ("seid", "qfi"))

#: ``struct session_id {u32 teid_ul; u32 teid_dl; u64 seid;}`` -- pipeline_types.h.
SESSION_ID = StructLayout("<IIQ", ("teid_ul", "teid_dl", "seid"))


# ---------------------------------------------------------------------------
# Map catalogue
# ---------------------------------------------------------------------------

#: Maps this suite asserts on, keyed by logical name.
#:
#: Values are only given a layout where an assertion actually reads them:
#: ``session_by_ue_ip_map`` needs ``value.seid`` for the re-attach check. The
#: others are asserted on by key presence or absence, and their values are large
#: nested structs whose full decoding would be a lot of brittle code for no
#: assertion.
MAPS: dict[str, MapSpec] = {
    "rules_match_pdr_map": MapSpec(
        logical_name="rules_match_pdr_map",
        seid_source="key",
        seid_field="seid",
        key_layout=PDRS_PER_SESSION,
        description="PDR id + SEID -> {far, qer, urr, bar, mar}",
    ),
    "eth_rules_match_pdr_map": MapSpec(
        logical_name="eth_rules_match_pdr_map",
        seid_source="key",
        seid_field="seid",
        key_layout=PDRS_PER_SESSION,
        description="ETH-PDU mirror of rules_match_pdr_map",
    ),
    "pdrs_per_session_map": MapSpec(
        logical_name="pdrs_per_session_map",
        seid_source="key",
        seid_field=None,  # the key IS the SEID
        description="SEID -> PDR array",
    ),
    "sdf_filters_map": MapSpec(
        logical_name="sdf_filters_map",
        seid_source="key",
        seid_field="seid",
        key_layout=SESSION_QFI,
        description="SEID + QFI -> SDF filter",
    ),
    "session_by_ue_ip_map": MapSpec(
        logical_name="session_by_ue_ip_map",
        seid_source="value",
        seid_field="seid",
        value_layout=SESSION_ID,
        description="UE IP -> {teid_ul, teid_dl, seid}",
    ),
    "session_rules_enabled_map": MapSpec(
        logical_name="session_rules_enabled_map",
        seid_source="key",
        seid_field=None,
        description="SEID -> enabled-rule bitmask",
    ),
}


def spec_for(logical_name: str) -> MapSpec:
    """Look up one of this UPF's maps."""
    return _spec_for(MAPS, logical_name)


# ---------------------------------------------------------------------------
# rules_enabled bitmask -- src/upf_app/kernel/include/rules_enabled_flags.h
# ---------------------------------------------------------------------------

RULE_QER_ENABLED = 1 << 0
RULE_URR_ENABLED = 1 << 1
RULE_BAR_ENABLED = 1 << 2
RULE_MAR_ENABLED = 1 << 3


def describe_rules_enabled(flags: int) -> str:
    """Render a rules_enabled bitmask for a failure message."""
    names = [
        name
        for bit, name in (
            (RULE_QER_ENABLED, "QER"),
            (RULE_URR_ENABLED, "URR"),
            (RULE_BAR_ENABLED, "BAR"),
            (RULE_MAR_ENABLED, "MAR"),
        )
        if flags & bit
    ]
    return f"0x{flags:x} ({'+'.join(names) if names else 'none'})"
