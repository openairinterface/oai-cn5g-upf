# SPDX-License-Identifier: MIT
"""The OAI UPF adapter: capability protocols implemented over bpftool and tc.

This is the seam a conformance scenario runs through. A scenario asks
``rules.installed_pdr_ids(seid)``; this module knows that the answer lives in
``rules_match_pdr_map``, that the kernel truncates that name to 15 characters, that
its key is ``{u16 pdr_id; u64 seid}`` with six bytes of padding, and that the whole
thing must be read with ``bpftool`` inside the UPF's container because nothing is
pinned to bpffs.

None of that is in the library, and none of it is in the scenarios.
"""

from __future__ import annotations

import logging

from pfcpkit.capabilities import Capability
from pfcpkit.inspect.bpftool import BpfMapInspector
from pfcpkit.inspect.tc import TcInspector, handle

from . import layouts
from .class_ids import qos_class_minor, session_class_minor

logger = logging.getLogger(__name__)

#: What this adapter can observe. Compared against each scenario's ``requires``.
CAPABILITIES = frozenset(
    {Capability.RULE_STATE, Capability.QOS_STATE, Capability.LOG_WINDOW}
)

ADAPTER_NAME = "oai-upf"


class OaiRuleState:
    """:class:`pfcpkit.capabilities.RuleState` over the UPF's BPF maps."""

    def __init__(self, bpf: BpfMapInspector) -> None:
        self._bpf = bpf

    def installed_pdr_ids(self, seid: int) -> list[int]:
        return self._bpf.pdr_ids_for_seid("rules_match_pdr_map", seid)

    def installed_qfis(self, seid: int) -> list[int]:
        """QFIs with SDF-filter state, from ``sdf_filters_map``."""
        qfis = [
            entry.key_field("qfi")
            for entry in self._bpf.entries_for_seid("sdf_filters_map", seid)
        ]
        return sorted(q for q in qfis if q is not None)

    def seid_for_ue_ip(self, ue_ipv4: str) -> int | None:
        """Owner of a UE address in ``session_by_ue_ip_map``.

        The map is keyed by the address in network byte order. Rather than
        reproducing that conversion and risking an endianness mistake, every entry
        is scanned and its key compared both ways.
        """
        wanted = _ipv4_to_int(ue_ipv4)
        swapped = int.from_bytes(wanted.to_bytes(4, "big"), "little")
        for entry in self._bpf.dump("session_by_ue_ip_map"):
            key = entry.key
            if isinstance(key, int) and key in (wanted, swapped):
                return entry.value_field("seid")
        return None

    def session_installed(self, seid: int) -> bool:
        return self._bpf.count_for_seid("pdrs_per_session_map", seid) > 0

    # -- OAI extras, used by this project's own scenarios -------------------
    def rules_enabled(self, seid: int) -> int | None:
        """The ``session_rules_enabled_map`` bitmask for a session."""
        for entry in self._bpf.entries_for_seid("session_rules_enabled_map", seid):
            if isinstance(entry.value, int):
                return entry.value
        return None

    def describe_rules_enabled(self, seid: int) -> str:
        flags = self.rules_enabled(seid)
        return "absent" if flags is None else layouts.describe_rules_enabled(flags)


class OaiQosState:
    """:class:`pfcpkit.capabilities.QosState` over the UPF's HTB classes.

    Class ids are derived, not discovered: the UPF hashes (SEID, QFI) with no
    counter, so this adapter can compute which class *should* exist and ask about
    exactly that one.
    """

    def __init__(self, tc: TcInspector, n3_iface: str) -> None:
        self._tc = tc
        self._iface = n3_iface

    def flow_exists(self, seid: int, qfi: int) -> bool:
        return self._flow_class(seid, qfi) is not None

    def flow_rate_kbps(self, seid: int, qfi: int) -> tuple[int, int] | None:
        entry = self._flow_class(seid, qfi)
        if entry is None or entry.rate_kbps is None or entry.ceil_kbps is None:
            return None
        return entry.rate_kbps, entry.ceil_kbps

    def session_shaper_exists(self, seid: int) -> bool:
        return (
            self._tc.class_by_handle(self._iface, handle(session_class_minor(seid)))
            is not None
        )

    def shaper_root_exists(self) -> bool:
        """Whether the shared HTB root qdisc is present.

        Created once per interface and shared by every session, so a scenario
        asserting that teardown left it alone must ask about it separately.
        """
        return self._tc.has_htb_root(self._iface)

    # -- OAI extras --------------------------------------------------------
    def flow_handle(self, seid: int, qfi: int) -> str:
        """The classid this flow's class would use, for failure messages."""
        return handle(qos_class_minor(seid, qfi))

    def _flow_class(self, seid: int, qfi: int):  # type: ignore[no-untyped-def]
        return self._tc.class_by_handle(self._iface, self.flow_handle(seid, qfi))


def _ipv4_to_int(address: str) -> int:
    octets = address.split(".")
    if len(octets) != 4:
        raise ValueError(f"not an IPv4 address: {address!r}")
    value = 0
    for octet in octets:
        value = (value << 8) | int(octet)
    return value
