# SPDX-License-Identifier: MIT
"""PFCP protocol constants (3GPP TS 29.244 V17.10.0).

Values mirror scapy's ``scapy.contrib.pfcp`` tables so they can be handed
straight to IE constructors.
"""

from __future__ import annotations

from enum import IntEnum


class MessageType(IntEnum):
    """PFCP message types -- TS 29.244 Table 7.3-1."""

    HEARTBEAT_REQUEST = 1
    HEARTBEAT_RESPONSE = 2
    ASSOCIATION_SETUP_REQUEST = 5
    ASSOCIATION_SETUP_RESPONSE = 6
    ASSOCIATION_RELEASE_REQUEST = 9
    ASSOCIATION_RELEASE_RESPONSE = 10
    SESSION_ESTABLISHMENT_REQUEST = 50
    SESSION_ESTABLISHMENT_RESPONSE = 51
    SESSION_MODIFICATION_REQUEST = 52
    SESSION_MODIFICATION_RESPONSE = 53
    SESSION_DELETION_REQUEST = 54
    SESSION_DELETION_RESPONSE = 55
    SESSION_REPORT_REQUEST = 56
    SESSION_REPORT_RESPONSE = 57

    @property
    def label(self) -> str:
        return self.name.lower()


class Cause(IntEnum):
    """Cause IE values -- TS 29.244 Section 8.2.1."""

    RESERVED = 0
    REQUEST_ACCEPTED = 1
    REQUEST_REJECTED = 64
    SESSION_CONTEXT_NOT_FOUND = 65
    MANDATORY_IE_MISSING = 66
    CONDITIONAL_IE_MISSING = 67
    INVALID_LENGTH = 68
    MANDATORY_IE_INCORRECT = 69
    INVALID_FORWARDING_POLICY = 70
    INVALID_FTEID_ALLOCATION_OPTION = 71
    NO_ESTABLISHED_SX_ASSOCIATION = 72
    RULE_CREATION_MODIFICATION_FAILURE = 73
    PFCP_ENTITY_IN_CONGESTION = 74
    NO_RESOURCES_AVAILABLE = 75
    SERVICE_NOT_SUPPORTED = 76
    SYSTEM_FAILURE = 77


def cause_name(value: int | None) -> str:
    """Human-readable name for a Cause value, tolerating unknown codes."""
    if value is None:
        return "<absent>"
    try:
        return Cause(value).name
    except ValueError:
        return f"<unknown:{value}>"


class SourceInterface(IntEnum):
    """Source Interface IE -- TS 29.244 Section 8.2.2."""

    ACCESS = 0
    CORE = 1
    SGI_LAN_N6_LAN = 2
    CP_FUNCTION = 3


class DestinationInterface(IntEnum):
    """Destination Interface IE -- TS 29.244 Section 8.2.24."""

    ACCESS = 0
    CORE = 1
    SGI_LAN_N6_LAN = 2
    CP_FUNCTION = 3
    LI_FUNCTION = 4


class GateStatus(IntEnum):
    """Gate Status IE -- TS 29.244 Section 8.2.7."""

    OPEN = 0
    CLOSED = 1


class PdnType(IntEnum):
    """PDN Type IE -- TS 29.244 Section 8.2.10.

    Note the ordering: 0 is IPv4. The reference tooling this suite was modelled
    on sent ``pdn_type=1`` (IPv6) for IPv4 sessions; lenient UPFs ignore it.
    """

    IPV4 = 0
    IPV6 = 1
    IPV4V6 = 2
    NON_IP = 3
    ETHERNET = 4


class OuterHeaderRemoval(IntEnum):
    """Outer Header Removal Description -- TS 29.244 Section 8.2.64."""

    GTPU_UDP_IPV4 = 0
    GTPU_UDP_IPV6 = 1
    UDP_IPV4 = 2
    UDP_IPV6 = 3
    IPV4 = 4
    IPV6 = 5
    GTPU_UDP_IP = 6


class NodeIdType(IntEnum):
    """Node ID Type -- TS 29.244 Section 8.2.38."""

    IPV4 = 0
    IPV6 = 1
    FQDN = 2


class ApplyAction(IntEnum):
    """Apply Action IE bit flags -- TS 29.244 Section 8.2.26.

    A flag set rather than a plain enum: combine with ``|``.
    """

    DROP = 1 << 0
    FORW = 1 << 1
    BUFF = 1 << 2
    NOCP = 1 << 3
    DUPL = 1 << 4


#: Sentinel for the Session Establishment Request header SEID.
#:
#: TS 29.244 Section 7.2.2.4.2: the CP sets SEID=0 in the header of a Session
#: Establishment Request, because the UP has not allocated one yet. The S flag
#: must still be set -- some UPFs reject a session message with S=0 outright at
#: decode time (cause 64), regardless of the SEID value.
ESTABLISHMENT_HEADER_SEID = 0

#: Default PFCP port for both source and destination (TS 29.244 Section 4.2.2).
PFCP_PORT = 8805
