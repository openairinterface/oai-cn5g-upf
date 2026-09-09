# SPDX-License-Identifier: MIT
"""Translation between :mod:`pfcpkit.models` specs and scapy PFCP IE trees.

Field-name traps verified against scapy 2.7.0 -- the casing is genuinely
inconsistent between IEs and getting it wrong fails silently at build time:

    IE_FTEID        V4, V6, CH, CHID, TEID, ipv4   (upper)
    IE_FSEID        v4, v6, seid, ipv4             (lower)
    IE_UE_IP_Address  V4, V6, SD, ipv4             (upper)
    IE_QFI          QFI                            (upper)
    IE_ApplyAction  FORW, DROP, BUFF, NOCP, DUPL   (upper)
    IE_MBR/IE_GBR   ul, dl                         (lower, 40-bit, kbps)
    IE_GateStatus   ul, dl                         (lower, 2-bit enum)
"""

from __future__ import annotations

from collections.abc import Iterator

from scapy.contrib.pfcp import (
    IE_APN_DNN,
    IE_FSEID,
    IE_FTEID,
    IE_GBR,
    IE_MBR,
    IE_PDI,
    IE_QFI,
    IE_ApplyAction,
    IE_Cause,
    IE_CPFunctionFeatures,
    IE_CreatedPDR,
    IE_CreateFAR,
    IE_CreatePDR,
    IE_CreateQER,
    IE_DestinationInterface,
    IE_FAR_Id,
    IE_ForwardingParameters,
    IE_GateStatus,
    IE_NetworkInstance,
    IE_NodeId,
    IE_OuterHeaderCreation,
    IE_OuterHeaderRemoval,
    IE_PDNType,
    IE_PDR_Id,
    IE_Precedence,
    IE_QER_Id,
    IE_RecoveryTimeStamp,
    IE_RemoveFAR,
    IE_RemovePDR,
    IE_RemoveQER,
    IE_SDF_Filter,
    IE_SourceInterface,
    IE_UE_IP_Address,
    IE_UpdateFAR,
    IE_UpdateForwardingParameters,
    IE_UpdatePDR,
    IE_UpdateQER,
    PFCPAssociationReleaseRequest,
    PFCPAssociationSetupRequest,
    PFCPHeartbeatResponse,
    PFCPSessionDeletionRequest,
    PFCPSessionEstablishmentRequest,
    PFCPSessionModificationRequest,
)
from scapy.packet import Packet

from ..errors import PfcpDecodeError
from ..models import (
    CreatedPdr,
    FarSpec,
    ModificationSpec,
    PdrSpec,
    PfcpResponse,
    QerSpec,
    SessionSpec,
)
from .types import NodeIdType

# IE type 114 -- Failed Rule ID (TS 29.244 Section 8.2.114). Not all scapy
# releases expose a dedicated class, so it is matched by ietype when present.
_FAILED_RULE_ID_IE_TYPE = 114


# ---------------------------------------------------------------------------
# Node-level messages
# ---------------------------------------------------------------------------


def association_setup_request(
    node_id: str, recovery_timestamp: int
) -> PFCPAssociationSetupRequest:
    """Association Setup Request -- TS 29.244 Section 7.4.4."""
    return PFCPAssociationSetupRequest(
        IE_list=[
            IE_NodeId(id_type=NodeIdType.IPV4, ipv4=node_id),
            IE_RecoveryTimeStamp(timestamp=recovery_timestamp),
            IE_CPFunctionFeatures(),
        ]
    )


def association_release_request(node_id: str) -> PFCPAssociationReleaseRequest:
    """Association Release Request -- TS 29.244 Section 7.4.5."""
    return PFCPAssociationReleaseRequest(
        IE_list=[IE_NodeId(id_type=NodeIdType.IPV4, ipv4=node_id)]
    )


def heartbeat_response(recovery_timestamp: int) -> PFCPHeartbeatResponse:
    """Heartbeat Response -- TS 29.244 Section 7.4.2.

    Answering these is what keeps the association alive. Missing them causes the
    UPF to tear the association down mid-run, which presents as an unexplained
    data-plane collapse rather than as a control-plane error.
    """
    return PFCPHeartbeatResponse(
        IE_list=[IE_RecoveryTimeStamp(timestamp=recovery_timestamp)]
    )


# ---------------------------------------------------------------------------
# Session messages
# ---------------------------------------------------------------------------


def session_establishment_request(
    spec: SessionSpec, *, node_id: str, cp_seid: int
) -> PFCPSessionEstablishmentRequest:
    """Session Establishment Request -- TS 29.244 Section 7.5.2."""
    ies: list[Packet] = [
        IE_NodeId(id_type=NodeIdType.IPV4, ipv4=node_id),
        IE_FSEID(v4=1, seid=cp_seid, ipv4=node_id),
    ]
    ies.extend(encode_create_pdr(pdr, spec.network_instance) for pdr in spec.pdrs)
    ies.extend(encode_create_far(far, spec.network_instance) for far in spec.fars)
    ies.extend(encode_create_qer(qer) for qer in spec.qers)
    ies.append(IE_PDNType(pdn_type=int(spec.pdn_type)))
    ies.append(IE_APN_DNN(apn_dnn=spec.apn_dnn))
    return PFCPSessionEstablishmentRequest(IE_list=ies)


def session_modification_request(
    delta: ModificationSpec, *, network_instance: str
) -> PFCPSessionModificationRequest:
    """Session Modification Request -- TS 29.244 Section 7.5.4.

    IEs are emitted removals-first, then creations, then updates, matching both
    the spec's presentation order and the order the UPF applies them.
    """
    ies: list[Packet] = []
    ies.extend(encode_remove_pdr(pdr_id) for pdr_id in delta.remove_pdr_ids)
    ies.extend(encode_remove_far(far_id) for far_id in delta.remove_far_ids)
    ies.extend(encode_remove_qer(qer_id) for qer_id in delta.remove_qer_ids)
    ies.extend(encode_create_pdr(pdr, network_instance) for pdr in delta.create_pdrs)
    ies.extend(encode_create_far(far, network_instance) for far in delta.create_fars)
    ies.extend(encode_create_qer(qer) for qer in delta.create_qers)
    ies.extend(encode_update_pdr(pdr, network_instance) for pdr in delta.update_pdrs)
    ies.extend(encode_update_far(far, network_instance) for far in delta.update_fars)
    ies.extend(encode_update_qer(qer) for qer in delta.update_qers)
    return PFCPSessionModificationRequest(IE_list=ies)


def session_deletion_request() -> PFCPSessionDeletionRequest:
    """Session Deletion Request -- TS 29.244 Section 7.5.6.

    The session is identified solely by the header SEID, so the body is empty.
    """
    return PFCPSessionDeletionRequest(IE_list=[])


# ---------------------------------------------------------------------------
# PDR
# ---------------------------------------------------------------------------


def encode_create_pdr(spec: PdrSpec, default_network_instance: str) -> IE_CreatePDR:
    """Create PDR IE -- TS 29.244 Table 7.5.2.2-1."""
    ies: list[Packet] = [
        IE_PDR_Id(id=spec.pdr_id),
        IE_Precedence(precedence=spec.precedence),
        _encode_pdi(spec, default_network_instance),
    ]
    if spec.outer_header_removal is not None:
        ies.append(IE_OuterHeaderRemoval(header=int(spec.outer_header_removal)))
    ies.append(IE_FAR_Id(id=spec.far_id))
    if spec.qer_id is not None:
        ies.append(IE_QER_Id(id=spec.qer_id))
    return IE_CreatePDR(IE_list=ies)


def encode_update_pdr(spec: PdrSpec, default_network_instance: str) -> IE_UpdatePDR:
    """Update PDR IE -- TS 29.244 Table 7.5.4.2-1.

    Same body shape as Create PDR; the PDR ID selects the existing rule.
    """
    ies: list[Packet] = [
        IE_PDR_Id(id=spec.pdr_id),
        IE_Precedence(precedence=spec.precedence),
        _encode_pdi(spec, default_network_instance),
    ]
    if spec.outer_header_removal is not None:
        ies.append(IE_OuterHeaderRemoval(header=int(spec.outer_header_removal)))
    ies.append(IE_FAR_Id(id=spec.far_id))
    if spec.qer_id is not None:
        ies.append(IE_QER_Id(id=spec.qer_id))
    return IE_UpdatePDR(IE_list=ies)


def encode_remove_pdr(pdr_id: int) -> IE_RemovePDR:
    """Remove PDR IE -- TS 29.244 Table 7.5.4.6-1."""
    return IE_RemovePDR(IE_list=[IE_PDR_Id(id=pdr_id)])


def _encode_pdi(spec: PdrSpec, default_network_instance: str) -> IE_PDI:
    """PDI grouped IE -- TS 29.244 Section 7.5.2.2.2."""
    ies: list[Packet] = [IE_SourceInterface(interface=int(spec.source_interface))]

    if spec.f_teid is not None:
        ies.append(_encode_fteid(spec))

    instance = spec.network_instance or default_network_instance
    if instance:
        ies.append(IE_NetworkInstance(instance=instance))

    if spec.ue_ipv4 is not None:
        ies.append(
            IE_UE_IP_Address(
                V4=1, SD=1 if spec.ue_ip_is_destination else 0, ipv4=spec.ue_ipv4
            )
        )

    if spec.sdf_filter is not None:
        # flow_description_length is a FieldLenField -- scapy derives it.
        ies.append(
            IE_SDF_Filter(FD=1, flow_description=spec.sdf_filter.flow_description)
        )

    if spec.qfi is not None:
        ies.append(IE_QFI(QFI=spec.qfi))

    return IE_PDI(IE_list=ies)


def _encode_fteid(spec: PdrSpec) -> IE_FTEID:
    f_teid = spec.f_teid
    if f_teid is None:  # pragma: no cover - guarded by the caller
        raise ValueError("_encode_fteid called without an F-TEID")
    if f_teid.choose:
        # CH=1: ask the UPF to allocate. TEID/ipv4 must be omitted -- scapy's
        # ConditionalFields drop them when CH is set.
        return IE_FTEID(V4=1, CH=1)
    return IE_FTEID(V4=1, TEID=f_teid.teid, ipv4=f_teid.ipv4)


# ---------------------------------------------------------------------------
# FAR
# ---------------------------------------------------------------------------


def encode_create_far(spec: FarSpec, default_network_instance: str) -> IE_CreateFAR:
    """Create FAR IE -- TS 29.244 Table 7.5.2.3-1."""
    ies: list[Packet] = [
        IE_FAR_Id(id=spec.far_id),
        _encode_apply_action(spec.apply_action),
    ]
    forwarding = _encode_forwarding_parameters(
        spec, default_network_instance, IE_ForwardingParameters
    )
    if forwarding is not None:
        ies.append(forwarding)
    return IE_CreateFAR(IE_list=ies)


def encode_update_far(spec: FarSpec, default_network_instance: str) -> IE_UpdateFAR:
    """Update FAR IE -- TS 29.244 Table 7.5.4.3-1.

    Note the distinct inner IE: updates carry *Update* Forwarding Parameters
    (IE type 11), not Forwarding Parameters (type 4).
    """
    ies: list[Packet] = [
        IE_FAR_Id(id=spec.far_id),
        _encode_apply_action(spec.apply_action),
    ]
    forwarding = _encode_forwarding_parameters(
        spec, default_network_instance, IE_UpdateForwardingParameters
    )
    if forwarding is not None:
        ies.append(forwarding)
    return IE_UpdateFAR(IE_list=ies)


def encode_remove_far(far_id: int) -> IE_RemoveFAR:
    """Remove FAR IE -- TS 29.244 Table 7.5.4.7-1."""
    return IE_RemoveFAR(IE_list=[IE_FAR_Id(id=far_id)])


def _encode_apply_action(flags: int) -> IE_ApplyAction:
    """Apply Action IE -- TS 29.244 Section 8.2.26."""
    from .types import ApplyAction

    return IE_ApplyAction(
        DROP=1 if flags & ApplyAction.DROP else 0,
        FORW=1 if flags & ApplyAction.FORW else 0,
        BUFF=1 if flags & ApplyAction.BUFF else 0,
        NOCP=1 if flags & ApplyAction.NOCP else 0,
        DUPL=1 if flags & ApplyAction.DUPL else 0,
    )


def _encode_forwarding_parameters(
    spec: FarSpec,
    default_network_instance: str,
    container: type[Packet],
) -> Packet | None:
    if spec.destination_interface is None and spec.outer_header_creation is None:
        return None

    ies: list[Packet] = []
    if spec.destination_interface is not None:
        ies.append(IE_DestinationInterface(interface=int(spec.destination_interface)))

    instance = spec.network_instance or default_network_instance
    if instance:
        ies.append(IE_NetworkInstance(instance=instance))

    if spec.outer_header_creation is not None:
        ies.append(
            IE_OuterHeaderCreation(
                GTPUUDPIPV4=1,
                TEID=spec.outer_header_creation.teid,
                ipv4=spec.outer_header_creation.ipv4,
            )
        )
    return container(IE_list=ies)


# ---------------------------------------------------------------------------
# QER
# ---------------------------------------------------------------------------


def encode_create_qer(spec: QerSpec) -> IE_CreateQER:
    """Create QER IE -- TS 29.244 Table 7.5.2.5-1."""
    return IE_CreateQER(IE_list=_qer_body(spec))


def encode_update_qer(spec: QerSpec) -> IE_UpdateQER:
    """Update QER IE -- TS 29.244 Table 7.5.4.5-1.

    This is the message that should change an existing HTB class's rate and ceil.
    """
    return IE_UpdateQER(IE_list=_qer_body(spec))


def encode_remove_qer(qer_id: int) -> IE_RemoveQER:
    """Remove QER IE -- TS 29.244 Table 7.5.4.9-1."""
    return IE_RemoveQER(IE_list=[IE_QER_Id(id=qer_id)])


def _qer_body(spec: QerSpec) -> list[Packet]:
    ies: list[Packet] = [
        IE_QER_Id(id=spec.qer_id),
        IE_GateStatus(ul=int(spec.gate_ul), dl=int(spec.gate_dl)),
    ]
    # MBR/GBR are single IEs carrying both directions (40-bit fields, kbps).
    # Emit them only when at least one direction is set, since their presence is
    # what distinguishes a dedicated flow from the session's default flow.
    if spec.mbr_ul_kbps is not None or spec.mbr_dl_kbps is not None:
        ies.append(IE_MBR(ul=spec.mbr_ul_kbps or 0, dl=spec.mbr_dl_kbps or 0))
    if spec.gbr_ul_kbps is not None or spec.gbr_dl_kbps is not None:
        ies.append(IE_GBR(ul=spec.gbr_ul_kbps or 0, dl=spec.gbr_dl_kbps or 0))
    if spec.qfi is not None:
        ies.append(IE_QFI(QFI=spec.qfi))
    return ies


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


def iter_ies(container: Packet) -> Iterator[Packet]:
    """Depth-first walk over every IE in a message or grouped IE.

    scapy's ``getlayer`` does not reach inside ``IE_list`` of compound IEs, so
    grouped IEs (Created PDR, PDI, ...) need an explicit walk.
    """
    ie_list = getattr(container, "IE_list", None)
    if not ie_list:
        return
    for ie in ie_list:
        yield ie
        yield from iter_ies(ie)


def find_ie(container: Packet, ie_cls: type[Packet]) -> Packet | None:
    """First IE of ``ie_cls`` anywhere in the message, or None."""
    for ie in iter_ies(container):
        if isinstance(ie, ie_cls):
            return ie
    return None


def decode_response(pkt: Packet) -> PfcpResponse:
    """Build a :class:`PfcpResponse` from a received scapy PFCP packet."""
    from scapy.contrib.pfcp import PFCP

    if not pkt.haslayer(PFCP):
        raise PfcpDecodeError("received datagram is not a PFCP message")

    header = pkt[PFCP]
    body = header.payload
    if body is None or isinstance(body, type(None)):  # pragma: no cover - defensive
        raise PfcpDecodeError(
            f"PFCP message type {header.message_type} carries no decodable body"
        )

    cause_ie = find_ie(body, IE_Cause)
    fseid_ie = find_ie(body, IE_FSEID)

    return PfcpResponse(
        message_type=int(header.message_type),
        seq=int(header.seq),
        cause=None if cause_ie is None else int(cause_ie.cause),
        up_seid=None if fseid_ie is None else int(fseid_ie.seid),
        created_pdrs=_decode_created_pdrs(body),
        failed_rule_id=_decode_failed_rule_id(body),
        raw=pkt,
    )


def _decode_created_pdrs(body: Packet) -> tuple[CreatedPdr, ...]:
    """Extract Created PDR IEs, including any UPF-allocated F-TEID."""
    created: list[CreatedPdr] = []
    for ie in iter_ies(body):
        if not isinstance(ie, IE_CreatedPDR):
            continue
        pdr_id_ie = find_ie(ie, IE_PDR_Id)
        if pdr_id_ie is None:
            continue
        fteid_ie = find_ie(ie, IE_FTEID)
        teid = None
        ipv4 = None
        if fteid_ie is not None:
            teid = int(getattr(fteid_ie, "TEID", 0)) or None
            raw_ipv4 = getattr(fteid_ie, "ipv4", None)
            ipv4 = str(raw_ipv4) if raw_ipv4 else None
        created.append(CreatedPdr(pdr_id=int(pdr_id_ie.id), teid=teid, ipv4=ipv4))
    return tuple(created)


def _decode_failed_rule_id(body: Packet) -> int | None:
    """Best-effort Failed Rule ID extraction (TS 29.244 Section 8.2.114).

    Matched by IE type rather than class, because scapy does not expose a
    dedicated class for it in every release. Returned as the raw rule-id bytes
    interpreted big-endian, which is enough to point at the offending rule.
    """
    for ie in iter_ies(body):
        if int(getattr(ie, "ietype", 0)) != _FAILED_RULE_ID_IE_TYPE:
            continue
        payload = bytes(ie.payload) if ie.payload else b""
        if len(payload) >= 2:
            # First octet is the rule-ID type; the remainder is the value.
            return int.from_bytes(payload[1:], "big")
    return None
