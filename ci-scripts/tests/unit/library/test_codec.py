# SPDX-License-Identifier: MIT
"""Round-trip tests for the spec -> scapy IE encoder.

Each test encodes a spec, serialises it to bytes, re-parses it, and asserts the
IEs survived with the intended values. That full round trip is the point: scapy's
IE field names are inconsistently cased between IEs (``IE_FTEID.V4`` vs
``IE_FSEID.v4``), and a mistyped keyword is silently ignored at construction --
producing a well-formed message with a missing or zeroed field. Only re-parsing
catches that.
"""

from __future__ import annotations

import pytest
from scapy.contrib.pfcp import (
    IE_FTEID,
    IE_GBR,
    IE_MBR,
    IE_QFI,
    PFCP,
    IE_CreatePDR,
    IE_CreateQER,
    IE_GateStatus,
    IE_OuterHeaderCreation,
    IE_OuterHeaderRemoval,
    IE_PDR_Id,
    IE_QER_Id,
    IE_RemovePDR,
    IE_SDF_Filter,
    IE_SourceInterface,
    IE_UE_IP_Address,
    IE_UpdateQER,
)

from pfcpkit.config import Settings
from pfcpkit.models import (
    FarSpec,
    FTeid,
    ModificationSpec,
    OuterHeaderCreation,
    PdrSpec,
    QerSpec,
    SdfFilter,
)
from pfcpkit.pfcp import codec
from pfcpkit.pfcp.types import (
    ApplyAction,
    DestinationInterface,
    GateStatus,
    OuterHeaderRemoval,
    SourceInterface,
)
from pfcpkit.presets import basic_ipv4_session, gbr_qer

UE_IP = "12.1.1.2"
N3_IP = "192.168.72.134"
GNB_IP = "192.168.72.141"


def reparse(ie):  # type: ignore[no-untyped-def]
    """Serialise an IE and parse it back, as the UPF's decoder would see it."""
    return type(ie)(bytes(ie))


@pytest.fixture()
def settings() -> Settings:
    return Settings.from_env(
        {
            "UPF_N3_ADDR": N3_IP,
            "GNB_N3_ADDR": GNB_IP,
            "UE_IPV4_BASE": UE_IP,
        }
    )


# ---------------------------------------------------------------------------
# PDR
# ---------------------------------------------------------------------------
def test_uplink_pdr_round_trip() -> None:
    spec = PdrSpec(
        pdr_id=1,
        far_id=1,
        source_interface=SourceInterface.ACCESS,
        precedence=100,
        ue_ipv4=UE_IP,
        f_teid=FTeid(teid=0xABCD, ipv4=N3_IP),
        qer_id=7,
        qfi=5,
        sdf_filter=SdfFilter("permit out ip from any to assigned"),
        outer_header_removal=OuterHeaderRemoval.GTPU_UDP_IPV4,
    )
    parsed = reparse(codec.encode_create_pdr(spec, "internet"))

    assert isinstance(parsed, IE_CreatePDR)
    assert codec.find_ie(parsed, IE_PDR_Id).id == 1
    assert codec.find_ie(parsed, IE_SourceInterface).interface == SourceInterface.ACCESS

    fteid = codec.find_ie(parsed, IE_FTEID)
    assert fteid.V4 == 1
    assert fteid.TEID == 0xABCD
    assert fteid.ipv4 == N3_IP

    ue_ip = codec.find_ie(parsed, IE_UE_IP_Address)
    assert ue_ip.V4 == 1
    assert ue_ip.SD == 0, "an uplink PDR matches the UE IP as source"
    assert ue_ip.ipv4 == UE_IP

    assert codec.find_ie(parsed, IE_QFI).QFI == 5
    assert codec.find_ie(parsed, IE_QER_Id).id == 7
    assert (
        codec.find_ie(parsed, IE_OuterHeaderRemoval).header
        == OuterHeaderRemoval.GTPU_UDP_IPV4
    )
    sdf = codec.find_ie(parsed, IE_SDF_Filter)
    assert sdf.FD == 1
    assert sdf.flow_description == b"permit out ip from any to assigned"


def test_downlink_pdr_marks_ue_ip_as_destination() -> None:
    spec = PdrSpec(
        pdr_id=2,
        far_id=2,
        source_interface=SourceInterface.CORE,
        ue_ipv4=UE_IP,
        ue_ip_is_destination=True,
    )
    parsed = reparse(codec.encode_create_pdr(spec, "internet"))
    assert codec.find_ie(parsed, IE_UE_IP_Address).SD == 1
    assert codec.find_ie(parsed, IE_SourceInterface).interface == SourceInterface.CORE
    assert codec.find_ie(parsed, IE_FTEID) is None


def test_chosen_fteid_sets_ch_and_omits_teid() -> None:
    """CH=1 asks the UPF to allocate; TEID and address must not be present."""
    spec = PdrSpec(
        pdr_id=1,
        far_id=1,
        source_interface=SourceInterface.ACCESS,
        f_teid=FTeid(choose=True),
    )
    fteid = codec.find_ie(reparse(codec.encode_create_pdr(spec, "internet")), IE_FTEID)
    assert fteid.CH == 1
    assert fteid.V4 == 1
    # scapy drops the conditional fields entirely when CH is set.
    assert getattr(fteid, "TEID", 0) in (0, None)


def test_remove_pdr_carries_only_the_id() -> None:
    parsed = reparse(codec.encode_remove_pdr(42))
    assert isinstance(parsed, IE_RemovePDR)
    assert codec.find_ie(parsed, IE_PDR_Id).id == 42


# ---------------------------------------------------------------------------
# FAR
# ---------------------------------------------------------------------------
def test_downlink_far_encodes_outer_header_creation() -> None:
    spec = FarSpec(
        far_id=2,
        apply_action=ApplyAction.FORW,
        destination_interface=DestinationInterface.ACCESS,
        outer_header_creation=OuterHeaderCreation(teid=0x1234, ipv4=GNB_IP),
    )
    parsed = reparse(codec.encode_create_far(spec, "internet"))
    ohc = codec.find_ie(parsed, IE_OuterHeaderCreation)
    assert ohc.GTPUUDPIPV4 == 1
    assert ohc.TEID == 0x1234
    assert ohc.ipv4 == GNB_IP


def test_uplink_far_has_no_outer_header_creation() -> None:
    spec = FarSpec(
        far_id=1,
        destination_interface=DestinationInterface.CORE,
    )
    parsed = reparse(codec.encode_create_far(spec, "internet"))
    assert codec.find_ie(parsed, IE_OuterHeaderCreation) is None


def test_apply_action_flags_combine() -> None:
    from scapy.contrib.pfcp import IE_ApplyAction

    spec = FarSpec(far_id=1, apply_action=ApplyAction.FORW | ApplyAction.NOCP)
    parsed = reparse(codec.encode_create_far(spec, "internet"))
    action = codec.find_ie(parsed, IE_ApplyAction)
    assert action.FORW == 1
    assert action.NOCP == 1
    assert action.DROP == 0
    assert action.BUFF == 0


def test_update_far_uses_update_forwarding_parameters() -> None:
    """Update FAR carries IE type 11, not the Create-side type 4."""
    from scapy.contrib.pfcp import (
        IE_ForwardingParameters,
        IE_UpdateForwardingParameters,
    )

    spec = FarSpec(
        far_id=2,
        destination_interface=DestinationInterface.ACCESS,
        outer_header_creation=OuterHeaderCreation(teid=9, ipv4=GNB_IP),
    )
    parsed = reparse(codec.encode_update_far(spec, "internet"))
    assert codec.find_ie(parsed, IE_UpdateForwardingParameters) is not None
    assert codec.find_ie(parsed, IE_ForwardingParameters) is None


# ---------------------------------------------------------------------------
# QER -- the IEs the reference tooling never exercised
# ---------------------------------------------------------------------------
def test_create_qer_round_trip_bitrates_in_kbps() -> None:
    spec = QerSpec(
        qer_id=3,
        qfi=5,
        gbr_ul_kbps=50_000,
        gbr_dl_kbps=60_000,
        mbr_ul_kbps=100_000,
        mbr_dl_kbps=120_000,
        gate_ul=GateStatus.OPEN,
        gate_dl=GateStatus.CLOSED,
    )
    parsed = reparse(codec.encode_create_qer(spec))

    assert isinstance(parsed, IE_CreateQER)
    assert codec.find_ie(parsed, IE_QER_Id).id == 3

    mbr = codec.find_ie(parsed, IE_MBR)
    assert (mbr.ul, mbr.dl) == (100_000, 120_000)

    gbr = codec.find_ie(parsed, IE_GBR)
    assert (gbr.ul, gbr.dl) == (50_000, 60_000)

    gate = codec.find_ie(parsed, IE_GateStatus)
    assert gate.ul == GateStatus.OPEN
    assert gate.dl == GateStatus.CLOSED

    assert codec.find_ie(parsed, IE_QFI).QFI == 5


def test_default_flow_qer_omits_bitrate_ies() -> None:
    """A QER with no GBR/MBR is the default flow; the IEs must be absent.

    Their absence is behaviourally significant -- the UPF selects a different HTB
    class layout for the default flow -- so emitting zeroed IEs would change the
    meaning of the message.
    """
    parsed = reparse(codec.encode_create_qer(QerSpec(qer_id=1, qfi=9)))
    assert codec.find_ie(parsed, IE_MBR) is None
    assert codec.find_ie(parsed, IE_GBR) is None
    assert codec.find_ie(parsed, IE_QER_Id).id == 1


def test_update_qer_round_trip() -> None:
    original = gbr_qer(qer_id=1, gbr_dl_kbps=50_000, mbr_dl_kbps=100_000)
    updated = original.with_bitrates(gbr_dl_kbps=10_000, mbr_dl_kbps=20_000)
    parsed = reparse(codec.encode_update_qer(updated))

    assert isinstance(parsed, IE_UpdateQER)
    assert codec.find_ie(parsed, IE_GBR).dl == 10_000
    assert codec.find_ie(parsed, IE_MBR).dl == 20_000
    # Uplink values are carried through untouched.
    assert codec.find_ie(parsed, IE_GBR).ul == original.gbr_ul_kbps


# ---------------------------------------------------------------------------
# Whole messages
# ---------------------------------------------------------------------------
def test_establishment_request_round_trip(settings: Settings) -> None:
    spec = basic_ipv4_session(settings, qer=gbr_qer())
    request = codec.session_establishment_request(
        spec, node_id="192.168.70.140", cp_seid=0x1234
    )
    wire = bytes(PFCP(version=1, S=1, seid=0, seq=1) / request)
    parsed = PFCP(wire)

    assert parsed.message_type == 50
    assert parsed.S == 1
    assert parsed.seid == 0, "establishment carries SEID=0 with S=1"

    from scapy.contrib.pfcp import IE_FSEID

    fseid = codec.find_ie(parsed.payload, IE_FSEID)
    assert fseid.seid == 0x1234
    assert fseid.v4 == 1, "IE_FSEID uses lowercase v4, unlike IE_FTEID"

    pdr_ids = {
        ie.id
        for ie in codec.iter_ies(parsed.payload)
        if isinstance(ie, IE_PDR_Id)
    }
    assert pdr_ids == {1, 2}


def test_modification_request_emits_removals_before_creations() -> None:
    delta = ModificationSpec(
        remove_pdr_ids=(3, 4),
        remove_qer_ids=(2,),
        create_pdrs=(
            PdrSpec(
                pdr_id=3,
                far_id=1,
                source_interface=SourceInterface.CORE,
                ue_ipv4=UE_IP,
                ue_ip_is_destination=True,
            ),
        ),
    )
    request = codec.session_modification_request(delta, network_instance="internet")
    parsed = type(request)(bytes(request))

    top_level = [type(ie).__name__ for ie in parsed.IE_list]
    assert top_level.index("IE_RemovePDR") < top_level.index("IE_CreatePDR")
    assert top_level.count("IE_RemovePDR") == 2
    assert top_level.count("IE_RemoveQER") == 1


def test_modification_reports_reused_rule_ids() -> None:
    """A rule ID both removed and re-created in one request is the interesting case."""
    delta = ModificationSpec(
        remove_pdr_ids=(3,),
        create_pdrs=(
            PdrSpec(
                pdr_id=3,
                far_id=1,
                source_interface=SourceInterface.CORE,
                ue_ipv4=UE_IP,
                ue_ip_is_destination=True,
            ),
        ),
    )
    assert delta.reused_pdr_ids() == (3,)
    assert delta.removal_count == 1


def test_deletion_request_body_is_empty() -> None:
    request = codec.session_deletion_request()
    assert list(request.IE_list) == []


# ---------------------------------------------------------------------------
# Response decoding
# ---------------------------------------------------------------------------
def test_decode_establishment_response_extracts_seid_and_created_pdr() -> None:
    from scapy.contrib.pfcp import (
        IE_FSEID,
        IE_Cause,
        IE_CreatedPDR,
        PFCPSessionEstablishmentResponse,
    )

    response = PFCPSessionEstablishmentResponse(
        IE_list=[
            IE_Cause(cause=1),
            IE_FSEID(v4=1, seid=0xDEADBEEF, ipv4=N3_IP),
            IE_CreatedPDR(
                IE_list=[IE_PDR_Id(id=1), IE_FTEID(V4=1, TEID=0x99, ipv4=N3_IP)]
            ),
        ]
    )
    wire = bytes(PFCP(version=1, S=1, seid=0x1234, seq=7) / response)

    decoded = codec.decode_response(PFCP(wire))
    assert decoded.accepted
    assert decoded.seq == 7
    assert decoded.up_seid == 0xDEADBEEF
    assert decoded.teid_for(1) == 0x99
    assert decoded.teid_for(2) is None


def test_decode_rejected_response() -> None:
    from scapy.contrib.pfcp import IE_Cause, PFCPSessionModificationResponse

    from pfcpkit.pfcp.types import Cause

    response = PFCPSessionModificationResponse(IE_list=[IE_Cause(cause=65)])
    wire = bytes(PFCP(version=1, S=1, seid=1, seq=3) / response)

    decoded = codec.decode_response(PFCP(wire))
    assert not decoded.accepted
    assert decoded.cause == Cause.SESSION_CONTEXT_NOT_FOUND


def test_decode_rejects_non_pfcp_payload() -> None:
    from scapy.packet import Raw

    from pfcpkit.errors import PfcpDecodeError

    with pytest.raises(PfcpDecodeError):
        codec.decode_response(Raw(b"\x00\x01\x02"))
