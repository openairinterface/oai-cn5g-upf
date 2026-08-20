# SPDX-License-Identifier: MIT
"""Ready-made session specs, so scenarios don't each re-derive the boilerplate.

A minimal IPv4 PDU session needs a matched pair of PDRs and FARs -- uplink
(Access -> Core, decapsulate GTP-U) and downlink (Core -> Access, encapsulate).
Every scenario needs that shape, and only some of them care about its details.
"""

from __future__ import annotations

from .config import Settings
from .models import (
    FarSpec,
    FTeid,
    OuterHeaderCreation,
    PdrSpec,
    QerSpec,
    SdfFilter,
    SessionSpec,
)
from .pfcp.types import (
    ApplyAction,
    DestinationInterface,
    OuterHeaderRemoval,
    SourceInterface,
)

#: "Permit everything" IPFilterRule -- the SDF filter is what makes the UPF write
#: an ``sdf_filters_map`` entry, so scenarios asserting on that map need one.
PERMIT_ANY = "permit out ip from any to assigned"

# Rule-id conventions used by these presets. Uplink and downlink get distinct
# ids so a scenario can remove one direction without disturbing the other.
UPLINK_PDR_ID = 1
DOWNLINK_PDR_ID = 2
UPLINK_FAR_ID = 1
DOWNLINK_FAR_ID = 2
DEFAULT_QER_ID = 1

#: Second flow, used by scenarios that need something to remove.
EXTRA_UPLINK_PDR_ID = 3
EXTRA_DOWNLINK_PDR_ID = 4
EXTRA_FAR_ID = 3
EXTRA_QER_ID = 2


def ue_ipv4(settings: Settings, index: int = 0) -> str:
    """Derive a distinct UE IP from the configured base.

    Scenarios must not share a UE IP. The UPF keys ``session_by_ue_ip_map`` by it
    and -- this is Fix 6 -- never clears the entry on deletion, so a shared
    address turns one scenario's leftovers into another's failure. Give every
    scenario its own index.
    """
    octets = [int(part) for part in settings.ue_ipv4_base.split(".")]
    if len(octets) != 4:
        raise ValueError(
            f"UE_IPV4_BASE is not an IPv4 address: {settings.ue_ipv4_base}"
        )
    octets[3] += index
    if not 0 < octets[3] < 255:
        raise ValueError(
            f"UE IP index {index} takes {settings.ue_ipv4_base} out of its subnet"
        )
    return ".".join(str(part) for part in octets)


def uplink_pdr(
    pdr_id: int,
    far_id: int,
    *,
    ue_ipv4: str,
    teid: int,
    n3_addr: str,
    qer_id: int | None = None,
    qfi: int | None = None,
    precedence: int = 65535,
    sdf: str | None = PERMIT_ANY,
) -> PdrSpec:
    """Access-side PDR: match GTP-U on the N3 TEID and strip the outer header."""
    return PdrSpec(
        pdr_id=pdr_id,
        far_id=far_id,
        source_interface=SourceInterface.ACCESS,
        precedence=precedence,
        ue_ipv4=ue_ipv4,
        ue_ip_is_destination=False,
        f_teid=FTeid(teid=teid, ipv4=n3_addr),
        qer_id=qer_id,
        qfi=qfi,
        sdf_filter=None if sdf is None else SdfFilter(sdf),
        outer_header_removal=OuterHeaderRemoval.GTPU_UDP_IPV4,
    )


def downlink_pdr(
    pdr_id: int,
    far_id: int,
    *,
    ue_ipv4: str,
    qer_id: int | None = None,
    qfi: int | None = None,
    precedence: int = 65535,
    sdf: str | None = PERMIT_ANY,
) -> PdrSpec:
    """Core-side PDR: match on the UE IP as destination.

    A downlink PDR carrying a QER is what puts the QER into the UPF's
    ``qers_downlink`` list, which is the gate for HTB class creation -- so QoS
    scenarios must attach the QER on this side, not only uplink.
    """
    return PdrSpec(
        pdr_id=pdr_id,
        far_id=far_id,
        source_interface=SourceInterface.CORE,
        precedence=precedence,
        ue_ipv4=ue_ipv4,
        ue_ip_is_destination=True,
        qer_id=qer_id,
        qfi=qfi,
        sdf_filter=None if sdf is None else SdfFilter(sdf),
    )


def uplink_far(far_id: int) -> FarSpec:
    """Forward decapsulated uplink traffic to the Core (N6)."""
    return FarSpec(
        far_id=far_id,
        apply_action=ApplyAction.FORW,
        destination_interface=DestinationInterface.CORE,
    )


def downlink_far(far_id: int, *, teid: int, gnb_addr: str) -> FarSpec:
    """Encapsulate downlink traffic toward the gNB (N3)."""
    return FarSpec(
        far_id=far_id,
        apply_action=ApplyAction.FORW,
        destination_interface=DestinationInterface.ACCESS,
        outer_header_creation=OuterHeaderCreation(teid=teid, ipv4=gnb_addr),
    )


def gbr_qer(
    qer_id: int = DEFAULT_QER_ID,
    *,
    qfi: int = 5,
    gbr_dl_kbps: int = 50_000,
    mbr_dl_kbps: int = 100_000,
    gbr_ul_kbps: int = 50_000,
    mbr_ul_kbps: int = 100_000,
) -> QerSpec:
    """A dedicated (non-default) QoS flow with explicit GBR and MBR.

    These become the HTB class's ``rate`` and ``ceil``, which is what the
    QoS-rate-change scenario asserts on.
    """
    return QerSpec(
        qer_id=qer_id,
        qfi=qfi,
        gbr_dl_kbps=gbr_dl_kbps,
        mbr_dl_kbps=mbr_dl_kbps,
        gbr_ul_kbps=gbr_ul_kbps,
        mbr_ul_kbps=mbr_ul_kbps,
    )


def default_qer(qer_id: int = DEFAULT_QER_ID, *, qfi: int = 9) -> QerSpec:
    """A QER with neither GBR nor MBR -- the session's default QoS flow."""
    return QerSpec(qer_id=qer_id, qfi=qfi)


def basic_ipv4_session(
    settings: Settings,
    *,
    ue_ipv4: str | None = None,
    ul_teid: int = 1,
    dl_teid: int = 2,
    qer: QerSpec | None = None,
) -> SessionSpec:
    """One UE, one QoS flow: 2 PDRs, 2 FARs, and optionally one QER.

    This is the smallest session the UPF will install a full datapath for.
    """
    ue = ue_ipv4 or settings.ue_ipv4_base
    qfi = qer.qfi if qer is not None else None
    qer_id = qer.qer_id if qer is not None else None

    return SessionSpec(
        ue_ipv4=ue,
        pdrs=(
            uplink_pdr(
                UPLINK_PDR_ID,
                UPLINK_FAR_ID,
                ue_ipv4=ue,
                teid=ul_teid,
                n3_addr=settings.upf_n3_addr,
                qer_id=qer_id,
                qfi=qfi,
            ),
            downlink_pdr(
                DOWNLINK_PDR_ID,
                DOWNLINK_FAR_ID,
                ue_ipv4=ue,
                qer_id=qer_id,
                qfi=qfi,
            ),
        ),
        fars=(
            uplink_far(UPLINK_FAR_ID),
            downlink_far(DOWNLINK_FAR_ID, teid=dl_teid, gnb_addr=settings.gnb_n3_addr),
        ),
        qers=() if qer is None else (qer,),
        apn_dnn=settings.apn_dnn,
        network_instance=settings.network_instance,
    )


def multi_flow_session(
    settings: Settings,
    *,
    ue_ipv4: str | None = None,
    ul_teid: int = 1,
    dl_teid: int = 2,
    extra_ul_teid: int = 3,
    extra_dl_teid: int = 4,
) -> SessionSpec:
    """Two QoS flows: 4 PDRs, 3 FARs, 2 QERs.

    Gives a scenario a whole second flow it can remove in a single modification
    -- which is what makes the per-removal pipeline rebuild observable, since the
    excess rebuild count scales with the number of removal IEs.
    """
    ue = ue_ipv4 or settings.ue_ipv4_base
    primary = gbr_qer(DEFAULT_QER_ID, qfi=5)
    secondary = gbr_qer(
        EXTRA_QER_ID, qfi=6, gbr_dl_kbps=20_000, mbr_dl_kbps=40_000
    )

    return SessionSpec(
        ue_ipv4=ue,
        pdrs=(
            uplink_pdr(
                UPLINK_PDR_ID,
                UPLINK_FAR_ID,
                ue_ipv4=ue,
                teid=ul_teid,
                n3_addr=settings.upf_n3_addr,
                qer_id=primary.qer_id,
                qfi=primary.qfi,
            ),
            downlink_pdr(
                DOWNLINK_PDR_ID,
                DOWNLINK_FAR_ID,
                ue_ipv4=ue,
                qer_id=primary.qer_id,
                qfi=primary.qfi,
            ),
            uplink_pdr(
                EXTRA_UPLINK_PDR_ID,
                EXTRA_FAR_ID,
                ue_ipv4=ue,
                teid=extra_ul_teid,
                n3_addr=settings.upf_n3_addr,
                qer_id=secondary.qer_id,
                qfi=secondary.qfi,
                precedence=100,
            ),
            downlink_pdr(
                EXTRA_DOWNLINK_PDR_ID,
                EXTRA_FAR_ID,
                ue_ipv4=ue,
                qer_id=secondary.qer_id,
                qfi=secondary.qfi,
                precedence=100,
            ),
        ),
        fars=(
            uplink_far(UPLINK_FAR_ID),
            downlink_far(DOWNLINK_FAR_ID, teid=dl_teid, gnb_addr=settings.gnb_n3_addr),
            downlink_far(
                EXTRA_FAR_ID, teid=extra_dl_teid, gnb_addr=settings.gnb_n3_addr
            ),
        ),
        qers=(primary, secondary),
        apn_dnn=settings.apn_dnn,
        network_instance=settings.network_instance,
    )
