# SPDX-License-Identifier: MIT
"""Tests for the spec dataclasses.

The validation in these models exists to turn silent misconfiguration into an
immediate, located error. A PDR referencing a FAR that is not in the session, for
instance, would otherwise be rejected by the UPF with a bare "mandatory IE
missing" -- true, but useless for finding the mistake.
"""

from __future__ import annotations

import pytest

from pfcpkit.config import Settings
from pfcpkit.models import (
    FarSpec,
    FTeid,
    ModificationSpec,
    PdrSpec,
    QerSpec,
    SessionSpec,
)
from pfcpkit.pfcp.types import SourceInterface
from pfcpkit.presets import basic_ipv4_session, gbr_qer, multi_flow_session

UE_IP = "12.1.1.2"
N3_IP = "192.168.72.134"


@pytest.fixture()
def settings() -> Settings:
    return Settings.from_env({"UE_IPV4_BASE": UE_IP, "UPF_N3_ADDR": N3_IP})


# ---------------------------------------------------------------------------
# FTeid
# ---------------------------------------------------------------------------
def test_explicit_fteid_requires_an_address() -> None:
    with pytest.raises(ValueError, match="requires ipv4"):
        FTeid(teid=1)


def test_chosen_fteid_rejects_an_explicit_teid() -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        FTeid(teid=1, ipv4=N3_IP, choose=True)


def test_chosen_fteid_needs_no_address() -> None:
    assert FTeid(choose=True).choose is True


# ---------------------------------------------------------------------------
# PdrSpec
# ---------------------------------------------------------------------------
def test_access_pdr_requires_an_fteid() -> None:
    """An Access-side PDR with no F-TEID could never match a packet."""
    with pytest.raises(ValueError, match="needs an F-TEID"):
        PdrSpec(pdr_id=1, far_id=1, source_interface=SourceInterface.ACCESS)


def test_core_pdr_needs_no_fteid() -> None:
    spec = PdrSpec(
        pdr_id=2,
        far_id=1,
        source_interface=SourceInterface.CORE,
        ue_ipv4=UE_IP,
        ue_ip_is_destination=True,
    )
    assert spec.f_teid is None


def test_pdr_id_must_be_positive() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        PdrSpec(pdr_id=0, far_id=1, source_interface=SourceInterface.CORE)


# ---------------------------------------------------------------------------
# QerSpec
# ---------------------------------------------------------------------------
def test_gbr_above_mbr_is_rejected() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        QerSpec(qer_id=1, gbr_dl_kbps=200, mbr_dl_kbps=100)


def test_default_flow_detection() -> None:
    assert QerSpec(qer_id=1, qfi=9).is_default_flow
    assert not QerSpec(qer_id=1, qfi=5, mbr_dl_kbps=1).is_default_flow


def test_with_bitrates_preserves_other_fields() -> None:
    original = gbr_qer(qer_id=4, qfi=6, gbr_dl_kbps=10, mbr_dl_kbps=20)
    updated = original.with_bitrates(gbr_dl_kbps=30, mbr_dl_kbps=40)

    assert (updated.gbr_dl_kbps, updated.mbr_dl_kbps) == (30, 40)
    assert updated.qer_id == original.qer_id
    assert updated.qfi == original.qfi
    assert updated.gbr_ul_kbps == original.gbr_ul_kbps
    # Frozen: the original is untouched.
    assert original.gbr_dl_kbps == 10


def test_negative_bitrate_is_rejected() -> None:
    with pytest.raises(ValueError, match="must be >= 0"):
        QerSpec(qer_id=1, mbr_dl_kbps=-1)


# ---------------------------------------------------------------------------
# SessionSpec
# ---------------------------------------------------------------------------
def test_session_rejects_dangling_far_reference() -> None:
    with pytest.raises(ValueError, match="references FAR 9"):
        SessionSpec(
            ue_ipv4=UE_IP,
            pdrs=(
                PdrSpec(
                    pdr_id=1,
                    far_id=9,
                    source_interface=SourceInterface.CORE,
                    ue_ipv4=UE_IP,
                ),
            ),
            fars=(FarSpec(far_id=1),),
        )


def test_session_rejects_dangling_qer_reference() -> None:
    with pytest.raises(ValueError, match="references QER 5"):
        SessionSpec(
            ue_ipv4=UE_IP,
            pdrs=(
                PdrSpec(
                    pdr_id=1,
                    far_id=1,
                    source_interface=SourceInterface.CORE,
                    ue_ipv4=UE_IP,
                    qer_id=5,
                ),
            ),
            fars=(FarSpec(far_id=1),),
        )


def test_session_rejects_duplicate_rule_ids() -> None:
    with pytest.raises(ValueError, match="duplicate pdr_id 1"):
        SessionSpec(
            ue_ipv4=UE_IP,
            pdrs=(
                PdrSpec(
                    pdr_id=1,
                    far_id=1,
                    source_interface=SourceInterface.CORE,
                    ue_ipv4=UE_IP,
                ),
                PdrSpec(
                    pdr_id=1,
                    far_id=1,
                    source_interface=SourceInterface.CORE,
                    ue_ipv4=UE_IP,
                ),
            ),
            fars=(FarSpec(far_id=1),),
        )


def test_session_needs_at_least_one_pdr() -> None:
    with pytest.raises(ValueError, match="at least one PDR"):
        SessionSpec(ue_ipv4=UE_IP, pdrs=(), fars=(FarSpec(far_id=1),))


def test_downlink_qers_mirrors_upf_gating(settings: Settings) -> None:
    """Only QERs on a Core-side PDR reach the UPF's qers_downlink list.

    That list is what gates HTB class creation, so this is the property a QoS
    scenario depends on.
    """
    spec = basic_ipv4_session(settings, qer=gbr_qer(qer_id=1))
    assert [q.qer_id for q in spec.downlink_qers()] == [1]

    # Attach the QER to the uplink PDR only -- no downlink QER, so no HTB class.
    uplink_only = SessionSpec(
        ue_ipv4=UE_IP,
        pdrs=(
            PdrSpec(
                pdr_id=1,
                far_id=1,
                source_interface=SourceInterface.ACCESS,
                f_teid=FTeid(teid=1, ipv4=N3_IP),
                qer_id=1,
            ),
        ),
        fars=(FarSpec(far_id=1),),
        qers=(gbr_qer(qer_id=1),),
    )
    assert uplink_only.downlink_qers() == ()


def test_session_qer_lookup(settings: Settings) -> None:
    spec = basic_ipv4_session(settings, qer=gbr_qer(qer_id=1))
    assert spec.qer(1).qer_id == 1
    with pytest.raises(KeyError):
        spec.qer(99)


def test_multi_flow_session_shape(settings: Settings) -> None:
    spec = multi_flow_session(settings)
    assert len(spec.pdrs) == 4
    assert len(spec.fars) == 3
    assert len(spec.qers) == 2
    assert len(spec.downlink_qers()) == 2


# ---------------------------------------------------------------------------
# ModificationSpec
# ---------------------------------------------------------------------------
def test_empty_modification_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one delta"):
        ModificationSpec()


def test_removal_count_sums_every_removal_kind() -> None:
    delta = ModificationSpec(
        remove_pdr_ids=(1, 2),
        remove_far_ids=(3,),
        remove_qer_ids=(4,),
    )
    assert delta.removal_count == 4


def test_describe_is_readable() -> None:
    delta = ModificationSpec(remove_pdr_ids=(3, 4), remove_qer_ids=(2,))
    described = delta.describe()
    assert "-pdr[3, 4]" in described
    assert "-qer[2]" in described
