# SPDX-License-Identifier: MIT
"""Intent-revealing specifications for PFCP rules and sessions.

Scenarios describe *what* they want installed; :mod:`pfcpkit.pfcp.codec` decides
how it is encoded. Keeping these as plain frozen dataclasses means the whole
model layer is unit-testable with no scapy, no socket and no UPF.

Everything is frozen and uses tuples rather than lists: a spec is a value, and
accidentally mutating one that a scenario already sent would make failures very
hard to reason about.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .pfcp.types import (
    ApplyAction,
    DestinationInterface,
    GateStatus,
    OuterHeaderRemoval,
    PdnType,
    SourceInterface,
)

# ---------------------------------------------------------------------------
# Leaf specs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FTeid:
    """Local F-TEID for a PDI -- TS 29.244 Section 8.2.3.

    ``choose=True`` sets the CH bit, asking the UPF to allocate the TEID itself
    and report it back in the Created PDR IE. That path is worth exercising: it
    is where the UPF allocates from a monotonic, never-released counter.
    """

    teid: int = 0
    ipv4: str | None = None
    choose: bool = False

    def __post_init__(self) -> None:
        if self.choose:
            if self.teid:
                raise ValueError("choose=True cannot be combined with an explicit teid")
        elif self.ipv4 is None:
            raise ValueError("an explicit F-TEID requires ipv4")


@dataclass(frozen=True)
class SdfFilter:
    """SDF Filter IE -- TS 29.244 Section 8.2.5 (IPFilterRule syntax)."""

    flow_description: str


@dataclass(frozen=True)
class OuterHeaderCreation:
    """Outer Header Creation for a FAR -- TS 29.244 Section 8.2.56.

    Only the GTP-U/UDP/IPv4 case is modelled, which is what N3 downlink needs.
    """

    teid: int
    ipv4: str


# ---------------------------------------------------------------------------
# Rule specs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PdrSpec:
    """Packet Detection Rule -- TS 29.244 Table 7.5.2.2-1."""

    pdr_id: int
    far_id: int
    source_interface: SourceInterface
    precedence: int = 65535
    ue_ipv4: str | None = None
    #: SD bit of the UE IP Address IE: False = source (uplink), True = destination
    #: (downlink). TS 29.244 Section 8.2.62.
    ue_ip_is_destination: bool = False
    f_teid: FTeid | None = None
    qer_id: int | None = None
    urr_id: int | None = None
    qfi: int | None = None
    sdf_filter: SdfFilter | None = None
    outer_header_removal: OuterHeaderRemoval | None = None
    network_instance: str | None = None

    def __post_init__(self) -> None:
        if self.pdr_id <= 0:
            raise ValueError(f"pdr_id must be positive, got {self.pdr_id}")
        if self.source_interface is SourceInterface.ACCESS and self.f_teid is None:
            raise ValueError(
                f"PDR {self.pdr_id}: an Access-side PDR needs an F-TEID to match on"
            )


@dataclass(frozen=True)
class FarSpec:
    """Forwarding Action Rule -- TS 29.244 Table 7.5.2.3-1."""

    far_id: int
    apply_action: int = ApplyAction.FORW
    destination_interface: DestinationInterface | None = None
    outer_header_creation: OuterHeaderCreation | None = None
    network_instance: str | None = None

    def __post_init__(self) -> None:
        if self.far_id <= 0:
            raise ValueError(f"far_id must be positive, got {self.far_id}")


@dataclass(frozen=True)
class QerSpec:
    """QoS Enforcement Rule -- TS 29.244 Table 7.5.2.5-1.

    Bitrates are in kbps, matching the MBR/GBR IE encoding (TS 29.244
    Sections 8.2.8 and 8.2.9).

    A QER with neither GBR nor MBR is treated by the UPF as the session's
    *default* QoS flow, which selects a different HTB class layout -- so the
    presence or absence of these fields is behaviourally significant, not
    cosmetic.
    """

    qer_id: int
    qfi: int | None = None
    mbr_ul_kbps: int | None = None
    mbr_dl_kbps: int | None = None
    gbr_ul_kbps: int | None = None
    gbr_dl_kbps: int | None = None
    gate_ul: GateStatus = GateStatus.OPEN
    gate_dl: GateStatus = GateStatus.OPEN

    def __post_init__(self) -> None:
        if self.qer_id <= 0:
            raise ValueError(f"qer_id must be positive, got {self.qer_id}")
        for name in ("mbr_ul_kbps", "mbr_dl_kbps", "gbr_ul_kbps", "gbr_dl_kbps"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} must be >= 0, got {value}")
        if (
            self.gbr_dl_kbps is not None
            and self.mbr_dl_kbps is not None
            and self.gbr_dl_kbps > self.mbr_dl_kbps
        ):
            raise ValueError(
                f"QER {self.qer_id}: downlink GBR ({self.gbr_dl_kbps}) exceeds "
                f"MBR ({self.mbr_dl_kbps})"
            )

    @property
    def is_default_flow(self) -> bool:
        """True when neither GBR nor MBR is present (the default QoS flow)."""
        return all(
            v is None
            for v in (
                self.mbr_ul_kbps,
                self.mbr_dl_kbps,
                self.gbr_ul_kbps,
                self.gbr_dl_kbps,
            )
        )

    def with_bitrates(
        self,
        *,
        gbr_dl_kbps: int | None = None,
        mbr_dl_kbps: int | None = None,
    ) -> QerSpec:
        """Return a copy with new downlink bitrates.

        The natural way to express "modify this flow's rate", which is exactly
        what the QoS-rate-change scenario needs.
        """
        return replace(
            self,
            gbr_dl_kbps=self.gbr_dl_kbps if gbr_dl_kbps is None else gbr_dl_kbps,
            mbr_dl_kbps=self.mbr_dl_kbps if mbr_dl_kbps is None else mbr_dl_kbps,
        )


# ---------------------------------------------------------------------------
# Session-level specs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionSpec:
    """Everything needed to build a Session Establishment Request."""

    ue_ipv4: str
    pdrs: tuple[PdrSpec, ...]
    fars: tuple[FarSpec, ...]
    qers: tuple[QerSpec, ...] = ()
    pdn_type: PdnType = PdnType.IPV4
    apn_dnn: str = "internet"
    network_instance: str = "internet"

    def __post_init__(self) -> None:
        if not self.pdrs:
            raise ValueError("a session needs at least one PDR")
        _reject_duplicates("pdr_id", [p.pdr_id for p in self.pdrs])
        _reject_duplicates("far_id", [f.far_id for f in self.fars])
        _reject_duplicates("qer_id", [q.qer_id for q in self.qers])

        far_ids = {f.far_id for f in self.fars}
        qer_ids = {q.qer_id for q in self.qers}
        for pdr in self.pdrs:
            if pdr.far_id not in far_ids:
                raise ValueError(
                    f"PDR {pdr.pdr_id} references FAR {pdr.far_id}, which is not "
                    f"in this session (have {sorted(far_ids)})"
                )
            if pdr.qer_id is not None and pdr.qer_id not in qer_ids:
                raise ValueError(
                    f"PDR {pdr.pdr_id} references QER {pdr.qer_id}, which is not "
                    f"in this session (have {sorted(qer_ids)})"
                )

    def qer(self, qer_id: int) -> QerSpec:
        """Look up a QER by id, for scenarios deriving an update from it."""
        for q in self.qers:
            if q.qer_id == qer_id:
                return q
        raise KeyError(f"no QER {qer_id} in this session spec")

    def far(self, far_id: int) -> FarSpec:
        """Look up a FAR by id.

        Rule ids are chosen by the CP function (TS 29.244 Sections 8.2.36, 8.2.74,
        8.2.75) and are session-scoped -- the UPF never allocates them. A scenario
        that wants "a FAR this session already has" should resolve it through the
        spec rather than a shared constant, so that referencing a FAR which does
        not exist fails loudly here instead of being answered with
        ``MANDATORY_IE_MISSING`` and mistaken for a UPF defect.
        """
        for f in self.fars:
            if f.far_id == far_id:
                return f
        raise KeyError(f"no FAR {far_id} in this session spec")

    def downlink_pdrs(self) -> tuple[PdrSpec, ...]:
        """PDRs on the Core side, i.e. the downlink direction."""
        return tuple(
            p for p in self.pdrs if p.source_interface is SourceInterface.CORE
        )

    def uplink_pdrs(self) -> tuple[PdrSpec, ...]:
        """PDRs on the Access side, i.e. the uplink direction.

        Selecting by source interface rather than by position keeps a scenario
        independent of the order a preset happens to list its rules in.
        """
        return tuple(
            p for p in self.pdrs if p.source_interface is SourceInterface.ACCESS
        )

    def pdrs_for_qer(self, qer_id: int) -> tuple[PdrSpec, ...]:
        """PDRs referencing a given QER -- one QoS flow's detection rules."""
        return tuple(p for p in self.pdrs if p.qer_id == qer_id)

    def far_ids_exclusive_to(self, pdrs: tuple[PdrSpec, ...]) -> tuple[int, ...]:
        """FAR ids used by ``pdrs`` and by no other PDR in the session.

        Withdrawing a QoS flow means removing its PDRs and any FAR that existed
        only to serve them -- removing a FAR still referenced by a surviving PDR
        would break that PDR instead of testing anything.
        """
        theirs = {p.far_id for p in pdrs}
        others = {p.far_id for p in self.pdrs if p not in pdrs}
        return tuple(sorted(theirs - others))

    def downlink_qers(self) -> tuple[QerSpec, ...]:
        """QERs referenced by a Core-side (downlink) PDR.

        Mirrors how the UPF derives ``qers_downlink``, which is what gates HTB
        class creation.
        """
        ids = {
            p.qer_id
            for p in self.pdrs
            if p.source_interface is SourceInterface.CORE and p.qer_id is not None
        }
        return tuple(q for q in self.qers if q.qer_id in ids)


@dataclass(frozen=True)
class ModificationSpec:
    """Deltas for a Session Modification Request -- TS 29.244 Section 7.5.4.

    Field order here matches the order the UPF applies them (removals, then
    creations, then updates), which is what makes rule-ID reuse within a single
    request interesting: the same numeric ID can legitimately appear in both
    ``remove_pdr_ids`` and ``create_pdrs``.
    """

    remove_pdr_ids: tuple[int, ...] = ()
    remove_far_ids: tuple[int, ...] = ()
    remove_qer_ids: tuple[int, ...] = ()
    create_pdrs: tuple[PdrSpec, ...] = ()
    create_fars: tuple[FarSpec, ...] = ()
    create_qers: tuple[QerSpec, ...] = ()
    update_pdrs: tuple[PdrSpec, ...] = ()
    update_fars: tuple[FarSpec, ...] = ()
    update_qers: tuple[QerSpec, ...] = ()

    def __post_init__(self) -> None:
        if self.is_empty:
            raise ValueError("a modification must carry at least one delta")

    @property
    def is_empty(self) -> bool:
        return not any(
            (
                self.remove_pdr_ids,
                self.remove_far_ids,
                self.remove_qer_ids,
                self.create_pdrs,
                self.create_fars,
                self.create_qers,
                self.update_pdrs,
                self.update_fars,
                self.update_qers,
            )
        )

    @property
    def removal_count(self) -> int:
        """Number of removal IEs.

        The UPF's per-removal datapath rebuild makes this the expected *excess*
        rebuild count while Fix 1 is outstanding.
        """
        return (
            len(self.remove_pdr_ids)
            + len(self.remove_far_ids)
            + len(self.remove_qer_ids)
        )

    def reused_pdr_ids(self) -> tuple[int, ...]:
        """PDR IDs that are both removed and re-created in this same request."""
        removed = set(self.remove_pdr_ids)
        return tuple(sorted(removed.intersection(p.pdr_id for p in self.create_pdrs)))

    def describe(self) -> str:
        parts: list[str] = []
        if self.remove_pdr_ids:
            parts.append(f"-pdr{list(self.remove_pdr_ids)}")
        if self.remove_far_ids:
            parts.append(f"-far{list(self.remove_far_ids)}")
        if self.remove_qer_ids:
            parts.append(f"-qer{list(self.remove_qer_ids)}")
        if self.create_pdrs:
            parts.append(f"+pdr{[p.pdr_id for p in self.create_pdrs]}")
        if self.create_fars:
            parts.append(f"+far{[f.far_id for f in self.create_fars]}")
        if self.create_qers:
            parts.append(f"+qer{[q.qer_id for q in self.create_qers]}")
        if self.update_pdrs:
            parts.append(f"~pdr{[p.pdr_id for p in self.update_pdrs]}")
        if self.update_fars:
            parts.append(f"~far{[f.far_id for f in self.update_fars]}")
        if self.update_qers:
            parts.append(f"~qer{[q.qer_id for q in self.update_qers]}")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Decoded responses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CreatedPdr:
    """Created PDR IE -- carries a UPF-allocated F-TEID when CH was set."""

    pdr_id: int
    teid: int | None = None
    ipv4: str | None = None


@dataclass(frozen=True)
class PfcpResponse:
    """Decoded view of a PFCP response.

    ``raw`` keeps the scapy packet available as an escape hatch for one-off
    assertions, so an unusual check never requires extending the codec first.
    """

    message_type: int
    seq: int
    cause: int | None
    up_seid: int | None = None
    created_pdrs: tuple[CreatedPdr, ...] = ()
    failed_rule_id: int | None = None
    raw: object | None = field(default=None, repr=False, compare=False)

    @property
    def accepted(self) -> bool:
        from .pfcp.types import Cause  # local import keeps models import-light

        return self.cause == Cause.REQUEST_ACCEPTED

    def teid_for(self, pdr_id: int) -> int | None:
        for created in self.created_pdrs:
            if created.pdr_id == pdr_id:
                return created.teid
        return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _reject_duplicates(label: str, values: list[int]) -> None:
    seen: set[int] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"duplicate {label} {value} in the same session")
        seen.add(value)
