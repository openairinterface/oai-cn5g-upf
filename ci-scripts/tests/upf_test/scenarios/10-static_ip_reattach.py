# SPDX-License-Identifier: MIT
"""Re-attach on a recycled UE IP and check the new session owns it.

**Scenario.** Establish a session for a UE address, confirm that address is
attributed to it, delete the session, then establish a second session for the *same*
address with different TEIDs -- the static-IP re-attach an SMF performs when a UE
detaches and returns.

**Expected behaviour.** Two things, checked in order. Deleting the first session clears
its UE-address attribution, since the session no longer exists. Establishing the second
then attributes that address to the new SEID, so downlink traffic for the UE is matched
against the session actually carrying it.

**Expected output.** Four passing checks: the precondition that the first session owned
its address, the entry cleared on deletion, the accepted re-establishment, and the
address now attributed to the second SEID. No warnings.

If the address is still attributed to the *first* SEID, the scenario adds a warning
naming both SEIDs. That distinguishes the two ways this can go wrong -- an address left
unclaimed is recoverable, whereas one attributed to a session that no longer exists
routes the UE's downlink traffic at a session the UPF has already torn down.
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.pfcp.session import SessionContext
from pfcpkit.scenarios import register

from .base import OaiScenario


@register
class StaticIpReattach(OaiScenario):
    """A new session on a recycled UE IP must take ownership of the map entry."""

    name = "static_ip_reattach"
    description = "Re-establishing on a recycled UE IP transfers ownership of it"
    tags = frozenset({"datapath", "regression"})
    requires = frozenset({Capability.RULE_STATE})
    ue_index = 19

    def arrange(self) -> None:
        settings = self.ctx.settings
        self.ue_address = self.ue_ip()

        self.first: SessionContext = self.establish(
            presets.basic_ipv4_session(
                settings, ue_ipv4=self.ue_address, ul_teid=0x1610, dl_teid=0x1611
            )
        )
        self.first_seid = self.first.require_up_seid()

        owner = self.rules.seid_for_ue_ip(self.ue_address)
        self.report.require(
            "the first session owns its UE IP",
            owner == self.first_seid,
            f"session_by_ue_ip_map[{self.ue_address}] = "
            f"{'absent' if owner is None else hex(owner)}, "
            f"expected 0x{self.first_seid:x}",
        )

    def act(self) -> None:
        # Delete, then re-attach on the same address with different TEIDs -- the
        # static-IP re-attach an SMF performs after a UE detaches and returns.
        self.delete(self.first)
        self.owner_after_delete = self.rules.seid_for_ue_ip(self.ue_address)

        self.second = self.establish(
            presets.basic_ipv4_session(
                self.ctx.settings,
                ue_ipv4=self.ue_address,
                ul_teid=0x1620,
                dl_teid=0x1621,
            )
        )
        self.second_seid = self.second.require_up_seid()

    def verify(self) -> None:
        report = self.report

        report.check(
            "the UE IP entry is cleared when its session is deleted",
            self.owner_after_delete is None,
            f"session_by_ue_ip_map still maps {self.ue_address} to "
            f"{hex(self.owner_after_delete or 0)} after deletion",
        )

        owner = self.rules.seid_for_ue_ip(self.ue_address)
        report.check_eq(
            "the re-attached session owns the UE IP", self.second_seid, owner
        )

        if owner == self.first_seid:
            report.warn(
                f"{self.ue_address} is still attributed to the deleted session "
                f"0x{self.first_seid:x} rather than the live 0x{self.second_seid:x}: "
                "downlink traffic for this UE would be matched against a session "
                "that no longer exists"
            )
