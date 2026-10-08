# SPDX-License-Identifier: MIT
"""Remove one QoS flow from a live session and check its rules are pruned.

**Scenario.** Establish a session with two QoS flows -- four PDRs, four FARs, two
QERs -- then modify it once to populate the classification state, then send a single
Session Modification Request withdrawing the whole second flow: its two PDRs, the FAR
used only by them, and its QER.

The first modification is not incidental. This UPF writes classification state in
``ModifyPipeline`` only, never in ``CreatePipeline``, so after establishment alone
there is nothing in ``sdf_filters_map`` for a later removal to prune.

**Expected behaviour.** The UPF accepts the modification and removes exactly what was
asked for. After it, ``rules_match_pdr_map`` holds no entry for either withdrawn PDR
and ``sdf_filters_map`` holds none for the withdrawn QFI, while every rule belonging
to the surviving flow is still installed. TS 29.244 Section 5.2.1 makes removal
mandatory, not advisory: a rule the CP has withdrawn must stop affecting traffic.

**Expected output.** Eight passing checks: the precondition that a second flow exists
to withdraw, the installation precondition, the accepted modification, absence of each
of the two removed PDRs, survival of the remaining PDRs, and absence of the removed
QFI. No warnings.

Entries here are keyed by (pdr_id, seid) and (seid, qfi), so a stale one cannot be hit
by a *different* session's traffic. What it costs instead is unbounded growth of maps
sized for a fixed session count, and rules outliving the session that owns them.
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.models import ModificationSpec
from pfcpkit.pfcp.session import SessionContext
from pfcpkit.scenarios import register

from .base import OaiScenario


@register
class MapPruningOnRemoval(OaiScenario):
    """Removing a PDR or QER must remove the rule state it installed."""

    name = "map_pruning"
    description = "Removing a PDR or QER prunes the rule state it installed"
    tags = frozenset({"datapath", "regression"})
    requires = frozenset({Capability.RULE_STATE})
    ue_index = 12

    def arrange(self) -> None:
        settings = self.ctx.settings
        self.session: SessionContext = self.establish(
            presets.multi_flow_session(
                settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x1210,
                dl_teid=0x1211,
                extra_ul_teid=0x1212,
                extra_dl_teid=0x1213,
            )
        )
        seid = self.session.require_up_seid()
        spec = self.session.spec

        # A no-op-shaped modification, purely to populate sdf_filters_map: the UPF
        # writes SDF filters in ModifyPipeline only, never in CreatePipeline, so
        # after establishment alone there is nothing there to prune.
        self.modify(
            self.session,
            ModificationSpec(update_qers=(spec.qer(presets.DEFAULT_QER_ID),)),
        )

        # Derive the flow to withdraw from the session that was actually
        # established, not from preset constants. `spec.qer()` raises if the id is
        # absent, and `require_pdrs_installed` below refuses to proceed unless the
        # rules are really in the map -- otherwise the removal would no-op and
        # "they are absent afterwards" would pass while testing nothing.
        self.doomed_qer = spec.qer(presets.EXTRA_QER_ID)
        doomed_pdrs = spec.pdrs_for_qer(self.doomed_qer.qer_id)
        self.removed_pdrs = tuple(p.pdr_id for p in doomed_pdrs)
        self.removed_fars = spec.far_ids_exclusive_to(doomed_pdrs)
        self.removed_qfi = self.doomed_qer.qfi
        self.surviving_pdrs = tuple(
            p.pdr_id for p in spec.pdrs if p.pdr_id not in self.removed_pdrs
        )

        self.report.require(
            "the session has a second QoS flow to withdraw",
            bool(self.removed_pdrs) and bool(self.surviving_pdrs),
            f"derived removals={self.removed_pdrs} survivors={self.surviving_pdrs}",
        )

        self.pdrs_before = self.rules.installed_pdr_ids(seid)
        self.qfis_before = self.rules.installed_qfis(seid)
        self.require_pdrs_installed(seid, self.removed_pdrs)

    def act(self) -> None:
        self.response = self.modify(
            self.session,
            ModificationSpec(
                remove_pdr_ids=self.removed_pdrs,
                remove_far_ids=self.removed_fars,
                remove_qer_ids=(self.doomed_qer.qer_id,),
            ),
        )

    def verify(self) -> None:
        report = self.report
        seid = self.session.require_up_seid()

        report.check("modification accepted", self.response.accepted)

        pdrs_after = self.rules.installed_pdr_ids(seid)
        for pdr_id in self.removed_pdrs:
            report.check_absent(
                f"PDR {pdr_id} is gone from rules_match_pdr_map", pdr_id, pdrs_after
            )
        report.check(
            "the surviving PDRs are still installed",
            all(pdr_id in pdrs_after for pdr_id in self.surviving_pdrs),
            f"expected {list(self.surviving_pdrs)} to remain; "
            f"rules_match_pdr_map holds {pdrs_after}",
        )

        if self.removed_qfi is not None and self.qfis_before:
            report.check_absent(
                f"QFI {self.removed_qfi} is gone from sdf_filters_map",
                self.removed_qfi,
                self.rules.installed_qfis(seid),
            )
