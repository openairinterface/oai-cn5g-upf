# SPDX-License-Identifier: MIT
"""Send one modification carrying several removals and count the datapath rebuilds.

**Scenario.** Establish a session with two QoS flows, then send a single Session
Modification Request that withdraws the whole second flow -- two PDRs, one FAR and one
QER, so four removal IEs in one request. Count how many times the UPF rebuilds the
datapath for that one request.

Rule ids are derived from the established session rather than written as constants.
The rebuild count scales with the number of removal *IEs* whether or not they match
anything, so a stale constant would still produce a number -- it would just be a number
about removing rules that never existed.

**Expected behaviour.** One Session Modification Request produces **one** datapath
rebuild. The request is a single atomic instruction (TS 29.244 Section 5.2.1): the UPF
applies all of its IEs and reprograms the datapath once, rather than reprogramming it
per IE. Rebuild cost is per-session and grows with the rule count, so a per-IE rebuild
turns a routine multi-rule modification into an O(rules x IEs) operation.

**Expected output.** Two passing checks: the accepted modification, and a rebuild count
of exactly one. No warnings.

A count above one adds a warning giving the count alongside the number of removal IEs
that produced it. The ratio between the two is the useful part -- it separates
"rebuilds once per IE" from something multiplying faster than that.

The count is read with the polling variant, because the log lags the process by a few
hundred milliseconds and an immediate read would undercount.
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.models import ModificationSpec
from pfcpkit.pfcp.session import SessionContext
from pfcpkit.scenarios import register

from .base import OaiScenario


@register
class RebuildOnce(OaiScenario):
    """One modification carrying several removals must rebuild the datapath once."""

    name = "rebuild_once"
    description = "A modification with N removals rebuilds the datapath exactly once"
    tags = frozenset({"datapath", "regression"})
    requires = frozenset({Capability.LOG_WINDOW})
    ue_index = 10

    def arrange(self) -> None:
        settings = self.ctx.settings
        self.session: SessionContext = self.establish(
            presets.multi_flow_session(
                settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x1010,
                dl_teid=0x1011,
                extra_ul_teid=0x1012,
                extra_dl_teid=0x1013,
            )
        )

    def act(self) -> None:
        # Remove the whole second flow -- 2 PDRs, 1 FAR, 1 QER, so four removal
        # IEs in one request. The count scales with the number of removal *IEs*
        # whether or not they match anything, so the ids are still derived from the
        # session: otherwise a preset renumbering would leave this quietly counting
        # rebuilds for rules that never existed.
        spec = self.session.spec
        doomed_qer = spec.qer(presets.EXTRA_QER_ID)
        doomed_pdrs = spec.pdrs_for_qer(doomed_qer.qer_id)
        self.delta = ModificationSpec(
            remove_pdr_ids=tuple(p.pdr_id for p in doomed_pdrs),
            remove_far_ids=spec.far_ids_exclusive_to(doomed_pdrs),
            remove_qer_ids=(doomed_qer.qer_id,),
        )
        self.mark = self.logs.mark()
        self.response = self.modify(self.session, self.delta)

    def verify(self) -> None:
        report = self.report
        seid = self.session.require_up_seid()

        report.check(
            "modification accepted",
            self.response.accepted,
            f"cause={self.response.cause} failed_rule={self.response.failed_rule_id}",
        )

        rebuilds = self.logs.stable_pipeline_rebuilds_since(self.mark, seid)
        report.check_count(
            "datapath rebuilt exactly once for the whole modification",
            1,
            rebuilds,
        )
        if rebuilds > 1:
            report.warn(
                f"{rebuilds} rebuilds for {self.delta.removal_count} removal IE(s) -- "
                "the ratio shows whether the datapath is rebuilt once per IE or "
                "something is multiplying faster than that"
            )
