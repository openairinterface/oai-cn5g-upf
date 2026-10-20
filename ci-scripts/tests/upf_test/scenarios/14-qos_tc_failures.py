# SPDX-License-Identifier: MIT
"""Apply a QER rate change and check the UPF logged no failed ``tc`` operation.

**Scenario.** Establish a session with a GBR/MBR QER and modify it once, so the shaping
classes exist and the *second* setup has something to collide with. Open a log window
only after that first modification -- its own ``tc`` operations are expected to succeed
and would otherwise be counted. Then send an Update QER with new bitrates and read the
window.

**Expected behaviour.** Applying new bitrates to an existing QoS flow completes without
any ``tc`` operation failing. Whether the UPF updates the class in place or replaces it,
either is fine; what a correct implementation cannot do is attempt an operation that
fails and continue as though it had not.

**Expected output.** Two passing checks -- the precondition that enforcement exists,
and zero failed ``tc`` operations -- plus one informational warning giving the number
of QoS setups the modification triggered. That count is reported rather than asserted:
one setup per modification is correct, and the number alone does not separate correct
from redundant.

Each failed operation found is also warned individually, truncated to its last 120
characters, so the specific failure is visible without dumping the log.

The outcome-level companion to ``06-qos_rate_change.py``, which asks whether the rate
actually changed. Separating them matters because the PFCP response is an accept in
either case: without the log there is nothing to distinguish "the UPF applied the new
rate" from "the UPF failed to and said nothing".
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.models import ModificationSpec
from pfcpkit.pfcp.session import SessionContext
from pfcpkit.scenarios import register

from .base import OaiScenario

_INITIAL = (50_000, 100_000)

_UPDATED = (20_000, 40_000)


@register
class QosRebuildTcFailures(OaiScenario):
    """Re-applying a QER must not leave failed ``tc`` operations in the log."""

    name = "qos_rebuild_tc_failures"
    description = "A QER rate change applies without a failed tc operation"
    tags = frozenset({"datapath", "regression", "qos"})
    requires = frozenset({Capability.QOS_STATE, Capability.LOG_WINDOW})
    ue_index = 21

    def arrange(self) -> None:
        self.qer = presets.gbr_qer(gbr_dl_kbps=_INITIAL[0], mbr_dl_kbps=_INITIAL[1])
        self.session: SessionContext = self.establish(
            presets.basic_ipv4_session(
                self.ctx.settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x1510,
                dl_teid=0x1511,
                qer=self.qer,
            )
        )

        # The first modification is what creates the classes at all -- none exist
        # after establishment. Its own tc operations are expected to succeed, so the
        # log window opens *after* it rather than around it.
        self.modify(self.session, ModificationSpec(update_qers=(self.qer,)))

        seid = self.session.require_up_seid()
        assert self.qer.qfi is not None
        self.report.require(
            "QoS enforcement exists for the flow before the rate change",
            self.qos.flow_exists(seid, self.qer.qfi),
            f"no enforcement state for seid=0x{seid:x} qfi={self.qer.qfi}; without "
            "it the second setup has nothing to collide with and this scenario "
            "proves nothing",
        )

    def act(self) -> None:
        self.mark = self.logs.mark()
        self.response = self.modify(
            self.session,
            ModificationSpec(
                update_qers=(
                    self.qer.with_bitrates(
                        gbr_dl_kbps=_UPDATED[0], mbr_dl_kbps=_UPDATED[1]
                    ),
                ),
            ),
        )

    def verify(self) -> None:
        report = self.report
        report.check("modification accepted", self.response.accepted)

        failures = self.logs.tc_failures_since(self.mark)
        report.check_count(
            "no tc operation failed while applying the new rate", 0, len(failures)
        )
        for line in failures[:3]:
            report.warn(f"tc: {line.strip()[-120:]}")

        # Reported rather than asserted: one setup per modification is correct, and
        # the count alone does not distinguish correct from redundant.
        report.warn(
            f"QoS setups during the rate change: "
            f"{self.logs.qos_setups_since(self.mark)}"
        )
