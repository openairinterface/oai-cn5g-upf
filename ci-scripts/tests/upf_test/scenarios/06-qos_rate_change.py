# SPDX-License-Identifier: MIT
"""Change a QER's GBR/MBR and check the new rates are enforced.

**Scenario.** Establish a session whose QER carries GBR 50000 / MBR 100000 kbps,
modify it once so the enforcement state exists, confirm it does, then send a second
Session Modification Request with an Update QER carrying GBR 20000 / MBR 40000 kbps.

**Expected behaviour.** The UPF accepts the modification and the enforced rate and
ceiling become 20000 and 40000 kbps. TS 29.244 Section 5.2.1 makes an Update QER a
directive: the new bitrates replace the old ones for that QoS flow. Enforcement state
for the flow continues to exist -- an update must not tear it down.

**Expected output.** Five passing checks: the precondition that enforcement exists,
the accepted modification, enforcement still present, and rate and ceiling each equal
to the updated value. No warnings.

If the rate and ceiling come back byte-identical to their pre-update values, the
scenario adds a warning saying so. That is a distinct observation from "wrong value":
unchanged means the update was not applied at all, and the PFCP response is an accept
either way, so nothing in the signalling separates "applied" from "silently ignored".
``14-qos_tc_failures.py`` looks at the mechanism behind that.

Two UPF behaviours shape the scenario, both established by inspection:

* enforcement state is created by ``ModifyPipeline`` only, never ``CreatePipeline``,
  so the session must be modified once before any of it exists -- hence the
  modification in ``arrange()``;
* deleted sessions leak their shaping classes, so assertions are scoped to this
  session's own derived class ids rather than counting classes on the interface.
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
class QosRateChange(OaiScenario):
    """An Update QER must change the enforced rate and ceiling."""

    name = "qos_rate_change"
    description = "An Update QER changes the enforced rate and ceiling"
    tags = frozenset({"datapath", "regression", "qos"})
    requires = frozenset({Capability.RULE_STATE, Capability.QOS_STATE})
    ue_index = 14

    def arrange(self) -> None:
        settings = self.ctx.settings
        self.qer = presets.gbr_qer(
            gbr_dl_kbps=_INITIAL[0], mbr_dl_kbps=_INITIAL[1]
        )
        self.session: SessionContext = self.establish(
            presets.basic_ipv4_session(
                settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x1410,
                dl_teid=0x1411,
                qer=self.qer,
            )
        )
        seid = self.session.require_up_seid()

        # First modification: this is what actually creates the HTB classes, since
        # CreatePipeline does not. After it the class exists at the initial rates.
        self.modify(self.session, ModificationSpec(update_qers=(self.qer,)))

        self.qfi = self.qer.qfi
        assert self.qfi is not None
        self.before = self.qos.flow_rate_kbps(seid, self.qfi)
        self.report.require(
            "QoS enforcement exists for the flow before the rate change",
            self.before is not None,
            f"no enforcement state for seid=0x{seid:x} qfi={self.qfi} "
            f"on adapter {self.ctx.adapter}",
        )

    def act(self) -> None:
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
        seid = self.session.require_up_seid()
        assert self.qfi is not None

        report.check("modification accepted", self.response.accepted)

        updated = self.qos.flow_rate_kbps(seid, self.qfi)
        report.check(
            "the QoS flow still has enforcement state after the rate change",
            updated is not None,
            f"enforcement for seid=0x{seid:x} qfi={self.qfi} disappeared",
        )
        if updated is None:
            return

        report.check_eq(
            "enforced rate matches the updated GBR", _UPDATED[0], updated[0]
        )
        report.check_eq(
            "enforced ceil matches the updated MBR", _UPDATED[1], updated[1]
        )

        if updated == self.before:
            report.warn(
                f"rate/ceil unchanged at {self.before} kbps: the update was not "
                "applied at all, rather than applied incorrectly. "
                "`qos_rebuild_tc_failures` examines the mechanism."
            )
