# SPDX-License-Identifier: MIT
"""Delete a session and check its shaping state is released.

**Scenario.** Establish a session with a GBR/MBR QER, modify it once so the shaping
state exists, confirm it does, then send a Session Deletion Request.

**Expected behaviour.** Deletion releases the session's resources (TS 29.244
Section 5.2.2), which here means both the per-flow enforcement state and the
per-session shaping parent. The **shared shaping root** must survive: it is created
once per interface and used by every session, so deleting it would break every other
session on that interface.

**Expected output.** Five passing checks: the precondition that shaping state existed,
the accepted deletion, per-flow enforcement gone, the per-session shaper gone, and the
shared root still present. No warnings.

The shared root is asserted separately, and positively, for that reason -- a scenario
that merely counted what remained on the interface could not tell "the session's state
was released" from "the interface was stripped".
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.models import ModificationSpec
from pfcpkit.scenarios import register

from .base import OaiScenario

_INITIAL = (50_000, 100_000)


@register
class QosClassRemovedOnDeletion(OaiScenario):
    """Deleting a session must release the shaping state it created."""

    name = "qos_class_cleanup"
    description = "Session deletion releases its shaping state, but not the shared root"
    tags = frozenset({"datapath", "regression", "qos"})
    requires = frozenset({Capability.RULE_STATE, Capability.QOS_STATE})
    ue_index = 15

    def arrange(self) -> None:
        settings = self.ctx.settings
        self.qer = presets.gbr_qer(gbr_dl_kbps=_INITIAL[0], mbr_dl_kbps=_INITIAL[1])
        self.session = self.establish(
            presets.basic_ipv4_session(
                settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x1420,
                dl_teid=0x1421,
                qer=self.qer,
            )
        )
        self.seid = self.session.require_up_seid()
        self.qfi = self.qer.qfi
        assert self.qfi is not None

        # Again: shaping state only comes into existence on modification.
        self.modify(self.session, ModificationSpec(update_qers=(self.qer,)))
        self.report.require(
            "an HTB class exists before deletion",
            self.qos.flow_exists(self.seid, self.qfi),
            "no class was created, so deletion cannot be shown to remove it",
        )

    def act(self) -> None:
        self.response = self.delete(self.session)

    def verify(self) -> None:
        report = self.report
        assert self.qfi is not None

        report.check(
            "deletion accepted",
            self.response is not None and self.response.accepted,
        )

        report.check(
            "the QoS-flow enforcement state is gone after deletion",
            not self.qos.flow_exists(self.seid, self.qfi),
            f"enforcement for seid=0x{self.seid:x} qfi={self.qfi} survives",
        )

        report.check(
            "the per-session shaper is gone after deletion",
            not self.qos.session_shaper_exists(self.seid),
            f"per-session shaper for seid=0x{self.seid:x} survives",
        )

        # Shared across every session on the interface, so it must survive:
        # removing it would break sessions this one knows nothing about.
        report.check(
            "the shared shaping root survives deletion",
            self.qos.shaper_root_exists(),
        )
