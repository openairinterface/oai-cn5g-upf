# SPDX-License-Identifier: MIT
"""Remove one QER from a two-flow session and check only its enforcement goes.

**Scenario.** Establish a session with two QoS flows, modify it once so both flows'
enforcement state exists, confirm both are present, then send a Session Modification
Request whose only content is a Remove QER for the second flow. The session and its
first flow stay up throughout.

The QER id is resolved from the established session in ``arrange()`` -- ``spec.qer()``
raises if it is absent -- so the request cannot silently remove a QER the session
never had, which would make the "it is gone" check pass vacuously.

**Expected behaviour.** The UPF accepts the modification, releases the enforcement
state belonging to the removed QER, and leaves the surviving flow's state untouched.
Both halves matter: over-removal would break a flow the CP never mentioned, and
under-removal leaves enforcement attached to a QER that no longer exists.

**Expected output.** Three passing checks: the accepted modification, the removed
QER's enforcement gone, and the surviving QER's enforcement still present. No
warnings.

Distinct from ``09-qos_class_cleanup.py``, where the whole session is deleted. Here
the session continues, and removal-during-modification is a different code path from
release-on-deletion. This case also has a consequence deletion does not: the stale
state keeps a class id derived from (SEID, QFI), so re-adding that QFI to the same
session later collides with what was left behind.
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.models import ModificationSpec
from pfcpkit.scenarios import register

from .base import OaiScenario


@register
class QerRemovalPrunesClass(OaiScenario):
    """Removing a QER must remove the enforcement state it created."""

    name = "qer_removal_prunes_class"
    description = "Removing a QER releases its enforcement, and only its own"
    tags = frozenset({"datapath", "regression", "qos"})
    requires = frozenset({Capability.RULE_STATE, Capability.QOS_STATE})
    ue_index = 17

    def arrange(self) -> None:
        settings = self.ctx.settings
        self.session = self.establish(
            presets.multi_flow_session(
                settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x1440,
                dl_teid=0x1441,
                extra_ul_teid=0x1442,
                extra_dl_teid=0x1443,
            )
        )
        self.seid = self.session.require_up_seid()

        self.kept_qer = self.session.spec.qer(presets.DEFAULT_QER_ID)
        self.doomed_qer = self.session.spec.qer(presets.EXTRA_QER_ID)
        assert self.doomed_qer.qfi is not None
        assert self.kept_qer.qfi is not None

        # Enforcement state is only created on modification, so make one first --
        # otherwise there is nothing for the removal to have removed.
        self.modify(self.session, ModificationSpec(update_qers=(self.kept_qer,)))
        self.report.require(
            "both QoS flows have HTB classes before the removal",
            all(
                self.qos.flow_exists(self.seid, qfi)
                for qfi in (self.kept_qer.qfi, self.doomed_qer.qfi)
            ),
            "expected a class for each of the session's two QFIs",
        )

    def act(self) -> None:
        self.response = self.modify(
            self.session,
            # The QER id comes from the session spec (resolved in arrange, which
            # raises if it is absent) rather than the constant, so this cannot
            # silently remove a QER the session never had.
            ModificationSpec(remove_qer_ids=(self.doomed_qer.qer_id,)),
        )

    def verify(self) -> None:
        report = self.report
        doomed_qfi = self.doomed_qer.qfi
        kept_qfi = self.kept_qer.qfi
        assert doomed_qfi is not None
        assert kept_qfi is not None

        report.check("modification accepted", self.response.accepted)

        stale = self.qos.flow_exists(self.seid, doomed_qfi)
        report.check(
            "the removed QER's enforcement state is gone",
            not stale,
            f"enforcement for QFI {doomed_qfi} survives its QER",
        )
        report.check(
            "the surviving QER keeps its enforcement state",
            self.qos.flow_exists(self.seid, kept_qfi),
            f"enforcement for QFI {kept_qfi} was removed with the other flow",
        )
