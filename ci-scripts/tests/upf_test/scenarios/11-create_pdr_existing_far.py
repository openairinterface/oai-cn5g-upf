# SPDX-License-Identifier: MIT
"""Create a PDR that references a FAR the session already has.

**Scenario.** Establish a session, then send a Session Modification Request whose only
content is one Create PDR referencing, by ID, a FAR that establishment already
installed. Then send a **control** request: the same shape of PDR, but with a
brand-new Create FAR alongside it.

The FAR and QER ids are resolved from the established session rather than from preset
constants. Rule ids are CP-assigned and session-scoped (TS 29.244 Sections 8.2.74,
8.2.75), so a stale constant would reference a rule that does not exist -- and the
answer to *that* is also a rejection, which would look identical to the behaviour under
test. A wrong QER id is worse still: the UPF logs "No QER associated with PDR" and
carries on, so it would weaken the scenario without failing it.

**Expected behaviour.** The first request is accepted and the new PDR reaches the
datapath. Per TS 29.244 Table 7.5.4.2-1 a Create PDR references its FAR by ID and
needs no accompanying Create FAR -- the FAR already belongs to the session, and
requiring it to be re-sent would make it impossible to attach a new PDR to existing
forwarding. This is the pattern an SMF uses to reconfigure a QoS flow: withdraw a PDR
and create its replacement against the FAR that is already there.

**Expected output.** Six passing checks: two spec preconditions, the accepted
establishment, the first modification accepted, the new PDR present in the rule map,
the control accepted, and the rejection cause not being *mandatory IE missing*. No
warnings.

The control exists to make the result diagnostic rather than merely negative. If the
first request is refused and the control is accepted, the missing Create FAR is
conclusively the cause and the PDR itself is fine; the scenario emits a warning saying
exactly that. If the control fails too, rule creation is broken more broadly and that
reading would be wrong -- which is why it is asserted rather than assumed.
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.models import ModificationSpec
from pfcpkit.pfcp.session import SessionContext
from pfcpkit.pfcp.types import Cause, cause_name
from pfcpkit.scenarios import register

from .base import OaiScenario

_NEW_PDR_ID = 21

_NEW_PDR_WITH_FAR_ID = 22

_NEW_FAR_ID = 23


@register
class CreatePdrExistingFar(OaiScenario):
    """A Create PDR may reference a FAR that already exists in the session."""

    name = "create_pdr_existing_far"
    description = "A Create PDR may reference a FAR the session already has"
    tags = frozenset({"datapath", "regression"})
    requires = frozenset({Capability.RULE_STATE})
    ue_index = 18

    def arrange(self) -> None:
        settings = self.ctx.settings
        self.session: SessionContext = self.establish(
            presets.basic_ipv4_session(
                settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x1810,
                dl_teid=0x1811,
                qer=presets.gbr_qer(),
            )
        )
        self.seid = self.session.require_up_seid()

        # Resolve the FAR to reference from the session that was actually
        # established, rather than from a shared preset constant. Rule ids are
        # CP-assigned (TS 29.244 Section 8.2.74) and session-scoped, so this FAR
        # exists only because establishment declared it -- and if the presets ever
        # renumber, referencing a FAR that does not exist would be answered with a
        # rejection indistinguishable from the behaviour under test. Resolving
        # through the spec turns that into an immediate, obvious error instead.
        downlink = self.session.spec.downlink_pdrs()
        self.report.require(
            "the established session has a downlink PDR to borrow a FAR from",
            bool(downlink),
            "presets.basic_ipv4_session produced no Core-side PDR",
        )
        self.existing_far_id = downlink[0].far_id
        existing_far = self.session.spec.far(self.existing_far_id)
        self.report.require(
            "that FAR really is part of the established session",
            existing_far.far_id == self.existing_far_id,
            f"FAR {self.existing_far_id} is referenced by a PDR but absent from "
            "the session spec",
        )

        # The new PDR also references a QER, which must likewise be one the session
        # already has. A wrong id here would not be rejected -- the UPF just logs
        # "No QER associated with PDR" and carries on -- so it would silently
        # weaken the scenario rather than fail it.
        self.existing_qer = self.session.spec.qer(presets.DEFAULT_QER_ID)

    def act(self) -> None:
        # A downlink PDR pointing at a FAR the session already has. Nothing else in
        # the request: per TS 29.244 Table 7.5.4.2-1 a Create PDR references its FAR
        # by ID (Section 8.2.74) and needs no accompanying Create FAR.
        self.without_far = self.modify(
            self.session,
            ModificationSpec(
                create_pdrs=(
                    presets.downlink_pdr(
                        _NEW_PDR_ID,
                        self.existing_far_id,
                        ue_ipv4=self.session.ue_ipv4,
                        qer_id=self.existing_qer.qer_id,
                        qfi=self.existing_qer.qfi,
                        precedence=200,
                    ),
                ),
            ),
        )

        # Control: the same shape, but creating a brand-new FAR alongside. If this
        # is accepted while the request above is not, the missing Create FAR is
        # conclusively the cause rather than anything about the PDR itself.
        self.with_far = self.modify(
            self.session,
            ModificationSpec(
                create_fars=(presets.uplink_far(_NEW_FAR_ID),),
                create_pdrs=(
                    presets.downlink_pdr(
                        _NEW_PDR_WITH_FAR_ID,
                        _NEW_FAR_ID,
                        ue_ipv4=self.session.ue_ipv4,
                        precedence=201,
                    ),
                ),
            ),
        )

    def verify(self) -> None:
        report = self.report

        report.check(
            "a Create PDR referencing an existing FAR is accepted",
            self.without_far.accepted,
            f"referenced FAR {self.existing_far_id} was established with this "
            f"session; cause={cause_name(self.without_far.cause)}",
        )

        installed = self.rules.installed_pdr_ids(self.seid)
        report.check_in(
            f"PDR {_NEW_PDR_ID} reached rules_match_pdr_map", _NEW_PDR_ID, installed
        )

        # The control should pass either way. If it does not, rule creation is
        # broken more broadly and the diagnosis below would be wrong.
        report.check(
            "the same PDR is accepted when a Create FAR accompanies it",
            self.with_far.accepted,
            f"cause={cause_name(self.with_far.cause)} -- the control failed too, so "
            "rule creation is broken more broadly than a missing Create FAR",
        )

        if not self.without_far.accepted and self.with_far.accepted:
            report.warn(
                "rejected without a Create FAR but accepted with one: the missing "
                "Create FAR is the cause, and the PDR itself is well-formed"
            )

        if self.without_far.cause is not None:
            report.check_eq(
                "the rejection is not 'mandatory IE missing'",
                False,
                self.without_far.cause == Cause.MANDATORY_IE_MISSING,
            )
