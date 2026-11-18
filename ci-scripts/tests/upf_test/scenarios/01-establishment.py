# SPDX-License-Identifier: MIT
"""Establish an IPv4 session with one dedicated QoS flow.

**Scenario.** Send one Session Establishment Request for an IPv4 PDU session: two
PDRs (uplink and downlink), two FARs, and one QER carrying GBR and MBR. The uplink
PDR supplies an explicit F-TEID rather than asking the UPF to choose one.

**Expected behaviour.** The UPF accepts the request, allocates a UP F-SEID and
returns it in an F-SEID IE. Where a Created PDR IE reports an F-TEID for a PDR that
supplied its own, the reported value equals the one requested -- returning a
different TEID would silently break the uplink.

TS 29.244 Section 7.5.3.2 asks for the Created PDR IE only where the UP function
allocated the F-TEID itself, so a UPF that omits it for an explicit (CH=0) F-TEID is
equally correct; the scenario accepts either, and only insists that any value it does
report is faithful.

**Expected output.** Five passing checks: the spec precondition, the accepted
response, the allocated F-SEID, the active session, and the F-TEID echo. No
warnings.

The whole scenario asserts only on what PFCP itself reveals -- the Cause IE, the
F-SEID, Created PDR F-TEIDs -- so it needs no datapath capability and stands as the
suite's smoke test: it exercises the association, the encoder, the transport and the
UPF's N4 handler end to end. Everything downstream depends on those, so a failure
here makes later results not worth reading.
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.models import SessionSpec
from pfcpkit.pfcp.session import SessionContext
from pfcpkit.scenarios import register

from .base import OaiScenario


@register
class SessionEstablishment(OaiScenario):
    """Establish a single IPv4 session carrying one dedicated QoS flow."""

    name = "establishment"
    description = "Establish an IPv4 session with a GBR/MBR QoS flow"
    tags = frozenset({"smoke"})
    ue_index = 0

    #: Explicit uplink F-TEID, distinctive so the echo can be checked against it.
    UL_TEID = 0x0A01

    def act(self) -> None:
        self.spec: SessionSpec = presets.basic_ipv4_session(
            self.ctx.settings, ul_teid=self.UL_TEID, qer=presets.gbr_qer()
        )
        # Resolve the uplink PDR from the spec rather than assuming its id, so a
        # preset renumbering cannot make the echo check look at the wrong rule.
        uplink = self.spec.uplink_pdrs()
        self.report.require(
            "the session spec has an uplink PDR carrying the explicit F-TEID",
            bool(uplink),
            "presets.basic_ipv4_session produced no Access-side PDR",
        )
        self.uplink_pdr_id = uplink[0].pdr_id
        self.session: SessionContext = self.establish(self.spec)

    def verify(self) -> None:
        r = self.report
        session = self.session

        r.check(
            "UPF allocated a UP F-SEID",
            session.up_seid is not None,
            "the response carried no F-SEID IE",
        )
        r.check(
            "session is tracked as active",
            session.active,
            session.describe(),
        )
        # Either shape is conformant, so branch rather than assert one of them:
        # this UPF reports a Created PDR for every PDR carrying an F-TEID,
        # including CH=0 where it allocated nothing, while a UPF that omits the IE
        # for an explicit F-TEID also satisfies TS 29.244 Section 7.5.3.2. What
        # neither may do is report a *different* TEID than requested.
        echoed = session.reported_teids.get(self.uplink_pdr_id)
        if echoed is None:
            r.check(
                "no Created PDR F-TEID reported for an explicit (CH=0) F-TEID",
                not session.reported_teids,
                f"reported_teids={session.reported_teids}",
            )
        else:
            r.check_eq(
                "the echoed F-TEID matches the one requested", self.UL_TEID, echoed
            )
