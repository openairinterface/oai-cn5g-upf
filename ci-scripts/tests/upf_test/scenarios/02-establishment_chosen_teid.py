# SPDX-License-Identifier: MIT
"""Establish a session with CH=1, letting the UPF choose the uplink F-TEID.

**Scenario.** Take the same session as ``01-establishment.py`` and replace the uplink
PDR's explicit F-TEID with the CH ("choose") bit set, asking the UPF to allocate one.
The uplink PDR is selected by source interface rather than by position, so a preset
reordering cannot leave the CH bit on a PDR that never carried an F-TEID.

**Expected behaviour.** The UPF accepts the request, allocates an uplink F-TEID
itself, and returns it in a Created PDR IE for that PDR -- here the IE is mandatory
rather than optional (TS 29.244 Section 7.5.3.2), because the UP function chose the
value. The reported TEID is non-zero and is not the placeholder the request carried,
since a session whose uplink TEID is zero has no usable tunnel endpoint.

**Expected output.** Five passing checks: the spec precondition, the accepted
response, the Created PDR IE being present for the CH=1 PDR, and the allocated TEID
being both non-zero and not an echo. No warnings.

Separate from ``01-establishment.py`` because CH=1 is a different code path in the
UPF: allocation from a monotonic, never-released counter rather than acceptance of a
supplied value.
"""

from __future__ import annotations

from dataclasses import replace

from pfcpkit import presets
from pfcpkit.models import FTeid
from pfcpkit.scenarios import register

from .base import OaiScenario


@register
class SessionEstablishmentChosenTeid(OaiScenario):
    """Establish a session asking the UPF to choose the uplink F-TEID (CH=1)."""

    name = "establishment_chosen_teid"
    description = "Establish a session with CH=1, letting the UPF allocate the F-TEID"
    tags = frozenset({"smoke", "fteid"})
    ue_index = 1

    def act(self) -> None:
        base = presets.basic_ipv4_session(self.ctx.settings, qer=presets.gbr_qer())

        # Swap the uplink PDR's explicit F-TEID for a "you choose" request. Select
        # it by source interface rather than by position: `base.pdrs[0]` happens to
        # be the Access-side rule today, but nothing guarantees that ordering, and
        # setting CH=1 on the downlink PDR instead would make this scenario assert
        # against a rule that never had an F-TEID.
        uplink = base.uplink_pdrs()
        self.report.require(
            "the session spec has an uplink PDR to set CH=1 on",
            bool(uplink),
            "presets.basic_ipv4_session produced no Access-side PDR",
        )
        self.chosen_pdr_id = uplink[0].pdr_id
        self.spec = replace(
            base,
            pdrs=tuple(
                replace(pdr, f_teid=FTeid(choose=True))
                if pdr.pdr_id == self.chosen_pdr_id
                else pdr
                for pdr in base.pdrs
            ),
        )
        self.session = self.establish(self.spec)

    def verify(self) -> None:
        r = self.report
        session = self.session
        pdr_id = self.chosen_pdr_id

        r.check(
            "UPF reported a Created PDR for the CH=1 uplink PDR",
            pdr_id in session.reported_teids,
            f"reported_teids={session.reported_teids}",
        )
        teid = session.reported_teids.get(pdr_id)
        r.check("the allocated F-TEID is non-zero", bool(teid), f"got {teid!r}")
        # CH=1 means the UPF picked the value, so it must not be the placeholder
        # zero we sent -- otherwise the uplink has no usable tunnel endpoint.
        r.check(
            "the allocated F-TEID was chosen by the UPF, not echoed",
            teid not in (None, 0),
            f"got {teid!r}",
        )
