# SPDX-License-Identifier: MIT
"""Re-establish an existing CP F-SEID and expect a rejection.

**Scenario.** Establish a session, then send a second Session Establishment Request
carrying the same CP F-SEID. The second request goes out through the raw send rather
than the usual helper, so a rejection is data to assert on rather than an aborted
scenario.

**Expected behaviour.** The UPF recognises the F-SEID as one it already holds and
rejects the duplicate with cause *Request rejected* (TS 29.244 Section 8.2.1). It
does not create a second session, and does not disturb the first.

**Expected output.** Three passing checks: the first establishment accepted, the
duplicate not accepted, and the cause being exactly ``REQUEST_REJECTED`` rather than
some other refusal. No warnings.

The suite's one negative case, which makes it useful beyond its own subject: it is
the evidence that a "rejected" verdict is something this harness observes and reports
rather than silently passes over.
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.pfcp.types import Cause, cause_name
from pfcpkit.scenarios import register

from .base import OaiScenario


@register
class SessionEstablishmentRejectsDuplicate(OaiScenario):
    """A second establishment reusing the same CP F-SEID must be rejected."""

    name = "establishment_duplicate"
    description = "Re-establishing an existing CP F-SEID is rejected"
    tags = frozenset({"negative"})
    ue_index = 2

    def arrange(self) -> None:
        self.spec = presets.basic_ipv4_session(self.ctx.settings)
        self.session = self.establish(self.spec)

    def act(self) -> None:
        # Re-send establishment for a SEID the UPF already knows. Uses the raw
        # send so a rejection is data to assert on, not an aborted scenario.
        self.duplicate = self.ctx.client.send_establishment(
            self.spec, self.session.cp_seid
        )

    def verify(self) -> None:
        r = self.report
        r.check(
            "duplicate establishment was not accepted",
            not self.duplicate.accepted,
            f"cause={cause_name(self.duplicate.cause)}",
        )
        r.check_eq(
            "cause is 'Request rejected'",
            Cause.REQUEST_REJECTED,
            self.duplicate.cause,
        )
