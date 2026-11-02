# SPDX-License-Identifier: MIT
"""Establish a session with a QER and check the UPF recorded that it has one.

**Scenario.** Establish a session carrying a GBR/MBR QER and send no modification, then
read the per-session rules-enabled bitmask and check the QER bit is set.

**Expected behaviour.** A session established with a QER is recorded as having one, from
establishment onwards. This is a narrower question than whether the QoS state was
*installed*: it asks only whether the UPF registered the rule's existence.

**Expected output.** Three passing checks: the accepted establishment, an entry present
for the session, and the QER bit set within it. No warnings.

The entry check polls up to ``SETTLE_TIMEOUT`` rather than reading once, so a slow UPF
is not reported as a broken one.

Paired with ``07-qos_at_establishment.py``, which asks whether the enforcement state
itself was installed. Read together the two localise where establishment stops short:
this scenario passing while that one fails says the UPF registered the QER and did not
act on it, which is a different problem from not having seen it. Asserted rather than
merely noted, because if this one ever starts failing too, that reading no longer holds.
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.pfcp.session import SessionContext
from pfcpkit.scenarios import register
from pfcpkit.waiting import wait_until

from .base import OaiScenario

_INITIAL = (50_000, 100_000)


@register
class QerFlagAtEstablishment(OaiScenario):
    """Establishment must record the session's QER in the rules-enabled bitmask."""

    name = "qer_flag_at_establishment"
    description = "Establishment alone sets the QER bit in session_rules_enabled_map"
    tags = frozenset({"datapath", "qos"})
    requires = frozenset({Capability.RULE_STATE})
    ue_index = 22

    def act(self) -> None:
        self.qer = presets.gbr_qer(gbr_dl_kbps=_INITIAL[0], mbr_dl_kbps=_INITIAL[1])
        # Deliberately no modification: the point is what establishment alone does.
        self.session: SessionContext = self.establish(
            presets.basic_ipv4_session(
                self.ctx.settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x1610,
                dl_teid=0x1611,
                qer=self.qer,
            )
        )

    def verify(self) -> None:
        report = self.report
        seid = self.session.require_up_seid()

        # Poll rather than read once, so a UPF that is merely slow is not reported
        # as one that never wrote the entry.
        present = wait_until(
            lambda: self.rules.rules_enabled(seid) is not None,
            timeout=self.ctx.settings.settle_timeout,
        )
        report.check(
            "session_rules_enabled_map holds an entry after establishment",
            present,
            f"no entry for seid=0x{seid:x}",
        )

        flags = self.rules.rules_enabled(seid)
        report.check(
            "the entry records that QER is enabled",
            flags is not None and bool(flags & 0x1),
            f"rules_enabled={None if flags is None else hex(flags)} "
            f"({self.rules.describe_rules_enabled(seid)})",
        )
