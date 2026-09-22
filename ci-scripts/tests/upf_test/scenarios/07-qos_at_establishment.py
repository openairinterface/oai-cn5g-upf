# SPDX-License-Identifier: MIT
"""Establish a session carrying a QER and check its QoS state is installed at once.

**Scenario.** Establish a session whose QER carries GBR and MBR, and send **no
modification at all** -- that omission is the whole point. Then poll for the QoS
enforcement state and the traffic-classification entry for the QER's QFI.

**Expected behaviour.** A QER present in a Session Establishment Request applies from
the moment the session exists. TS 29.244 Section 5.2.1 attaches no precondition about
a later modification, and an SMF is not obliged to send one, so the enforcement state
and the SDF filter for the QFI should both be in place after establishment alone.

**Expected output.** Three passing checks: the accepted establishment, enforcement
state present for the flow, and the SDF filter installed for its QFI. No warnings.

Both state checks poll up to ``SETTLE_TIMEOUT`` before concluding. Asserting absence
immediately would be indistinguishable from asserting it too early, which would make
this scenario report a defect whenever the UPF was merely slower than the test.

``15-qer_flag_at_establishment.py`` is the complement: it asks whether the UPF
*recorded* the QER, which narrows down where the state stops being written.
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.scenarios import register
from pfcpkit.waiting import wait_until

from .base import OaiScenario

_INITIAL = (50_000, 100_000)


@register
class QosAtEstablishment(OaiScenario):
    """Establishing a session with a QER must install its QoS enforcement."""

    name = "qos_at_establishment"
    description = "Establishment alone installs a QER's enforcement and classification"
    tags = frozenset({"datapath", "regression", "qos"})
    requires = frozenset({Capability.RULE_STATE, Capability.QOS_STATE})
    ue_index = 16

    def act(self) -> None:
        settings = self.ctx.settings
        self.qer = presets.gbr_qer(gbr_dl_kbps=_INITIAL[0], mbr_dl_kbps=_INITIAL[1])
        # Deliberately no modification anywhere in this scenario.
        self.session = self.establish(
            presets.basic_ipv4_session(
                settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x1430,
                dl_teid=0x1431,
                qer=self.qer,
            )
        )

    def verify(self) -> None:
        report = self.report
        seid = self.session.require_up_seid()
        qfi = self.qer.qfi
        assert qfi is not None
        settle = self.ctx.settings.settle_timeout

        # Poll rather than read once: asserting absence immediately would be
        # indistinguishable from asserting it too early, and would report a defect
        # whenever the UPF was merely slower than this test.
        appeared = wait_until(
            lambda: self.qos.flow_exists(seid, qfi),
            timeout=settle,
        )
        report.check(
            "an HTB class exists for the QoS flow after establishment alone",
            appeared,
            f"no enforcement state for seid=0x{seid:x} qfi={qfi} appeared within "
            f"{settle:.1f}s of establishment",
        )

        sdf_present = wait_until(
            lambda: qfi in self.rules.installed_qfis(seid), timeout=settle
        )
        report.check(
            "the SDF filter is installed after establishment alone",
            sdf_present,
            f"sdf_filters_map holds {self.rules.installed_qfis(seid)} for "
            f"seid=0x{seid:x}",
        )
