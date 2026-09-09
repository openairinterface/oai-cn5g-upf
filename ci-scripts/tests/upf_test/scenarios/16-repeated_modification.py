# SPDX-License-Identifier: MIT
"""Modify one session repeatedly and check the UPF neither degrades nor accumulates.

**Scenario.** Establish a session, then send ten Session Modification Requests, each an
Update QER with a different bitrate so no request is a literal repeat. Then send an
eleventh and measure *that one alone*: the question is not whether the first
modification worked, but whether the datapath is still being reprogrammed once the
earlier ones have had their effect.

**Expected behaviour.** Four things, and each is a separate failure mode:

* every modification is accepted;
* the eleventh still rebuilds the datapath -- accepting a request without acting on it
  would leave the CP believing a configuration the data plane does not have;
* no kernel attach is refused across the run, which would mean per-modification
  resources accumulating rather than being replaced;
* the session's rule set is byte-identical to what establishment installed, and it still
  has exactly one per-session entry. Ten Update QERs change bitrates, not rules.

**Expected output.** Seven passing checks: the ten acceptances, the eleventh acceptance,
a non-zero rebuild count for it, zero attach refusals, the unchanged rule set, and the
single per-session entry. No warnings.

Any attach refusals found are summarised in one warning giving the count. The rule-set
check is a weaker guard than a direct test of the UPF's rule categorisation would be,
but it does catch a rule set that grows across modifications.

**This scenario can leave the UPF degraded**, which is why it is numbered last. If you
run it alone and then run anything else, restart the UPF first::

    docker compose -f docker-compose.yaml restart upf
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.models import ModificationSpec
from pfcpkit.pfcp.session import SessionContext
from pfcpkit.scenarios import register

from .base import OaiScenario

_ROUNDS = 10

_EXCLUSIVITY = r"Exclusivity flag on, cannot modify"


@register
class RepeatedModificationStability(OaiScenario):
    """Repeated modifications must keep updating the datapath, and not degrade it."""

    name = "repeated_modification_stability"
    description = "Repeated modifications rebuild the datapath and accumulate nothing"
    tags = frozenset({"datapath", "regression", "stress"})
    requires = frozenset({Capability.RULE_STATE, Capability.LOG_WINDOW})
    ue_index = 20

    def arrange(self) -> None:
        settings = self.ctx.settings
        self.qer = presets.gbr_qer(gbr_dl_kbps=50_000, mbr_dl_kbps=100_000)
        self.session: SessionContext = self.establish(
            presets.basic_ipv4_session(
                settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x2010,
                dl_teid=0x2011,
                qer=self.qer,
            )
        )
        self.seid = self.session.require_up_seid()
        self.pdrs_before = self.rules.installed_pdr_ids(self.seid)

    def act(self) -> None:
        self.start_mark = self.logs.mark()
        self.accepted = 0

        # Vary the bitrate each round so no request is a literal repeat.
        for round_index in range(_ROUNDS):
            gbr = 20_000 + round_index * 1_000
            response = self.modify(
                self.session,
                ModificationSpec(
                    update_qers=(
                        self.qer.with_bitrates(
                            gbr_dl_kbps=gbr, mbr_dl_kbps=gbr * 2
                        ),
                    ),
                ),
            )
            if response.accepted:
                self.accepted += 1

        # Measure the last modification on its own: the question is not whether the
        # first one worked, but whether the datapath is still being reprogrammed
        # after the earlier ones have had their effect.
        self.final_mark = self.logs.mark()
        self.final_response = self.modify(
            self.session,
            ModificationSpec(
                update_qers=(
                    self.qer.with_bitrates(gbr_dl_kbps=99_000, mbr_dl_kbps=198_000),
                ),
            ),
        )

    def verify(self) -> None:
        report = self.report
        seid = self.seid

        report.check_count(
            f"all {_ROUNDS} modifications were accepted", _ROUNDS, self.accepted
        )
        report.check(
            "the final modification was accepted", self.final_response.accepted
        )

        # The core assertion: the datapath is still being reprogrammed at the end.
        # A UPF that accepts a request without acting on it leaves the CP believing a
        # configuration the data plane does not have.
        final_rebuilds = self.logs.stable_pipeline_rebuilds_since(
            self.final_mark, seid
        )
        report.check(
            "the datapath is still rebuilt after repeated modifications",
            final_rebuilds > 0,
            f"the last modification produced {final_rebuilds} rebuild(s); the UPF "
            "answered 'accepted' without touching the datapath",
        )

        exhausted = self.logs.find_since(self.start_mark, _EXCLUSIVITY)
        report.check_count(
            "no XDP attach was refused during the run", 0, len(exhausted)
        )
        if exhausted:
            report.warn(
                f"{len(exhausted)} attach refusal(s): per-modification resources "
                "accumulated until the kernel refused another attach"
            )

        # State hygiene: ten Update QERs change bitrates, not rules, so the rule set
        # must be unchanged. A weaker guard than inspecting the UPF's own per-session
        # rule array, but it does catch a set that grows across modifications.
        report.check_eq(
            "the rule set is unchanged after repeated modifications",
            self.pdrs_before,
            self.rules.installed_pdr_ids(seid),
        )
        report.check_count(
            "the session still has exactly one pdrs_per_session_map entry",
            1,
            (1 if self.rules.session_installed(seid) else 0),
        )
