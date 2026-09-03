# SPDX-License-Identifier: MIT
"""Send a modification with no removals at all and count the datapath rebuilds.

**Scenario.** Establish a single-flow session, then send one Session Modification
Request whose only content is an Update QER changing the bitrates. No Remove IEs of any
kind.

**Expected behaviour.** One rebuild, for the same reason as ``12-rebuild_once.py``: a
Session Modification Request is one instruction, applied once.

**Expected output.** Two passing checks: the accepted modification, and a rebuild count
of exactly one. No warnings.

The narrower companion to ``12-rebuild_once.py``, and the more diagnostic of the two.
With zero removal IEs there is nothing for any per-removal work to fire on, so a count
above one localises the extra rebuild to the update path itself rather than to the
handling of removals.
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.models import ModificationSpec
from pfcpkit.scenarios import register

from .base import OaiScenario


@register
class RebuildOnceForUpdateOnly(OaiScenario):
    """A modification with no removals at all must still rebuild only once."""

    name = "rebuild_once_update_only"
    description = "An update-only modification rebuilds the datapath exactly once"
    tags = frozenset({"datapath", "regression"})
    requires = frozenset({Capability.LOG_WINDOW})
    ue_index = 11

    def arrange(self) -> None:
        settings = self.ctx.settings
        self.qer = presets.gbr_qer(gbr_dl_kbps=50_000, mbr_dl_kbps=100_000)
        self.session = self.establish(
            presets.basic_ipv4_session(
                settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x1020,
                dl_teid=0x1021,
                qer=self.qer,
            )
        )

    def act(self) -> None:
        self.mark = self.logs.mark()
        self.response = self.modify(
            self.session,
            ModificationSpec(
                update_qers=(
                    self.qer.with_bitrates(gbr_dl_kbps=30_000, mbr_dl_kbps=60_000),
                ),
            ),
        )

    def verify(self) -> None:
        report = self.report
        seid = self.session.require_up_seid()

        report.check("modification accepted", self.response.accepted)
        report.check_count(
            "update-only modification rebuilt the datapath once",
            1,
            self.logs.stable_pipeline_rebuilds_since(self.mark, seid),
        )
