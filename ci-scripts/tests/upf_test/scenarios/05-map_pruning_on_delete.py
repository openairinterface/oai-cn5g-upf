# SPDX-License-Identifier: MIT
"""Delete a session and check nothing of it remains in the rule maps.

**Scenario.** Establish a single-flow session, modify it once so the classification
state is written (this UPF populates ``sdf_filters_map`` in ``ModifyPipeline`` only),
confirm rule state exists, then send a Session Deletion Request. The deletion happens
in ``act()`` rather than being left to teardown, because what it leaves behind is the
subject.

**Expected behaviour.** The UPF accepts the deletion and releases every piece of
per-session state: no ``rules_match_pdr_map`` entries, no ``sdf_filters_map`` entries,
and no ``pdrs_per_session_map`` entry for that SEID. TS 29.244 Section 5.2.2 treats
deletion as releasing the session's resources, so state surviving it belongs to a
session that no longer exists.

**Expected output.** Five passing checks: the precondition that rule state existed,
the accepted deletion, and zero remaining entries in each of the three maps. No
warnings.

Kept separate from ``04-map_pruning.py`` because removal-during-modification and
release-on-deletion are different code paths in the UPF, and either could work while
the other does not.
"""

from __future__ import annotations

from pfcpkit import presets
from pfcpkit.capabilities import Capability
from pfcpkit.models import ModificationSpec
from pfcpkit.scenarios import register

from .base import OaiScenario


@register
class MapPruningOnDeletion(OaiScenario):
    """Deleting a session must leave nothing of it in the rule maps."""

    name = "map_pruning_on_delete"
    description = "Session deletion clears every rule-map entry the session held"
    tags = frozenset({"datapath", "regression"})
    requires = frozenset({Capability.RULE_STATE})
    ue_index = 13

    def arrange(self) -> None:
        settings = self.ctx.settings
        self.session = self.establish(
            presets.basic_ipv4_session(
                settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x1220,
                dl_teid=0x1221,
                qer=presets.gbr_qer(),
            )
        )
        self.seid = self.session.require_up_seid()
        # Populate sdf_filters_map: the UPF writes SDF filters in ModifyPipeline
        # only, so establishment alone leaves nothing there to prune.
        self.modify(
            self.session,
            ModificationSpec(
                update_qers=(self.session.spec.qer(presets.DEFAULT_QER_ID),)
            ),
        )
        self.report.require(
            "the session has rule-map entries before deletion",
            len(self.rules.installed_pdr_ids(self.seid)) > 0,
            "nothing was installed, so deletion cannot be shown to clear it",
        )

    def act(self) -> None:
        # Delete here rather than leaving it to teardown, because the assertions
        # are about what deletion leaves behind.
        self.response = self.delete(self.session)

    def verify(self) -> None:
        report = self.report
        seid = self.seid

        report.check(
            "deletion accepted",
            self.response is not None and self.response.accepted,
            f"response={self.response}",
        )
        report.check_count(
            "no rules_match_pdr_map entries remain for the deleted session",
            0,
            len(self.rules.installed_pdr_ids(seid)),
        )
        report.check_count(
            "no sdf_filters_map entries remain for the deleted session",
            0,
            len(self.rules.installed_qfis(seid)),
        )
        report.check_count(
            "no pdrs_per_session_map entry remains for the deleted session",
            0,
            (1 if self.rules.session_installed(seid) else 0),
        )
