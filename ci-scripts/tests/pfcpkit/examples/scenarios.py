# SPDX-License-Identifier: MIT
"""Three example scenarios, one per style you are likely to write.

Read alongside [`pfcpkit/README.md`](../README.md).

* :class:`ExampleEstablishment` -- PFCP responses only. Needs no capability, so it
  runs against any adapter, however little it can observe.
* :class:`ExampleModificationPrunesRules` -- asserts on data-plane state through
  :class:`~pfcpkit.capabilities.RuleState`. Portable across UPFs, because it names
  the question and not the storage.
* :class:`ExampleRebuildCount` -- asserts on the log, using an adapter *extra*. The
  least portable of the three, and the only one needing
  :class:`~pfcpkit.examples.base.ExampleScenario`.

All three follow the same skeleton: ``arrange`` sets up preconditions, ``act``
performs the one operation under test, ``verify`` asserts. ``execute()`` runs them in
that order and always runs ``teardown``, so a scenario never leaks a session even when
it raises.

Each carries a `Scenario / Expected behaviour / Expected output` docstring, which is
the convention.
"""

from __future__ import annotations

from .. import presets
from ..capabilities import Capability
from ..models import ModificationSpec, PfcpResponse, SessionSpec
from ..pfcp.session import SessionContext
from ..scenarios.base import PfcpScenario
from .base import ExampleScenario


class ExampleEstablishment(PfcpScenario):
    """Establish a session and check the UPF accepted it.

    **Scenario.** Send one Session Establishment Request for an IPv4 PDU session with
    two PDRs, two FARs and a QER.

    **Expected behaviour.** The UPF accepts the request and returns a UP F-SEID, which
    every later request for this session is addressed to.

    **Expected output.** Two passing checks: the accepted response and the allocated
    F-SEID. No warnings.

    Note there is no ``requires``: this asserts only on what PFCP itself reveals, so it
    runs against any adapter. Worth having as the first scenario in a suite -- it proves
    the association, the encoder and the transport work before anything harder is read.
    """

    name = "example_establishment"
    description = "A session establishment request is accepted and returns a UP F-SEID"
    tags = frozenset({"example", "smoke"})
    ue_index = 0

    def act(self) -> None:
        # `self.establish` sends the request, tracks the session for teardown, and
        # aborts the scenario if the UPF refused -- so `verify` can assume a session.
        self.session: SessionContext = self.establish(
            presets.basic_ipv4_session(
                self.ctx.settings,
                ue_ipv4=self.ue_ip(),
                qer=presets.gbr_qer(),
            )
        )

    def verify(self) -> None:
        self.report.check("establishment accepted", self.session.active)
        self.report.check(
            "the UPF allocated a UP F-SEID",
            self.session.up_seid is not None,
            "the response carried no F-SEID IE",
        )


class ExampleModificationPrunesRules(PfcpScenario):
    """Remove a PDR and check the data plane stopped holding it.

    **Scenario.** Establish a session with two QoS flows, confirm its rules reached the
    data plane, then send one Session Modification Request removing the second flow's
    PDRs.

    **Expected behaviour.** The UPF accepts the modification and the removed PDRs are
    no longer installed, while the remaining ones still are. TS 29.244 Section 5.2.1
    makes removal mandatory rather than advisory.

    **Expected output.** Four passing checks: the installation precondition, the
    accepted modification, the removed PDRs absent, and the survivors present.

    Two habits worth copying:

    * **Rule ids come from the session, not from constants.** ``spec.qer()`` and
      ``spec.pdrs_for_qer()`` raise if the id is absent, so a preset renumbering is an
      immediate error rather than a request that removes nothing.
    * **Assert the rules were there before removing them.** Removing a rule that was
      never installed is a no-op, and "it is absent afterwards" would then pass while
      testing nothing. ``require_pdrs_installed`` aborts the scenario instead of
      letting it report a vacuous success.
    """

    name = "example_modification_prunes_rules"
    description = "Removing a PDR prunes the rule state it installed"
    tags = frozenset({"example"})
    requires = frozenset({Capability.RULE_STATE})
    ue_index = 1

    def arrange(self) -> None:
        self.session = self.establish(
            presets.multi_flow_session(
                self.ctx.settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x9010,
                dl_teid=0x9011,
                extra_ul_teid=0x9012,
                extra_dl_teid=0x9013,
            )
        )
        seid = self.session.require_up_seid()

        spec: SessionSpec = self.session.spec
        doomed = spec.pdrs_for_qer(spec.qer(presets.EXTRA_QER_ID).qer_id)
        self.removed = tuple(pdr.pdr_id for pdr in doomed)
        self.survivors = tuple(
            pdr.pdr_id for pdr in spec.pdrs if pdr.pdr_id not in self.removed
        )

        # Aborts if the rules are not really installed, so the removal below cannot
        # succeed vacuously.
        self.require_pdrs_installed(seid, self.removed)

    def act(self) -> None:
        self.response: PfcpResponse = self.modify(
            self.session, ModificationSpec(remove_pdr_ids=self.removed)
        )

    def verify(self) -> None:
        report = self.report
        seid = self.session.require_up_seid()

        report.check("modification accepted", self.response.accepted)

        installed = self.ctx.rules.installed_pdr_ids(seid)
        for pdr_id in self.removed:
            report.check_absent(
                f"PDR {pdr_id} is no longer installed", pdr_id, installed
            )
        report.check(
            "the surviving PDRs are still installed",
            all(pdr_id in installed for pdr_id in self.survivors),
            f"expected {list(self.survivors)} to remain; found {installed}",
        )


class ExampleRebuildCount(ExampleScenario):
    """Count how many times one modification reprogrammed the data plane.

    **Scenario.** Establish a session, open a log window, then send one Session
    Modification Request carrying an Update QER.

    **Expected behaviour.** One request produces one reprogramming pass. A Session
    Modification Request is a single instruction: the UPF applies all of its IEs and
    reprograms once, rather than once per IE.

    **Expected output.** Two passing checks: the accepted modification and a count of
    exactly one.

    This is the least portable of the three, and shows why. The log *pattern* is
    specific to one implementation, so it lives in the adapter
    (:meth:`~pfcpkit.examples.adapter.ExampleLogSource.rebuilds_since`) rather than
    here -- and because that method is on no protocol, this is the one example that
    extends :class:`~pfcpkit.examples.base.ExampleScenario` rather than
    ``PfcpScenario``, so ``self.logs`` is typed as the concrete adapter and the call
    type-checks. Reaching it through ``self.ctx.logs`` would not.

    Note ``stable_count_since`` over ``count_since`` in a real adapter: reads of a live
    log lag the process, so an immediate count undercounts.
    """

    name = "example_rebuild_count"
    description = "One modification reprograms the data plane exactly once"
    tags = frozenset({"example"})
    requires = frozenset({Capability.LOG_WINDOW})
    ue_index = 2

    def arrange(self) -> None:
        self.qer = presets.gbr_qer(gbr_dl_kbps=50_000, mbr_dl_kbps=100_000)
        self.session = self.establish(
            presets.basic_ipv4_session(
                self.ctx.settings,
                ue_ipv4=self.ue_ip(),
                ul_teid=0x9020,
                dl_teid=0x9021,
                qer=self.qer,
            )
        )

    def act(self) -> None:
        # Open the window immediately before the operation, so nothing earlier in the
        # scenario is counted.
        self.mark = self.logs.mark()
        self.response = self.modify(
            self.session,
            ModificationSpec(
                update_qers=(
                    self.qer.with_bitrates(gbr_dl_kbps=20_000, mbr_dl_kbps=40_000),
                ),
            ),
        )

    def verify(self) -> None:
        report = self.report
        seid = self.session.require_up_seid()

        report.check("modification accepted", self.response.accepted)
        # `self.logs` is ExampleLogSource, so the adapter extra is in scope. Through
        # `self.ctx.logs` -- typed as the LogSource protocol -- it would not be.
        rebuilds = self.logs.rebuilds_since(self.mark, seid)
        report.check_count("the data plane was reprogrammed once", 1, rebuilds)
