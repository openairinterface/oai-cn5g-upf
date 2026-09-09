# SPDX-License-Identifier: MIT
"""The scenario interface.

:class:`PfcpScenario` uses the Template Method pattern: :meth:`execute` is the
fixed skeleton -- arrange, act, verify, and *always* tear down -- while subclasses
supply the phases. That structure buys three things a plain function could not:

* teardown cannot be forgotten, so a failing scenario never leaks a PFCP session
  into the next one -- a UPF that keys its downlink lookup by UE IP will happily
  serve a leaked session's state to the next scenario;
* an unhandled exception becomes a recorded failure instead of aborting the
  whole suite;
* every scenario reports in the same shape, so the runner needs no per-scenario
  knowledge.

To add a scenario: subclass this, set ``name``, implement :meth:`act` and
:meth:`verify`, and decorate the class with
:func:`pfcpkit.scenarios.register`. Nothing else needs to change.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import ClassVar

from ..capabilities import Capability
from ..errors import ScenarioAborted
from ..models import ModificationSpec, PfcpResponse, SessionSpec
from ..pfcp.session import SessionContext
from ..report import TestReport
from .context import ScenarioContext

logger = logging.getLogger(__name__)


class PfcpScenario(ABC):
    """One end-to-end PFCP scenario."""

    #: Stable identifier used by the CLI, the registry, and reports.
    name: ClassVar[str]
    #: One-line human summary, shown by ``--list``.
    #:
    #: States the behaviour under test, in the present tense and as the *correct*
    #: outcome -- "Removed PDRs are pruned from the datapath", not "removed PDRs are
    #: not pruned". A scenario describes the requirement; whether this UPF currently
    #: meets it is a property of the run, not of the scenario.
    description: ClassVar[str] = ""
    #: Selection labels, e.g. ``{"smoke"}`` or ``{"qos"}``.
    tags: ClassVar[frozenset[str]] = frozenset()

    #: Observations this scenario needs. The runner skips -- and reports -- any
    #: scenario whose requirements the adapter does not declare, so a capability
    #: gap never masquerades as a pass.
    requires: ClassVar[frozenset[Capability]] = frozenset()

    #: Offset from ``UE_IPV4_BASE`` for this scenario's UE address.
    #:
    #: Every scenario needs its own, and the convention tests assert they are
    #: distinct. This is not tidiness: a UPF that never clears its UE-IP lookup
    #: on session deletion makes two scenarios sharing an address into one
    #: scenario's leftovers becoming the other's failure
    ue_index: ClassVar[int] = 0

    def __init__(self, ctx: ScenarioContext) -> None:
        self.ctx = ctx
        self.report = TestReport(self.name)
        self._owned: list[SessionContext] = []

    # ------------------------------------------------------------------
    # Template method -- the fixed skeleton. Subclasses should not override.
    # ------------------------------------------------------------------
    def execute(self) -> TestReport:
        """Run the scenario and return its report. Never raises."""
        logger.info("scenario %s: starting", self.name)
        try:
            self.arrange()
            self.act()
            self.verify()
        except ScenarioAborted as exc:
            logger.warning("scenario %s: aborted -- %s", self.name, exc)
            self.report.abort(f"aborted: {exc}")
        except Exception as exc:  # noqa: BLE001 - reported, never propagated
            logger.exception("scenario %s: unhandled error", self.name)
            self.report.error(f"unhandled {type(exc).__name__}: {exc}")
        finally:
            self._safe_teardown()
        logger.info("scenario %s: %s", self.name, self.report.verdict)
        return self.report

    # ------------------------------------------------------------------
    # Phases
    # ------------------------------------------------------------------
    def arrange(self) -> None:
        """Establish preconditions.

        Default is a no-op, which suits scenarios whose subject *is* the
        establishment. Override to set up a session before acting on it.
        """

    @abstractmethod
    def act(self) -> None:
        """Perform the PFCP exchange under test."""

    @abstractmethod
    def verify(self) -> None:
        """Record assertions on ``self.report``."""

    def teardown(self) -> None:
        """Release anything this scenario created.

        Default deletes every session established through :meth:`establish`,
        newest first. Override to add extra cleanup, and call ``super()``.
        """
        for session in reversed(self._owned):
            if session.active:
                self.ctx.client.delete_session(session, tolerate_failure=True)

    # ------------------------------------------------------------------
    # Helpers for subclasses
    # ------------------------------------------------------------------
    def ue_ip(self) -> str:
        """This scenario's own UE IPv4 address, derived from :attr:`ue_index`."""
        from .. import presets  # local import avoids a cycle via presets -> models

        return presets.ue_ipv4(self.ctx.settings, self.ue_index)

    def require_pdrs_installed(self, seid: int, pdr_ids: Sequence[int]) -> None:
        """Abort unless the data plane really holds every named PDR.

        Guards the vacuous pass. A scenario that removes a PDR and then asserts it
        is absent proves nothing if the PDR was never installed: the removal
        no-ops, the absence check succeeds, and the report is green while nothing
        was tested. Asserting presence first makes that impossible.
        """
        installed = self.ctx.rules.installed_pdr_ids(seid)
        missing = [pdr_id for pdr_id in pdr_ids if pdr_id not in installed]
        self.report.require(
            f"PDR(s) {list(pdr_ids)} are installed before being removed",
            not missing,
            f"{missing} absent; the data plane holds {installed} "
            "-- removing them would be a no-op and the absence check meaningless",
        )

    def establish(self, spec: SessionSpec) -> SessionContext:
        """Establish a session, register it for teardown, and require success.

        Aborts the scenario if the UPF did not return a UP F-SEID: without one,
        no later modification or deletion can address the session, so every
        subsequent assertion would fail for the same uninteresting reason.
        """
        session = self.ctx.client.establish_session(spec)
        self._owned.append(session)
        self.report.require(
            "session establishment accepted",
            session.addressable and session.active,
            "no UP F-SEID in the establishment response",
        )
        return session

    def modify(self, session: SessionContext, delta: ModificationSpec) -> PfcpResponse:
        """Send a Session Modification Request."""
        return self.ctx.client.modify_session(session, delta)

    def delete(self, session: SessionContext) -> PfcpResponse | None:
        """Delete a session now, rather than leaving it to teardown."""
        return self.ctx.client.delete_session(session)

    def track(self, session: SessionContext) -> SessionContext:
        """Register an externally-created session for automatic teardown."""
        if session not in self._owned:
            self._owned.append(session)
        return session

    @property
    def owned_sessions(self) -> tuple[SessionContext, ...]:
        return tuple(self._owned)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    def _safe_teardown(self) -> None:
        try:
            self.teardown()
        except Exception:  # noqa: BLE001 - must not mask the real failure
            logger.exception("scenario %s: teardown failed", self.name)
            self.report.warn("teardown did not complete cleanly")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} name={self.name!r}>"
