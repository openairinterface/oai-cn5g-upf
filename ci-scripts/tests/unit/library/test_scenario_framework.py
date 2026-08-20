# SPDX-License-Identifier: MIT
"""Tests for the scenario base class and registry.

These use a fake client, so the whole scenario lifecycle -- including teardown
behaviour on failure -- is verified without a UPF, a socket, or root.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from pfcpkit.capabilities import Capability
from pfcpkit.config import Settings
from pfcpkit.models import ModificationSpec, PfcpResponse, SessionSpec
from pfcpkit.pfcp.session import SessionContext
from pfcpkit.pfcp.types import Cause
from pfcpkit.presets import basic_ipv4_session
from pfcpkit.scenarios import partition_by_capability, register, select
from pfcpkit.scenarios.base import PfcpScenario
from pfcpkit.scenarios.context import ScenarioContext


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
@dataclass
class FakeClient:
    """Stands in for PfcpClient, recording calls instead of sending packets."""

    settings: Settings
    established: list[SessionContext] = field(default_factory=list)
    deleted: list[int] = field(default_factory=list)
    modifications: list[ModificationSpec] = field(default_factory=list)
    accept_establishment: bool = True
    _next_seid: int = 0x1000

    def establish_session(self, spec: SessionSpec) -> SessionContext:
        self._next_seid += 1
        session = SessionContext(cp_seid=self._next_seid, spec=spec)
        if self.accept_establishment:
            session.up_seid = self._next_seid ^ 0xFF00
        else:
            session.active = False
        self.established.append(session)
        return session

    def modify_session(
        self, session: SessionContext, delta: ModificationSpec
    ) -> PfcpResponse:
        self.modifications.append(delta)
        return PfcpResponse(
            message_type=53,
            seq=1,
            cause=Cause.REQUEST_ACCEPTED,
            up_seid=session.up_seid,
        )

    def delete_session(
        self,
        session: SessionContext,
        *,
        tolerate_failure: bool = False,  # noqa: ARG002 - mirrors the real signature
    ) -> PfcpResponse | None:
        self.deleted.append(session.cp_seid)
        session.active = False
        return PfcpResponse(message_type=55, seq=1, cause=Cause.REQUEST_ACCEPTED)


class NullRuleState:
    """A RuleState that observes nothing -- structurally valid, always empty.

    The point is that the library's scenario machinery can be exercised against
    *some* adapter without importing a real one. Anything asserting on real state
    belongs in an adapter's own tests.
    """

    def installed_pdr_ids(self, seid: int) -> list[int]:  # noqa: ARG002
        return []

    def installed_qfis(self, seid: int) -> list[int]:  # noqa: ARG002
        return []

    def seid_for_ue_ip(self, ue_ipv4: str) -> int | None:  # noqa: ARG002
        return None

    def session_installed(self, seid: int) -> bool:  # noqa: ARG002
        return False


class NullQosState:
    def flow_exists(self, seid: int, qfi: int) -> bool:  # noqa: ARG002
        return False

    def flow_rate_kbps(self, seid: int, qfi: int) -> tuple[int, int] | None:  # noqa: ARG002, E501
        return None

    def session_shaper_exists(self, seid: int) -> bool:  # noqa: ARG002
        return False

    def shaper_root_exists(self) -> bool:
        return False


class NullLogSource:
    def mark(self) -> object:
        return 0

    def find_since(self, mark: object, pattern: str) -> list[str]:  # noqa: ARG002
        return []

    def count_since(self, mark: object, pattern: str) -> int:  # noqa: ARG002
        return 0

    def stable_count_since(self, mark: object, pattern: str) -> int:  # noqa: ARG002
        return 0

    def errors_since(
        self, mark: object, *, ignore: tuple[str, ...] = ()
    ) -> list[str]:  # noqa: ARG002
        return []


@pytest.fixture()
def ctx() -> ScenarioContext:
    settings = Settings.from_env({})
    return ScenarioContext(
        settings=settings,
        client=FakeClient(settings),  # type: ignore[arg-type]
        rules=NullRuleState(),
        qos=NullQosState(),
        logs=NullLogSource(),
        capabilities=frozenset(Capability),
        adapter="null",
    )


def _spec(ctx: ScenarioContext) -> SessionSpec:
    return basic_ipv4_session(ctx.settings)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
def test_phases_run_in_order(ctx: ScenarioContext) -> None:
    calls: list[str] = []

    class Ordered(PfcpScenario):
        name = "unit_ordered"

        def arrange(self) -> None:
            calls.append("arrange")

        def act(self) -> None:
            calls.append("act")

        def verify(self) -> None:
            calls.append("verify")
            self.report.check("ran", True)

        def teardown(self) -> None:
            calls.append("teardown")

    report = Ordered(ctx).execute()
    assert calls == ["arrange", "act", "verify", "teardown"]
    assert report.ok


def test_teardown_runs_even_when_act_raises(ctx: ScenarioContext) -> None:
    """An unhandled error must not leak state into the next scenario."""
    torn_down = False

    class Exploding(PfcpScenario):
        name = "unit_exploding"

        def act(self) -> None:
            raise RuntimeError("boom")

        def verify(self) -> None:  # pragma: no cover - never reached
            self.report.check("unreachable", True)

        def teardown(self) -> None:
            nonlocal torn_down
            torn_down = True

    report = Exploding(ctx).execute()
    assert torn_down
    assert not report.ok
    assert "RuntimeError" in report.render()


def test_established_sessions_are_deleted_by_default_teardown(
    ctx: ScenarioContext,
) -> None:
    class Establishing(PfcpScenario):
        name = "unit_establishing"

        def act(self) -> None:
            self.establish(_spec(self.ctx))

        def verify(self) -> None:
            self.report.check("established", True)

    Establishing(ctx).execute()
    client = ctx.client
    assert len(client.established) == 1  # type: ignore[attr-defined]
    assert client.deleted == [client.established[0].cp_seid]  # type: ignore[attr-defined]


def test_failed_establishment_aborts_before_act(ctx: ScenarioContext) -> None:
    ctx.client.accept_establishment = False  # type: ignore[attr-defined]
    acted = False

    class Dependent(PfcpScenario):
        name = "unit_dependent"

        def arrange(self) -> None:
            self.establish(_spec(self.ctx))

        def act(self) -> None:
            nonlocal acted
            acted = True

        def verify(self) -> None:  # pragma: no cover - never reached
            self.report.check("unreachable", True)

    report = Dependent(ctx).execute()
    assert not acted, "act() must not run once a precondition has failed"
    assert not report.ok
    assert "aborted" in report.render()


def test_teardown_failure_is_a_warning_not_a_crash(ctx: ScenarioContext) -> None:
    class BadTeardown(PfcpScenario):
        name = "unit_bad_teardown"

        def act(self) -> None:
            pass

        def verify(self) -> None:
            self.report.check("fine", True)

        def teardown(self) -> None:
            raise RuntimeError("teardown exploded")

    report = BadTeardown(ctx).execute()
    assert report.warnings == 1
    # The scenario's own assertions still stand.
    assert report.passed == 1


def test_execute_never_raises(ctx: ScenarioContext) -> None:
    class Hostile(PfcpScenario):
        name = "unit_hostile"

        def arrange(self) -> None:
            raise KeyError("in arrange")

        def act(self) -> None:  # pragma: no cover
            pass

        def verify(self) -> None:  # pragma: no cover
            pass

    report = Hostile(ctx).execute()  # must not propagate
    assert not report.ok


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def test_register_rejects_a_nameless_scenario() -> None:
    class Nameless(PfcpScenario):
        def act(self) -> None: ...
        def verify(self) -> None: ...

    with pytest.raises(ValueError, match="class-level `name`"):
        register(Nameless)


def test_register_rejects_a_duplicate_name() -> None:
    class First(PfcpScenario):
        name = "unit_duplicate_name"

        def act(self) -> None: ...
        def verify(self) -> None: ...

    class Second(PfcpScenario):
        name = "unit_duplicate_name"

        def act(self) -> None: ...
        def verify(self) -> None: ...

    register(First)
    with pytest.raises(ValueError, match="already registered"):
        register(Second)


def test_select_rejects_an_unknown_name() -> None:
    with pytest.raises(KeyError, match="unknown scenario"):
        select(names=["no_such_scenario"])


def test_select_by_tag_finds_only_the_tagged_scenarios() -> None:
    """Registers its own tagged scenario rather than relying on a shipped one.

    The library carries no scenarios of its own, so a test that selected by a tag it
    expected to find would be asserting on whichever project's root happened to be
    registered -- passing or failing for reasons outside this file.
    """

    class Tagged(PfcpScenario):
        name = "unit_tagged_scenario"
        tags = frozenset({"unit_only_tag"})

        def act(self) -> None: ...
        def verify(self) -> None: ...

    register(Tagged)
    selected = select(tags=["unit_only_tag"])
    assert selected == [Tagged]


def test_select_by_an_unused_tag_returns_nothing() -> None:
    assert select(tags=["no_scenario_carries_this_tag"]) == []


def test_select_with_no_filters_returns_everything() -> None:
    assert len(select()) >= len(select(tags=["unit_only_tag"]))


def test_the_library_registers_no_discovery_root_of_its_own() -> None:
    """`pfcpkit` ships machinery, not scenarios.

    If the library ever started carrying its own scenario package again, every
    consuming project would silently inherit it -- including scenarios that skip
    themselves on that project's adapter, which is indistinguishable from passing.
    """
    from pfcpkit.scenarios import discovery_roots

    assert not [r for r in discovery_roots() if r.startswith("pfcpkit.")]


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------
def test_the_null_adapters_satisfy_the_capability_protocols(
    ctx: ScenarioContext,
) -> None:
    """The protocols are runtime_checkable, so this is a real structural check.

    If a protocol grows a method, this fails here rather than as an
    ``AttributeError`` in the middle of a live scenario run.
    """
    from pfcpkit.capabilities import LogSource, QosState, RuleState

    assert isinstance(ctx.rules, RuleState)
    assert isinstance(ctx.qos, QosState)
    assert isinstance(ctx.logs, LogSource)


def test_scenarios_are_skipped_rather_than_run_without_their_capability() -> None:
    class NeedsQos(PfcpScenario):
        name = "unit_needs_qos"
        requires = frozenset({Capability.QOS_STATE})

        def act(self) -> None: ...
        def verify(self) -> None: ...

    class NeedsNothing(PfcpScenario):
        name = "unit_needs_nothing"

        def act(self) -> None: ...
        def verify(self) -> None: ...

    runnable, skipped = partition_by_capability(
        [NeedsQos, NeedsNothing], frozenset({Capability.RULE_STATE})
    )
    assert runnable == [NeedsNothing]
    assert skipped == [(NeedsQos, frozenset({Capability.QOS_STATE}))]


def test_a_skip_names_what_is_missing() -> None:
    """The missing set is returned, not swallowed.

    A conformance suite that silently drops what it cannot observe is
    indistinguishable from one that passed those scenarios -- which is exactly the
    failure this guards against.
    """

    class NeedsBoth(PfcpScenario):
        name = "unit_needs_both"
        requires = frozenset({Capability.QOS_STATE, Capability.LOG_WINDOW})

        def act(self) -> None: ...
        def verify(self) -> None: ...

    _, skipped = partition_by_capability([NeedsBoth], frozenset())
    (_, missing), = skipped
    assert missing == frozenset({Capability.QOS_STATE, Capability.LOG_WINDOW})


def test_context_reports_support(ctx: ScenarioContext) -> None:
    assert ctx.supports(Capability.RULE_STATE, Capability.QOS_STATE)
    assert ctx.missing(frozenset({Capability.LOG_WINDOW})) == frozenset()
