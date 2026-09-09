# SPDX-License-Identifier: MIT
"""Runs the documented example, so the guide cannot rot.

``pfcpkit/README.md`` tells a new project to write an adapter, a harness and some
scenarios. ``pfcpkit/examples/`` is that walkthrough as code. If the library changes in
a way that breaks the documented pattern -- a protocol gains a method, a scenario hook
is renamed, ``execute()`` stops running ``teardown`` -- this fails, rather than the
guide quietly becoming wrong.

The example scenarios are driven against a fake client that records requests and
mutates the in-memory adapter state as a UPF would. So this checks something stronger
than "the code imports": it checks the scenarios *pass* when the UPF behaves correctly,
which is what a reader copying them is entitled to assume.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from pfcpkit.capabilities import LogSource, QosState, RuleState
from pfcpkit.config import Settings
from pfcpkit.examples import EXAMPLE_SCENARIOS
from pfcpkit.examples.adapter import (
    ADAPTER_NAME,
    CAPABILITIES,
    ExampleLogSource,
    ExampleQosState,
    ExampleRuleState,
    FakeUpfState,
)
from pfcpkit.models import ModificationSpec, PfcpResponse, SessionSpec
from pfcpkit.pfcp.session import SessionContext
from pfcpkit.pfcp.types import Cause
from pfcpkit.scenarios import PfcpScenario, partition_by_capability
from pfcpkit.scenarios.context import ScenarioContext


@dataclass
class CorrectUpf:
    """A fake client backed by :class:`FakeUpfState`, behaving as a UPF should.

    Deliberately *correct*: it installs what it is asked to install, prunes what it is
    asked to remove, and reprograms once per modification. The example scenarios must
    pass against it. A UPF with the defects the OAI suite documents would fail them,
    which is the point.
    """

    settings: Settings
    state: FakeUpfState
    _next_seid: int = 0x2000
    requests: list[str] = field(default_factory=list)

    def establish_session(self, spec: SessionSpec) -> SessionContext:
        self._next_seid += 1
        seid = self._next_seid
        session = SessionContext(cp_seid=seid, spec=spec)
        session.up_seid = seid

        self.state.pdrs[seid] = [pdr.pdr_id for pdr in spec.pdrs]
        self.state.qfis[seid] = sorted(
            {qer.qfi for qer in spec.qers if qer.qfi is not None}
        )
        if spec.ue_ipv4:
            self.state.ue_owners[spec.ue_ipv4] = seid
        for qer in spec.qers:
            if qer.qfi is not None and qer.gbr_dl_kbps and qer.mbr_dl_kbps:
                self.state.rates[(seid, qer.qfi)] = (qer.gbr_dl_kbps, qer.mbr_dl_kbps)
        self.state.shapers.add(seid)
        self.state.log.append(f"create session 0x{seid:x}")
        self.requests.append("establish")
        return session

    def modify_session(
        self, session: SessionContext, delta: ModificationSpec
    ) -> PfcpResponse:
        seid = session.require_up_seid()

        for pdr_id in delta.remove_pdr_ids:
            if pdr_id in self.state.pdrs.get(seid, []):
                self.state.pdrs[seid].remove(pdr_id)
        for qer_id in delta.remove_qer_ids:
            qer = next((q for q in session.spec.qers if q.qer_id == qer_id), None)
            if qer is not None and qer.qfi is not None:
                self.state.qfis.get(seid, []).remove(qer.qfi)
                self.state.rates.pop((seid, qer.qfi), None)
        for pdr in delta.create_pdrs:
            self.state.pdrs.setdefault(seid, []).append(pdr.pdr_id)
        for qer in delta.update_qers:
            if qer.qfi is not None and qer.gbr_dl_kbps and qer.mbr_dl_kbps:
                self.state.rates[(seid, qer.qfi)] = (qer.gbr_dl_kbps, qer.mbr_dl_kbps)

        # Exactly one reprogramming pass per request -- what `example_rebuild_count`
        # asserts, and what the OAI UPF currently does not do.
        self.state.log.append(f"rebuild session 0x{seid:x}")
        self.requests.append("modify")
        return PfcpResponse(
            message_type=53, seq=1, cause=Cause.REQUEST_ACCEPTED, up_seid=seid
        )

    def delete_session(
        self, session: SessionContext, *, tolerate_failure: bool = False
    ) -> PfcpResponse | None:
        seid = session.require_up_seid()
        self.state.pdrs.pop(seid, None)
        self.state.qfis.pop(seid, None)
        self.state.shapers.discard(seid)
        for key in [k for k in self.state.rates if k[0] == seid]:
            del self.state.rates[key]
        for address, owner in list(self.state.ue_owners.items()):
            if owner == seid:
                del self.state.ue_owners[address]
        session.active = False
        self.state.log.append(f"delete session 0x{seid:x}")
        self.requests.append("delete")
        return PfcpResponse(message_type=55, seq=1, cause=Cause.REQUEST_ACCEPTED)


@pytest.fixture()
def state() -> FakeUpfState:
    return FakeUpfState()


@pytest.fixture()
def ctx(state: FakeUpfState) -> ScenarioContext:
    """Exactly the wiring `pfcpkit/README.md` describes for a harness."""
    settings = Settings.from_env({})
    return ScenarioContext(
        settings=settings,
        client=CorrectUpf(settings, state),  # type: ignore[arg-type]
        rules=ExampleRuleState(state),
        qos=ExampleQosState(state),
        logs=ExampleLogSource(state),
        capabilities=CAPABILITIES,
        adapter=ADAPTER_NAME,
    )


# ---------------------------------------------------------------------------
# The adapter satisfies what it claims
# ---------------------------------------------------------------------------
def test_the_example_adapter_implements_every_protocol(state: FakeUpfState) -> None:
    """The protocols are ``runtime_checkable``, so this is a structural check.

    It is the same check a new adapter should copy: if a protocol gains a method, this
    fails here rather than as an ``AttributeError`` mid-scenario.
    """
    assert isinstance(ExampleRuleState(state), RuleState)
    assert isinstance(ExampleQosState(state), QosState)
    assert isinstance(ExampleLogSource(state), LogSource)


def test_declared_capabilities_match_the_protocols_implemented() -> None:
    """Over-claiming turns a clean skip into a confusing mid-run failure."""
    assert len(CAPABILITIES) == 3


# ---------------------------------------------------------------------------
# The example scenarios pass against a correct UPF
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "example_cls", EXAMPLE_SCENARIOS, ids=lambda cls: str(cls.name)
)
def test_example_scenario_passes(
    example_cls: type[PfcpScenario], ctx: ScenarioContext
) -> None:
    report = example_cls(ctx).execute()
    assert report.ok, "\n" + report.render()
    assert report.warnings == 0, "\n" + report.render()


def test_examples_cover_the_three_styles() -> None:
    """One PFCP-only, one state-asserting, one log-asserting.

    Asserted so that trimming the examples cannot silently drop the style a reader
    came for.
    """
    requires = {cls.name: frozenset(cls.requires) for cls in EXAMPLE_SCENARIOS}
    assert any(not r for r in requires.values()), "no PFCP-only example"
    assert any(
        r and all(c.name == "RULE_STATE" for c in r) for r in requires.values()
    ), "no state-asserting example"
    assert any(
        r and all(c.name == "LOG_WINDOW" for c in r) for r in requires.values()
    ), "no log-asserting example"


def test_a_scenario_is_skipped_when_its_capability_is_absent() -> None:
    """What a partially-capable adapter gets: a reported skip, not a failure."""
    runnable, skipped = partition_by_capability(
        EXAMPLE_SCENARIOS, frozenset()
    )
    assert [cls.name for cls in runnable] == ["example_establishment"]
    assert len(skipped) == 2
    for _, missing in skipped:
        assert missing, "a skip must name what was missing"


# ---------------------------------------------------------------------------
# The lifecycle the guide promises
# ---------------------------------------------------------------------------
def test_sessions_are_deleted_even_though_no_scenario_deletes_them(
    ctx: ScenarioContext, state: FakeUpfState
) -> None:
    """`execute()` runs teardown, which releases what `establish()` tracked.

    The guide tells readers they need not clean up. This is that promise, checked.
    """
    for scenario_cls in EXAMPLE_SCENARIOS:
        scenario_cls(ctx).execute()

    assert state.pdrs == {}, "a session survived its scenario"
    assert state.ue_owners == {}
    assert state.rates == {}


# ---------------------------------------------------------------------------
# The guide's own code blocks
# ---------------------------------------------------------------------------
_README = Path(__file__).resolve().parents[2] / "pfcpkit" / "README.md"


def _python_blocks(markdown: str) -> list[str]:
    return re.findall(r"```python\n(.*?)```", markdown, re.DOTALL)


def test_the_guide_has_code_blocks_to_check() -> None:
    """Guards against the check below passing because it found nothing."""
    assert _README.exists(), f"{_README} is missing"
    assert len(_python_blocks(_README.read_text())) >= 5


def test_every_code_block_in_the_guide_parses() -> None:
    """Cheap guard against the guide drifting into syntax errors.

    Compile-only, because several blocks are fragments with ``...`` placeholders that
    cannot run standalone. Whether the *behaviour* is right is covered by the example
    scenarios above, which are the same patterns in runnable form.
    """
    for index, block in enumerate(_python_blocks(_README.read_text()), start=1):
        try:
            compile(block, f"{_README.name} block {index}", "exec")
        except SyntaxError as exc:  # pragma: no cover - only on a broken guide
            pytest.fail(f"block {index} does not parse: {exc}\n{block}")
