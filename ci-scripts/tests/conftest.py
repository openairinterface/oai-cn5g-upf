# SPDX-License-Identifier: MIT
"""pytest adapter.

Every discovered scenario becomes a pytest case automatically, which buys ``-k``
filtering and JUnit XML for CI without making pytest a dependency of the
scenarios themselves -- ``run_scenarios.py`` remains the stdlib+scapy path.

Discovery covers both roots: :mod:`pfcpkit.conformance` (adapter-agnostic) and
:mod:`upf_test.scenarios` (OAI-specific). A scenario requiring a capability the
OAI adapter does not provide is *skipped with its missing set named*, rather than
quietly omitted from the parametrisation -- a suite that drops what it cannot
observe looks identical to one that passed it.

Integration cases are marked ``integration`` and need a live UPF. To run only the
framework's own unit tests::

    pytest -m "not integration"
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from pfcpkit.config import Settings
from pfcpkit.scenarios import ScenarioContext, discover
from upf_test.harness import build_context, register_scenarios
from upf_test.inspector import ADAPTER_NAME, CAPABILITIES
from upf_test.settings import Deployment


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Parametrise ``scenario_cls`` over every discovered scenario.

    Skips a test that already parametrises the argument itself. Without that guard the
    two collide with "duplicate parametrization", which is a confusing failure for a
    unit test that happens to pick the same argument name -- and the name is an obvious
    one to pick.
    """
    if "scenario_cls" not in metafunc.fixturenames:
        return
    if any(
        mark.name == "parametrize" and "scenario_cls" in str(mark.args[0])
        for mark in metafunc.definition.iter_markers()
    ):
        return

    register_scenarios()
    found = discover()

    params = []
    for name, cls in found.items():
        missing = frozenset(cls.requires) - CAPABILITIES
        marks = (
            pytest.mark.skip(
                reason=(
                    f"adapter {ADAPTER_NAME} does not provide "
                    + ", ".join(sorted(c.name for c in missing))
                )
            ),
        ) if missing else ()
        params.append(pytest.param(cls, id=name, marks=marks))

    metafunc.parametrize("scenario_cls", params)


@pytest.fixture(scope="session")
def settings() -> Settings:
    return Settings.from_env()


@pytest.fixture(scope="session")
def deployment() -> Deployment:
    return Deployment.from_env()


@pytest.fixture(scope="session")
def ctx(settings: Settings, deployment: Deployment) -> Iterator[ScenarioContext]:
    """One PFCP association and adapter set shared by every integration case."""
    with build_context(settings, deployment) as context:
        yield context
