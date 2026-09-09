# SPDX-License-Identifier: MIT
"""Runs every registered scenario as a pytest case.

The scenario classes are the source of truth; this module is a ~10-line adapter.
Parametrisation happens in ``conftest.py::pytest_generate_tests``.
"""

from __future__ import annotations

import pytest

from pfcpkit.scenarios import PfcpScenario, ScenarioContext


@pytest.mark.integration
def test_scenario(scenario_cls: type[PfcpScenario], ctx: ScenarioContext) -> None:
    report = scenario_cls(ctx).execute()
    assert report.ok, "\n" + report.render()
