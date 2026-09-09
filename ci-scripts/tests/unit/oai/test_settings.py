# SPDX-License-Identifier: MIT
"""Tests for the OAI deployment settings.

Environment parsing is worth pinning because a bad value here does not fail
loudly: a wrong container name makes every inspection return nothing, which reads
as "the UPF installed nothing".
"""

from __future__ import annotations

import pytest

from pfcpkit.errors import ConfigError
from upf_test.settings import Deployment


def test_defaults_match_the_compose_topology() -> None:
    deployment = Deployment.from_env({})
    assert deployment.upf_container == "upf-test"
    assert deployment.n3_iface == "n3"
    assert deployment.n6_iface == "n6"
    assert deployment.bpftool.endswith("bpftool")
    assert deployment.command_timeout > 0


def test_environment_overrides_are_honoured() -> None:
    deployment = Deployment.from_env(
        {"UPF_CONTAINER": "other-upf", "N3_IFACE": "eth1", "COMMAND_TIMEOUT": "30"}
    )
    assert deployment.upf_container == "other-upf"
    assert deployment.n3_iface == "eth1"
    assert deployment.command_timeout == 30.0
    assert deployment.n6_iface == "n6", "unset keys keep their default"


def test_an_empty_override_is_an_error_not_a_fallback() -> None:
    """``UPF_CONTAINER=`` almost certainly means a broken shell expansion."""
    with pytest.raises(ConfigError, match="empty"):
        Deployment.from_env({"UPF_CONTAINER": ""})


def test_a_non_numeric_timeout_is_rejected() -> None:
    with pytest.raises(ConfigError, match="not a number"):
        Deployment.from_env({"COMMAND_TIMEOUT": "soon"})


def test_a_non_positive_timeout_is_rejected() -> None:
    with pytest.raises(ConfigError, match="must be > 0"):
        Deployment.from_env({"COMMAND_TIMEOUT": "0"})


def test_describe_names_the_container_and_interfaces() -> None:
    described = Deployment.from_env({}).describe()
    assert "upf-test" in described
    assert "n3" in described
