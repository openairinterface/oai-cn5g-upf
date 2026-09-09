# SPDX-License-Identifier: MIT
"""Wiring: builds a :class:`ScenarioContext` for the OAI UPF.

The one place that knows how this UPF is observed, kept separate so the split
between execution targets is explicit and in a single spot:

* ``bpftool`` and ``tc`` run **inside the container** -- no BPF map is pinned to
  bpffs, and ``tc`` is network-namespace scoped, so both must execute in the UPF's
  own namespaces;
* ``docker logs`` runs **on the host**.

Also the place that registers this project's own scenario root, so a run covers
both the library's conformance set and the OAI-specific scenarios.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from pfcpkit.config import Settings
from pfcpkit.inspect.bpftool import BpfMapInspector
from pfcpkit.inspect.logs import LogInspector
from pfcpkit.inspect.runner import DockerExecRunner, LocalRunner
from pfcpkit.inspect.tc import TcInspector
from pfcpkit.scenarios import add_discovery_root
from pfcpkit.scenarios.context import ScenarioContext

from . import layouts
from .inspector import ADAPTER_NAME, CAPABILITIES, OaiQosState, OaiRuleState
from .logs import OaiLogs
from .settings import Deployment

logger = logging.getLogger(__name__)

#: This project's own scenarios, in addition to ``pfcpkit.conformance``.
SCENARIO_ROOT = "upf_test.scenarios"


def register_scenarios() -> None:
    """Make this project's OAI-specific scenarios discoverable."""
    add_discovery_root(SCENARIO_ROOT)


@contextmanager
def build_context(
    settings: Settings | None = None,
    deployment: Deployment | None = None,
) -> Iterator[ScenarioContext]:
    """Open a PFCP association and yield a fully-wired scenario context.

    The association is released and the socket closed on exit even if a scenario
    raised -- leaving one open makes the next run's association setup fail against
    a UPF that thinks it already has a peer.
    """
    from pfcpkit.pfcp.client import PfcpClient  # local: keeps import cost off --list

    settings = settings or Settings.from_env()
    deployment = deployment or Deployment.from_env()
    register_scenarios()

    in_container = DockerExecRunner(deployment.upf_container)
    on_host = LocalRunner()

    bpf = BpfMapInspector(in_container, layouts.MAPS, bpftool=deployment.bpftool)
    tc = TcInspector(in_container)
    logs = OaiLogs(LogInspector(on_host, deployment.upf_container))

    logger.info("adapter %s: %s", ADAPTER_NAME, deployment.describe())

    with PfcpClient(settings) as client:
        yield ScenarioContext(
            settings=settings,
            client=client,
            rules=OaiRuleState(bpf),
            qos=OaiQosState(tc, deployment.n3_iface),
            logs=logs,
            capabilities=CAPABILITIES,
            adapter=ADAPTER_NAME,
        )
