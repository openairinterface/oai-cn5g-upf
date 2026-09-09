# SPDX-License-Identifier: MIT
"""Collaborators handed to every scenario.

Constructor injection rather than globals or singletons: a scenario receives
exactly what it may use, the runner controls collaborator lifetime, and a
scenario can be exercised against fakes with no UPF present.

The observation collaborators are typed as the :mod:`pfcpkit.capabilities`
protocols, not as concrete inspectors. That is the whole reason a conformance
scenario can run against a UPF this library has never seen -- it asks
``rules.installed_pdr_ids(seid)`` and never learns whether the answer came from
``bpftool``, a CLI, or an HTTP endpoint.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..capabilities import Capability, LogSource, QosState, RuleState
from ..config import Settings
from ..pfcp.client import PfcpClient


@dataclass(frozen=True)
class ScenarioContext:
    """Everything a scenario is allowed to reach for.

    ``client`` drives the control plane; ``rules``, ``qos`` and ``logs`` observe
    what the data plane did about it. Most interesting assertions need the latter
    three -- a PFCP response says only that a request was accepted, not that the
    pipeline was rebuilt correctly.
    """

    settings: Settings
    client: PfcpClient
    rules: RuleState
    qos: QosState
    logs: LogSource

    #: What the adapter behind this context can actually observe. The runner
    #: compares it against each scenario's ``requires`` and skips the mismatch.
    capabilities: frozenset[Capability] = field(default_factory=frozenset)

    #: Adapter name, for failure messages ("oai-upf", "eupf", ...).
    adapter: str = "unknown"

    def supports(self, *required: Capability) -> bool:
        return all(capability in self.capabilities for capability in required)

    def missing(self, required: frozenset[Capability]) -> frozenset[Capability]:
        return frozenset(required) - self.capabilities
