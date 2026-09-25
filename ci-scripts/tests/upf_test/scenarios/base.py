# SPDX-License-Identifier: MIT
"""The base class every scenario in this package inherits from.

"""

from __future__ import annotations

from typing import cast

from pfcpkit.scenarios.base import PfcpScenario

from ..inspector import OaiQosState, OaiRuleState
from ..logs import OaiLogs


class OaiScenario(PfcpScenario):
    """A scenario written against the OAI UPF specifically.

    Each property is a ``cast`` -- a compile-time assertion, no runtime effect. It
    holds because :func:`upf_test.harness.build_context` is the only thing that builds
    a context here and always supplies the OAI adapters. Build one some other way and
    these would lie, surfacing as an ``AttributeError`` inside a scenario.
    """

    @property
    def rules(self) -> OaiRuleState:
        """Rule state, including the OAI-only ``rules_enabled`` bitmask."""
        return cast(OaiRuleState, self.ctx.rules)

    @property
    def qos(self) -> OaiQosState:
        """QoS state, including ``flow_handle`` for failure messages."""
        return cast(OaiQosState, self.ctx.qos)

    @property
    def logs(self) -> OaiLogs:
        """The log, including this UPF's own patterns."""
        return cast(OaiLogs, self.ctx.logs)
