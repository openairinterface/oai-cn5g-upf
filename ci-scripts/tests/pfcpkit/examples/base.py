# SPDX-License-Identifier: MIT
"""Step 3 of the guide: a project's own scenario base class.

Needed as soon as a scenario uses an adapter *extra* -- a method the adapter has but no
capability protocol declares. ``ScenarioContext`` types its fields as the protocols, so
reaching an extra through the context is a type error::

    self.ctx.logs.rebuilds_since(mark, seid)
    # error: "LogSource" has no attribute "rebuilds_since"

The error is correct: ``LogSource`` has no such method. The object does, and a scenario
written for one UPF is entitled to use it. So a project adds properties returning the
same objects under its own concrete types, in one place:

Scenarios then use ``self.logs`` rather than ``self.ctx.logs``. Same object, different
declared type. The real one is
[`upf_test/scenarios/base.py`](../../upf_test/scenarios/base.py).

If none of your scenarios use extras, you do not need this file at all -- subclass
``PfcpScenario`` directly.
"""

from __future__ import annotations

from typing import cast

from ..scenarios.base import PfcpScenario
from .adapter import ExampleLogSource, ExampleQosState, ExampleRuleState


class ExampleScenario(PfcpScenario):
    """A scenario written against the example adapter specifically.

    Each property is a ``cast``: a compile-time assertion, no runtime effect. It holds
    because the project's own ``build_context`` is the only thing that builds a context
    for these scenarios and always supplies these adapters.
    """

    @property
    def rules(self) -> ExampleRuleState:
        return cast(ExampleRuleState, self.ctx.rules)

    @property
    def qos(self) -> ExampleQosState:
        return cast(ExampleQosState, self.ctx.qos)

    @property
    def logs(self) -> ExampleLogSource:
        return cast(ExampleLogSource, self.ctx.logs)
