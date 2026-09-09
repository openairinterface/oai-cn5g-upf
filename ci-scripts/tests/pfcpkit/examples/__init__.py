# SPDX-License-Identifier: MIT
"""A worked example of building a scenario suite on ``pfcpkit``.

Read [`pfcpkit/README.md`](../README.md) first; this package is the code that guide
refers to. Two modules:

* :mod:`pfcpkit.examples.adapter` -- an adapter implementing all three capability
  protocols over an in-memory dict, showing the shape without needing a UPF.
* :mod:`pfcpkit.examples.scenarios` -- three scenarios against it, one per style:
  PFCP-only, state-asserting, and log-asserting.

**Not a discovery root.** Nothing here is decorated with ``@register``, so importing
this package adds nothing to the registry and ``--all`` never picks it up. The
scenarios are registered on demand by :func:`register_examples`, which only the unit
tests call. Real scenarios *do* use the decorator -- the guide shows that form -- and
it is omitted here purely to keep example code out of real runs.
"""

from __future__ import annotations

from ..scenarios import register
from .scenarios import (
    ExampleEstablishment,
    ExampleModificationPrunesRules,
    ExampleRebuildCount,
)

#: The example scenarios, in the order the guide introduces them.
EXAMPLE_SCENARIOS = (
    ExampleEstablishment,
    ExampleModificationPrunesRules,
    ExampleRebuildCount,
)


def register_examples() -> None:
    """Add the example scenarios to the registry.

    Only the library's own tests call this. A project following the guide writes
    ``@register`` on its scenario classes instead and never needs it.
    """
    for scenario in EXAMPLE_SCENARIOS:
        register(scenario)


__all__ = [
    "EXAMPLE_SCENARIOS",
    "ExampleEstablishment",
    "ExampleModificationPrunesRules",
    "ExampleRebuildCount",
    "register_examples",
]
