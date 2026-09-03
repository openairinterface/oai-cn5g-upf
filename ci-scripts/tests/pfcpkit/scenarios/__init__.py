# SPDX-License-Identifier: MIT
"""Scenario registry and auto-discovery.

Adding a scenario means creating a module in a discovery root and decorating the
class with :func:`register`. :func:`discover` imports every module in every
registered root, so there is no import list to maintain and no runner edit
required.

**Module naming: ``NN-topic.py``**, two digits and a hyphen, one registered scenario
per module. Two things follow:

* discovery walks each root in sorted order, so the number fixes *run* order. That
  matters: a scenario which can degrade the UPF must run last, and relying on a
  filename happening to sort late is luck, not intent.
* one class per file means the filename names the scenario, so ``--list`` output and
  the directory listing agree, and a scenario is never hidden behind a module named
  after a theme rather than a behaviour.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from collections.abc import Iterable, Mapping

from ..capabilities import Capability
from .base import PfcpScenario
from .context import ScenarioContext

logger = logging.getLogger(__name__)

#: Modules in a discovery root that are infrastructure rather than scenarios.
_NON_SCENARIO_MODULES = frozenset({"base", "context"})

_REGISTRY: dict[str, type[PfcpScenario]] = {}

#: Packages walked by :func:`discover`, in order. Empty by default -- the library
#: ships no scenarios of its own, so a project must register its root.
_ROOTS: list[str] = []


def add_discovery_root(package: str) -> None:
    """Register a package to be walked for scenarios.

    Idempotent, and order-preserving: roots are walked in the order added.
    """
    if package not in _ROOTS:
        _ROOTS.append(package)


def discovery_roots() -> tuple[str, ...]:
    return tuple(_ROOTS)


def register(cls: type[PfcpScenario]) -> type[PfcpScenario]:
    """Class decorator adding a scenario to the registry.

    Raises:
        ValueError: the class has no ``name``, or the name is already taken.
    """
    name = getattr(cls, "name", None)
    if not name:
        raise ValueError(f"{cls.__name__} must define a class-level `name`")
    existing = _REGISTRY.get(name)
    if existing is not None and existing is not cls:
        raise ValueError(
            f"scenario name {name!r} is already registered to {existing.__name__}"
        )
    _REGISTRY[name] = cls
    return cls


def discover() -> Mapping[str, type[PfcpScenario]]:
    """Import every scenario module in every root, then return the registry.

    Idempotent: already-imported modules are cheap no-ops.
    """
    for root in _ROOTS:
        try:
            package = importlib.import_module(root)
        except ModuleNotFoundError:
            logger.warning("scenario root %s is not importable -- skipped", root)
            continue
        for info in pkgutil.iter_modules(package.__path__):
            if info.name in _NON_SCENARIO_MODULES or info.name.startswith("_"):
                continue
            importlib.import_module(f"{root}.{info.name}")
    return dict(_REGISTRY)


def select(
    names: Iterable[str] | None = None,
    tags: Iterable[str] | None = None,
) -> list[type[PfcpScenario]]:
    """Resolve a selection of scenarios, preserving registration order.

    With neither argument, returns everything. ``names`` and ``tags`` are a union,
    not an intersection, so ``--scenario x --tag smoke`` runs both.

    Raises:
        KeyError: a requested name is not registered.
    """
    available = discover()

    if not names and not tags:
        return list(available.values())

    wanted: dict[str, type[PfcpScenario]] = {}

    for name in names or ():
        try:
            wanted[name] = available[name]
        except KeyError:
            raise KeyError(
                f"unknown scenario {name!r}; available: {', '.join(sorted(available))}"
            ) from None

    if tags:
        tag_set = set(tags)
        for scenario_name, cls in available.items():
            if cls.tags & tag_set:
                wanted.setdefault(scenario_name, cls)

    return [cls for key, cls in available.items() if key in wanted]


#: One scenario that could not run, paired with the capabilities it was missing.
Skip = tuple["type[PfcpScenario]", frozenset[Capability]]


def partition_by_capability(
    scenarios: Iterable[type[PfcpScenario]], available: frozenset[Capability]
) -> tuple[list[type[PfcpScenario]], list[Skip]]:
    """Split scenarios into runnable and skipped, with each skip's missing set.

    Returned rather than logged so the caller can *report* the skips. A conformance
    suite that silently drops scenarios it cannot run looks identical to one that
    passed them.
    """
    runnable: list[type[PfcpScenario]] = []
    skipped: list[Skip] = []
    for cls in scenarios:
        missing = frozenset(cls.requires) - available
        if missing:
            skipped.append((cls, missing))
        else:
            runnable.append(cls)
    return runnable, skipped


def describe_all() -> str:
    """Human-readable catalogue for ``--list``.

    The root package is shown only when more than one is registered. With a single
    root it is the same string on every line, which is noise rather than information.
    """
    available = discover()
    if not available:
        return "no scenarios registered -- was a discovery root registered?"

    roots = {cls.__module__.rsplit(".", 1)[0] for cls in available.values()}
    width = max(len(name) for name in available)
    lines: list[str] = []
    for name, cls in available.items():
        tags = f"  tags={','.join(sorted(cls.tags))}" if cls.tags else ""
        root = f"  ({cls.__module__.rsplit('.', 1)[0]})" if len(roots) > 1 else ""
        lines.append(f"  {name:<{width}}  {cls.description}{tags}{root}")
    return "\n".join(lines)


__all__ = [
    "Capability",
    "PfcpScenario",
    "ScenarioContext",
    "add_discovery_root",
    "describe_all",
    "discover",
    "discovery_roots",
    "partition_by_capability",
    "register",
    "select",
]
