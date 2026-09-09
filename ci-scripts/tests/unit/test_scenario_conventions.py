# SPDX-License-Identifier: MIT
"""Conventions every scenario must follow.

This file sits at the top of ``unit/`` rather than under ``library/`` or ``oai/``
because it checks the scenario *set* rather than any one module. Four rules are
enforced here rather than merely documented, because breaking any of them is silent.

Rule 1 -- distinct UE addresses.

This exists because of a real failure, not as a precaution. When
``qos_at_establishment`` was added it took the same ``ue_index`` as
``static_ip_reattach``, and because the UPF never clears ``session_by_ue_ip_map``
on deletion (Fix 6) the first scenario's leftover entry made the second one's
precondition fail. The symptom looked like a UPF bug in a scenario that was
actually fine.

Rule 2 -- numbered module names, unique across the set.

``NN-topic.py``, and because discovery walks the package in sorted order the number
fixes the order scenarios run in. ``16-repeated_modification.py`` must run last
because it can leave the UPF degraded, and relying on a filename happening to sort
late is luck rather than intent.

Rule 3 -- one registered scenario per module.

The filename then names the scenario, so ``--list`` and the directory listing agree.
Grouping several scenarios under a themed module hides them: a reader scanning the
directory for "what is checked about QoS cleanup?" sees a filename, not a theme they
have to open to decode.

Rule 4 -- declared capabilities match what the source reads.

An undeclared read cannot be skipped. Against the OAI adapter that is currently
harmless, since it provides everything; against an adapter that does not, the scenario
runs anyway and fails on state it was never going to be able to read -- which reads as
a UPF defect rather than as a missing declaration.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest

from pfcpkit.config import Settings
from pfcpkit.presets import ue_ipv4
from pfcpkit.scenarios import PfcpScenario, discover, discovery_roots
from upf_test.harness import register_scenarios

#: The root whose scenarios are shipped by this repo. Anything else discovered came
#: from a test registering a throwaway class.
_SHIPPED_ROOT = "upf_test.scenarios"


def real_scenarios() -> dict[str, type[PfcpScenario]]:
    """The shipped scenarios only, from every root.

    ``register`` is global, and ``test_scenario_framework.py`` registers throwaway
    classes to exercise the registry itself. Those live in test modules rather than
    in a scenario package, so they are excluded by module rather than by name -- a
    name filter would quietly stop working the moment a test class is renamed.
    """
    register_scenarios()
    return {
        name: cls
        for name, cls in discover().items()
        if cls.__module__.startswith(_SHIPPED_ROOT)
    }


def _root_of(cls: type[PfcpScenario]) -> str:
    return cls.__module__.rsplit(".", 1)[0]


def _module_of(cls: type[PfcpScenario]) -> str:
    return cls.__module__.rsplit(".", 1)[-1]


# ---------------------------------------------------------------------------
# Discovery itself
# ---------------------------------------------------------------------------
def test_the_scenario_root_is_registered_and_populated() -> None:
    """Guards against the rest of this file passing because discovery found nothing.

    A root that stops being importable is logged as a warning and skipped, so without
    this every conventions check below would go green on an empty set.
    """
    register_scenarios()
    assert _SHIPPED_ROOT in discovery_roots()

    scenarios = real_scenarios()
    assert len(scenarios) >= 16, f"only discovered {len(scenarios)} scenarios"
    assert {_root_of(cls) for cls in scenarios.values()} == {_SHIPPED_ROOT}


# ---------------------------------------------------------------------------
# Rule 1 -- distinct UE addresses
# ---------------------------------------------------------------------------
def test_every_scenario_has_a_distinct_ue_index() -> None:
    scenarios = real_scenarios()
    assert scenarios, "no scenarios were discovered"

    by_index: dict[int, list[str]] = {}
    for name, cls in scenarios.items():
        by_index.setdefault(cls.ue_index, []).append(name)

    clashes = {index: names for index, names in by_index.items() if len(names) > 1}
    assert not clashes, (
        "scenarios sharing a ue_index share a UE IP, and session_by_ue_ip_map is "
        f"never cleared on deletion: {clashes}"
    )


def test_ue_indices_resolve_to_distinct_addresses() -> None:
    """Distinct indices must also produce distinct addresses in the configured base."""
    settings = Settings.from_env({})
    addresses = [ue_ipv4(settings, cls.ue_index) for cls in real_scenarios().values()]
    duplicated = [addr for addr, count in Counter(addresses).items() if count > 1]
    assert not duplicated, f"duplicate UE addresses: {duplicated}"


def test_every_ue_index_stays_inside_the_subnet() -> None:
    """The UE pool is a /24, so an index must not push the last octet out of range."""
    settings = Settings.from_env({})
    for name, cls in real_scenarios().items():
        address = ue_ipv4(settings, cls.ue_index)
        last = int(address.split(".")[-1])
        assert 0 < last < 255, f"{name}: ue_index {cls.ue_index} gives {address}"


def test_ue_ipv4_rejects_an_out_of_range_index() -> None:
    settings = Settings.from_env({})
    with pytest.raises(ValueError, match="out of its subnet"):
        ue_ipv4(settings, 1000)


# ---------------------------------------------------------------------------
# Rule 2 -- numbered module names
# ---------------------------------------------------------------------------

#: ``NN-topic``: two digits, a hyphen, then a lower-case topic.
_MODULE_NAME = re.compile(r"^\d{2}-[a-z][a-z0-9_]*$")


def test_scenario_modules_are_numbered() -> None:
    """Scenario modules carry a two-digit chronological prefix.

    The number records when the topic was added and, because discovery walks each
    root in sorted order, also fixes the order scenarios run in --
    ``upf_test/scenarios/02-stability.py`` must run last within its root, because it
    can leave the UPF degraded for whatever follows.
    """
    offenders = {
        name: _module_of(cls)
        for name, cls in real_scenarios().items()
        if not _MODULE_NAME.match(_module_of(cls))
    }
    assert not offenders, (
        "scenario modules must be named NN-topic.py so the chronology and run "
        f"order are explicit: {offenders}"
    )


def test_module_numbers_are_unique() -> None:
    """Two modules must not share a prefix, or their relative order is undefined."""
    by_prefix: dict[str, set[str]] = {}
    for cls in real_scenarios().values():
        module = _module_of(cls)
        by_prefix.setdefault(module[:2], set()).add(module)
    clashes = {prefix: sorted(m) for prefix, m in by_prefix.items() if len(m) > 1}
    assert not clashes, f"modules sharing a number: {clashes}"


def test_the_numbers_are_contiguous_from_one() -> None:
    """A gap means a scenario was deleted and its number left behind.

    Not fatal, but it makes "the next free number" ambiguous for whoever adds the
    next scenario, and two people picking differently reintroduces a clash.
    """
    numbers = sorted(int(_module_of(cls)[:2]) for cls in real_scenarios().values())
    assert numbers == list(range(1, len(numbers) + 1)), f"non-contiguous: {numbers}"


# ---------------------------------------------------------------------------
# Rule 3 -- one scenario per module
# ---------------------------------------------------------------------------
def test_each_module_registers_exactly_one_scenario() -> None:
    """The filename names the scenario, so the two must correspond one to one."""
    per_module: dict[str, list[str]] = {}
    for name, cls in real_scenarios().items():
        per_module.setdefault(_module_of(cls), []).append(name)
    crowded = {module: sorted(v) for module, v in per_module.items() if len(v) > 1}
    assert not crowded, (
        "one registered scenario per module, so the directory listing names the "
        f"behaviour rather than a theme: {crowded}"
    )


def test_the_module_name_matches_the_scenario_it_registers() -> None:
    """``NN-topic.py`` and the scenario ``name`` must be recognisably the same thing.

    Deliberately loose -- it accepts an abbreviated filename such as
    ``14-qos_tc_failures.py`` for ``qos_rebuild_tc_failures`` -- because demanding an
    exact match would force either ugly filenames or renamed scenarios, and the point
    is only that someone scanning the directory can find a named scenario. What it
    does catch is a copy-paste that left an unrelated name behind.
    """
    mismatched = {}
    for name, cls in real_scenarios().items():
        topic = _module_of(cls)[3:]
        name_words = set(name.split("_"))
        topic_words = set(topic.split("_"))
        if not (topic_words & name_words):
            mismatched[_module_of(cls)] = name
    assert not mismatched, f"module name shares no word with its scenario: {mismatched}"


# ---------------------------------------------------------------------------
# Rule 3 -- capabilities are declared
# ---------------------------------------------------------------------------
def test_declared_capabilities_are_a_subset_of_what_exists() -> None:
    """A typo'd requirement would skip the scenario forever, silently."""
    from pfcpkit.capabilities import Capability

    for name, cls in real_scenarios().items():
        assert set(cls.requires) <= set(Capability), name


def test_scenarios_declare_the_capabilities_they_use() -> None:
    """A scenario reading state it never declared cannot be skipped cleanly.

    Instead of being skipped on an adapter lacking that capability, it runs and fails
    on state it was never going to be able to read -- which reads as a UPF defect
    rather than as a missing declaration.

    Checked by source text rather than by running anything, so a branch that only
    executes against a broken UPF is covered too. Both access forms count: the
    narrowed ``self.rules`` an :class:`~upf_test.scenarios.base.OaiScenario` uses, and
    ``self.ctx.rules`` for anything reaching the context directly.
    """
    from pfcpkit.capabilities import Capability

    uses = {
        "rules": Capability.RULE_STATE,
        "qos": Capability.QOS_STATE,
        "logs": Capability.LOG_WINDOW,
    }

    package = Path(__file__).resolve().parent.parent / _SHIPPED_ROOT.replace(".", "/")
    sources = {p.stem: p.read_text() for p in package.glob("*.py")}

    for name, cls in real_scenarios().items():
        source = sources.get(_module_of(cls))
        assert source is not None, f"no source found for {name}"
        for attribute, capability in uses.items():
            reads = f"self.ctx.{attribute}." in source or f"self.{attribute}." in source
            if reads:
                assert capability in cls.requires, (
                    f"{name} reads {attribute} state but does not require "
                    f"{capability.name}"
                )
