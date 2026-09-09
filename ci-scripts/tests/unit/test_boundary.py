# SPDX-License-Identifier: MIT
"""Enforces the one-way dependency between the library and the adapter.

``upf_test`` may import ``pfcpkit`` freely. ``pfcpkit`` must never import
``upf_test`` -- not once, not in a function body, not in a docstring example that
someone later copies. The whole value of the split is that another project can take
``pfcpkit`` and supply its own adapter and scenarios; a single import in the wrong
direction silently destroys that while every test still passes.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_LIBRARY = _ROOT / "pfcpkit"

#: Packages the library is not allowed to reach into.
_FORBIDDEN = ("upf_test",)


def _imported_modules(source: str, filename: str) -> set[str]:
    """Every module name an ``import`` in this file could reach, at any nesting."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source, filename=filename)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def _library_sources() -> list[Path]:
    return sorted(_LIBRARY.rglob("*.py"))


def test_the_library_has_sources_to_check() -> None:
    """Guards against the check passing because it found nothing."""
    assert len(_library_sources()) > 10


@pytest.mark.parametrize("path", _library_sources(), ids=lambda p: p.name)
def test_the_library_never_imports_the_adapter(path: Path) -> None:
    imported = _imported_modules(path.read_text(), str(path))
    offending = sorted(
        name
        for name in imported
        for forbidden in _FORBIDDEN
        if name == forbidden or name.startswith(f"{forbidden}.")
    )
    assert not offending, (
        f"{path.relative_to(_ROOT)} imports {', '.join(offending)}; the library must "
        "stay usable without this project's adapter"
    )


def test_the_adapter_is_expected_to_import_the_library() -> None:
    """The dependency is one-way, not absent -- assert the direction that must hold."""
    adapter_imports: set[str] = set()
    for path in sorted((_ROOT / "upf_test").rglob("*.py")):
        adapter_imports |= _imported_modules(path.read_text(), str(path))
    assert any(name.startswith("pfcpkit") for name in adapter_imports)


def _has_register_decorator(source: str, filename: str) -> bool:
    """Whether any class in this file is decorated with ``@register``.

    Parsed rather than grepped. A substring search for ``@register`` also matches
    prose -- ``pfcpkit/examples/`` discusses the decorator at length without using it --
    which made an earlier version of this test fail for the wrong reason.
    """
    for node in ast.walk(ast.parse(source, filename=filename)):
        if not isinstance(node, ast.ClassDef):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = getattr(target, "id", None) or getattr(target, "attr", None)
            if name == "register":
                return True
    return False


def test_the_library_registers_no_scenarios() -> None:
    """A companion to the import rule, aimed at the same failure.

    The library shipped a ``conformance`` package for a while. It is gone by choice, and
    if it came back every consuming project would silently inherit it -- including
    scenarios that skip themselves on that project's adapter, which is
    indistinguishable from passing.

    ``pfcpkit/examples/`` is the deliberate exception in spirit but not in fact: it
    defines scenario *classes* as documentation, and registers them only when
    :func:`pfcpkit.examples.register_examples` is called explicitly. Nothing is
    decorated, so importing the package adds nothing to the registry and ``--all``
    never sees it -- which is what this test checks.
    """
    assert not (_LIBRARY / "conformance").exists()

    registered = [
        path
        for path in _library_sources()
        if _has_register_decorator(path.read_text(), str(path))
    ]
    assert not registered, (
        "pfcpkit must define the scenario machinery, not scenarios: "
        f"{[str(p.relative_to(_ROOT)) for p in registered]}"
    )


def test_importing_the_examples_registers_nothing() -> None:
    """The stronger form of the rule above: checked by behaviour, not by source.

    A project that imports anything from ``pfcpkit`` must not acquire scenarios as a
    side effect. Parsing decorators would miss a module-level ``register(...)`` call.
    """
    import pfcpkit.examples  # noqa: F401 - the import IS the thing under test
    from pfcpkit.scenarios import discover

    leaked = [name for name in discover() if name.startswith("example_")]
    assert not leaked, f"importing pfcpkit.examples registered {leaked}"
