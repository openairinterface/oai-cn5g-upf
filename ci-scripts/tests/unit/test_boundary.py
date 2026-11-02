# SPDX-License-Identifier: MIT
"""Enforces that the adapter actually depends on the library.

``pfcpkit`` now lives in its own repo (openairinterface/pfcp-kit) and is pulled in as an
ordinary dependency, so the direction that used to need enforcing from this side --
the library never reaching into ``upf_test`` -- is no longer something this repo can
even express: ``upf_test`` is not on ``pfcpkit``'s import path at all. What is still
worth checking from here is the direction that *is* expected to hold: this adapter
really does build on the library rather than reimplementing it.
"""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _imported_modules(source: str, filename: str) -> set[str]:
    """Every module name an ``import`` in this file could reach, at any nesting."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source, filename=filename)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def test_the_adapter_is_expected_to_import_the_library() -> None:
    """The dependency is one-way, not absent -- assert the direction that must hold."""
    adapter_imports: set[str] = set()
    for path in sorted((_ROOT / "upf_test").rglob("*.py")):
        adapter_imports |= _imported_modules(path.read_text(), str(path))
    assert any(name.startswith("pfcpkit") for name in adapter_imports)
