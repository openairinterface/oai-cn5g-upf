# SPDX-License-Identifier: MIT
"""Unit tests for :mod:`pfcpkit` -- the reusable, UPF-agnostic half.

These must pass without any OAI-specific module being importable, which is what
the boundary test in :mod:`unit.test_boundary` enforces. A project vendoring
``pfcpkit`` can take this directory along with it unchanged.
"""
