# SPDX-License-Identifier: MIT
"""Inspection of UPF runtime state: BPF maps, ``tc`` classes, and logs.

This layer answers "what did the UPF actually do to its data path?", which is
what the bug-reproducing scenarios assert on. PFCP responses alone cannot see
any of it.

``subprocess`` is confined to :mod:`pfcpkit.inspect.runner`; everything else
here works on its :class:`CommandResult`. That keeps the inspectors testable
against captured output and lets the execution target change (docker exec, local
shell, later kubectl or ssh) without touching a single assertion.
"""

from __future__ import annotations

from .bpftool import BpfMapInspector, MapEntry
from .logs import LogInspector, LogMark
from .runner import CommandResult, CommandRunner, DockerExecRunner, LocalRunner
from .tc import TcClass, TcInspector

__all__ = [
    "BpfMapInspector",
    "CommandResult",
    "CommandRunner",
    "DockerExecRunner",
    "LocalRunner",
    "LogInspector",
    "LogMark",
    "MapEntry",
    "TcClass",
    "TcInspector",
]
