# SPDX-License-Identifier: MIT
"""A library for driving a UPF over N4/PFCP and asserting on what it did.

**Start with [`README.md`](README.md)** -- how to write scenarios, build an adapter for
a new UPF, and the conventions worth adopting. [`examples/`](examples/) is a complete
worked version, runnable without a UPF.

Ships no scenarios of its own: it supplies the machinery, a project supplies what is
specific to its UPF. In this repo that project is :mod:`upf_test`.

The package is layered, with dependencies pointing strictly downward:

    scenarios/      PfcpScenario base, registry, capability-typed context.
                    No scapy, no sockets, no subprocess.
    capabilities    protocols for observing UPF state, so a scenario names the
                    question rather than the storage
    pfcp/client     PfcpClient facade (associate / establish / modify / delete)
    inspect/        generic mechanics for shelling out: bpftool, tc, log windowing
    pfcp/transport  socket, sequence correlation, retries, heartbeats
    pfcp/codec      spec dataclasses <-> scapy IE trees
    config, errors, report, models, presets, waiting

Boundaries worth preserving:
  * ``scapy`` is imported only by ``pfcp.codec`` and ``pfcp.transport``.
  * ``socket`` is imported only by ``pfcp.transport``.
  * ``subprocess`` is imported only by ``inspect.runner``.
  * environment variables are read only by ``config``.
  * nothing here imports a project-specific package -- enforced by
    ``unit/test_boundary.py``.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
