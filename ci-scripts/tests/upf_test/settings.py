# SPDX-License-Identifier: MIT
"""Deployment settings specific to the OAI UPF test environment.

Separate from :class:`pfcpkit.config.Settings`, which holds only PFCP addressing
and timing. Everything here is about *how this UPF is deployed and observed* --
which container it runs in, where its ``bpftool`` lives, which interfaces carry N3
and N6. A UPF observed over an HTTP API would need none of it, which is precisely
why it does not belong in the library.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from pfcpkit.errors import ConfigError

_DEFAULTS: Mapping[str, str] = {
    "UPF_CONTAINER": "upf-test",
    "N3_IFACE": "n3",
    "N6_IFACE": "n6",
    "BPFTOOL": "/openair-upf/bin/bpftool",
    "COMMAND_TIMEOUT": "15.0",
}


@dataclass(frozen=True)
class Deployment:
    """Where the UPF under test lives, and how to reach its state."""

    #: Container the UPF runs in. ``bpftool`` and ``tc`` are exec'd inside it --
    #: BPF maps are not pinned anywhere, and ``tc`` is network-namespace scoped, so
    #: both must run in the UPF's own namespaces.
    upf_container: str
    #: Interface QoS classes are attached to.
    n3_iface: str
    #: Interface facing the data network.
    n6_iface: str
    #: Path to bpftool inside the container. The image ships its own.
    bpftool: str
    #: Timeout for a single inspection command.
    command_timeout: float

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Deployment:
        source = os.environ if env is None else env

        def get(key: str) -> str:
            value = source.get(key, _DEFAULTS[key])
            if not value:
                raise ConfigError(f"{key} is set but empty")
            return value

        timeout_raw = get("COMMAND_TIMEOUT")
        try:
            command_timeout = float(timeout_raw)
        except ValueError as exc:
            raise ConfigError(
                f"COMMAND_TIMEOUT={timeout_raw!r} is not a number"
            ) from exc
        if command_timeout <= 0:
            raise ConfigError("COMMAND_TIMEOUT must be > 0")

        return cls(
            upf_container=get("UPF_CONTAINER"),
            n3_iface=get("N3_IFACE"),
            n6_iface=get("N6_IFACE"),
            bpftool=get("BPFTOOL"),
            command_timeout=command_timeout,
        )

    def describe(self) -> str:
        return (
            f"container={self.upf_container} n3={self.n3_iface} n6={self.n6_iface}"
        )
