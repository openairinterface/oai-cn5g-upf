# SPDX-License-Identifier: MIT
"""Generic suite configuration -- PFCP addressing and timing.

All configuration comes from environment variables with defaults matching
``ci-scripts/tests/docker-compose.yaml``, so a default checkout runs against the
default topology with no arguments.

``from_env`` takes the mapping as a parameter rather than reading ``os.environ``
directly, which keeps it unit-testable.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from .errors import ConfigError

_DEFAULTS: Mapping[str, str] = {
    # --- N4 / PFCP ---------------------------------------------------------
    "UPF_N4_ADDR": "192.168.70.134",
    "CP_NODE_ID": "192.168.70.140",
    "PFCP_PORT": "8805",
    "PFCP_BIND_ADDR": "0.0.0.0",
    "PFCP_BIND_PORT": "8805",
    # --- user plane --------------------------------------------------------
    "UPF_N3_ADDR": "192.168.72.134",
    "GNB_N3_ADDR": "192.168.72.141",
    "UE_IPV4_BASE": "12.1.1.2",
    "NETWORK_INSTANCE": "internet",
    "APN_DNN": "internet",
    # --- timing -----------------------------------------------------------
    "RESPONSE_TIMEOUT": "3.0",
    "REQUEST_RETRIES": "2",
    "SETTLE_TIMEOUT": "5.0",
}


@dataclass(frozen=True)
class Settings:
    """Immutable suite configuration.

    Frozen so it can be shared freely across scenarios and threads without any
    risk of one scenario mutating another's view of the world.
    """

    # N4 / PFCP
    upf_n4_addr: str
    cp_node_id: str
    pfcp_port: int
    pfcp_bind_addr: str
    pfcp_bind_port: int

    # user plane
    upf_n3_addr: str
    gnb_n3_addr: str
    ue_ipv4_base: str
    network_instance: str
    apn_dnn: str

    # timing
    response_timeout: float
    request_retries: int
    settle_timeout: float

    # Base value for locally-allocated CP SEIDs. Derived from the PID by default
    # so concurrent runs (and reruns against a UPF holding stale state) never
    # collide, while staying readable in logs.
    seid_base: int = field(default_factory=lambda: (os.getpid() & 0xFFFF) << 32)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        """Build settings from ``env`` (defaults to ``os.environ``)."""
        source = os.environ if env is None else env

        def get(key: str) -> str:
            value = source.get(key, _DEFAULTS[key])
            if not value:
                raise ConfigError(f"{key} is set but empty")
            return value

        def get_int(key: str) -> int:
            raw = get(key)
            try:
                return int(raw)
            except ValueError as exc:
                raise ConfigError(f"{key}={raw!r} is not an integer") from exc

        def get_float(key: str) -> float:
            raw = get(key)
            try:
                return float(raw)
            except ValueError as exc:
                raise ConfigError(f"{key}={raw!r} is not a number") from exc

        settings = cls(
            upf_n4_addr=get("UPF_N4_ADDR"),
            cp_node_id=get("CP_NODE_ID"),
            pfcp_port=get_int("PFCP_PORT"),
            pfcp_bind_addr=get("PFCP_BIND_ADDR"),
            pfcp_bind_port=get_int("PFCP_BIND_PORT"),
            upf_n3_addr=get("UPF_N3_ADDR"),
            gnb_n3_addr=get("GNB_N3_ADDR"),
            ue_ipv4_base=get("UE_IPV4_BASE"),
            network_instance=get("NETWORK_INSTANCE"),
            apn_dnn=get("APN_DNN"),
            response_timeout=get_float("RESPONSE_TIMEOUT"),
            request_retries=get_int("REQUEST_RETRIES"),
            settle_timeout=get_float("SETTLE_TIMEOUT"),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        """Reject values that would fail confusingly much later."""
        if self.request_retries < 1:
            raise ConfigError("REQUEST_RETRIES must be >= 1")
        if self.response_timeout <= 0:
            raise ConfigError("RESPONSE_TIMEOUT must be > 0")
        if not 0 < self.pfcp_port < 65536:
            raise ConfigError(f"PFCP_PORT out of range: {self.pfcp_port}")
        if not 0 < self.pfcp_bind_port < 65536:
            raise ConfigError(f"PFCP_BIND_PORT out of range: {self.pfcp_bind_port}")

    def describe(self) -> str:
        """One-line summary for run logs."""
        return (
            f"N4 {self.cp_node_id} -> {self.upf_n4_addr}:{self.pfcp_port} | "
            f"N3 upf={self.upf_n3_addr} gnb={self.gnb_n3_addr} | "
            f"ue_base={self.ue_ipv4_base}"
        )
