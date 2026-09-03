# SPDX-License-Identifier: MIT
"""Per-session state tracked by the test client.

Capturing the **UP F-SEID** from the Session Establishment Response is what makes
modification and deletion testing possible at all: those messages address the
session by the UP-assigned SEID in the PFCP header. The reference tooling this
suite replaces discarded responses entirely, which is precisely why it could only
ever establish sessions.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from ..models import SessionSpec


@dataclass
class SessionContext:
    """Live state for one PFCP session.

    Mutable by design -- it accumulates knowledge as the session progresses
    (UP SEID from the establishment response, UPF-allocated TEIDs, whether the
    session is still active).
    """

    cp_seid: int
    spec: SessionSpec
    up_seid: int | None = None
    #: PDR id -> F-TEID reported in a Created PDR IE.
    #:
    #: Deliberately *not* called "allocated": this UPF emits a Created PDR for
    #: every PDR with an F-TEID, so for CH=0 the value is an **echo** of the TEID
    #: we supplied, and only for CH=1 is it a fresh UPF allocation. (TS 29.244
    #: §7.5.3.2 asks for the IE only when the UP function allocated one, so the
    #: echo is a harmless liberty -- but assuming otherwise produces wrong
    #: assertions.)
    reported_teids: dict[int, int] = field(default_factory=dict)
    active: bool = True
    #: Number of Session Modification Requests accepted for this session.
    modifications: int = 0

    @property
    def ue_ipv4(self) -> str:
        return self.spec.ue_ipv4

    @property
    def addressable(self) -> bool:
        """True once the UPF has told us the SEID to address it by."""
        return self.up_seid is not None

    def require_up_seid(self) -> int:
        """UP SEID, or a clear error explaining why we cannot proceed."""
        if self.up_seid is None:
            raise ValueError(
                f"session cp_seid=0x{self.cp_seid:x} has no UP F-SEID: the "
                "establishment response was missing or rejected, so it cannot "
                "be modified or deleted"
            )
        return self.up_seid

    def describe(self) -> str:
        up = "unset" if self.up_seid is None else f"0x{self.up_seid:x}"
        return (
            f"session cp=0x{self.cp_seid:x} up={up} ue={self.ue_ipv4} "
            f"{'active' if self.active else 'deleted'}"
        )


class SeidAllocator:
    """Allocates unique CP F-SEIDs for this run.

    Seeded from a configurable base (PID-derived by default) so concurrent runs,
    and reruns against a UPF still holding stale sessions, never collide -- while
    staying small and readable in logs, unlike a random 64-bit value.
    """

    def __init__(self, base: int) -> None:
        self._base = base
        self._counter = itertools.count(1)

    def next(self) -> int:
        return self._base + next(self._counter)
