# SPDX-License-Identifier: MIT
"""What a scenario is allowed to observe, stated independently of how.

Scenarios do not depend on a particular UPF; they depend on what can be observed
about one. Expressing that as a small set of protocols is what lets the same
"removed PDRs must be gone" assertion run against an eBPF data path read with
``bpftool``, a VPP one read over a CLI, or an implementation with nothing but a
REST endpoint.

The abstraction is deliberately **semantic, not storage-shaped**. A method like
``get_map_entries()`` would bake eBPF into the interface and make it useless to
anything else; ``installed_pdr_ids(seid)`` asks the question the test actually
cares about.

Not every UPF can answer every question. Rather than returning ``None`` and
leaving a scenario to half-run, an adapter declares its :class:`Capability` set
and scenarios declare what they require. The runner skips the mismatch **and says
so** -- a silent skip is how a conformance suite quietly stops testing anything.
"""

from __future__ import annotations

from enum import Enum, auto
from typing import Any, Protocol, runtime_checkable


class Capability(Enum):
    """An observation an adapter is able to make."""

    #: PDR/QER rule state per session can be read back.
    RULE_STATE = auto()
    #: Per-flow QoS enforcement state (rates, shaper classes) can be read back.
    QOS_STATE = auto()
    #: The UPF's log can be windowed and searched.
    LOG_WINDOW = auto()

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.name.lower()


@runtime_checkable
class RuleState(Protocol):
    """Session rule state, as the data plane currently holds it."""

    def installed_pdr_ids(self, seid: int) -> list[int]:
        """PDR ids currently installed for a session, sorted."""
        ...

    def installed_qfis(self, seid: int) -> list[int]:
        """QFIs with traffic-classification state for a session, sorted."""
        ...

    def seid_for_ue_ip(self, ue_ipv4: str) -> int | None:
        """Which session currently owns a UE address, if any."""
        ...

    def session_installed(self, seid: int) -> bool:
        """Whether the data plane holds any per-session state at all."""
        ...


@runtime_checkable
class QosState(Protocol):
    """Per-flow QoS enforcement state."""

    def flow_exists(self, seid: int, qfi: int) -> bool:
        """Whether enforcement state exists for one QoS flow."""
        ...

    def flow_rate_kbps(self, seid: int, qfi: int) -> tuple[int, int] | None:
        """``(guaranteed, maximum)`` in kbps for one flow, or None if absent.

        Maps onto the QER's GBR and MBR (TS 29.244 Sections 8.2.8, 8.2.9) however
        the implementation realises them.
        """
        ...

    def session_shaper_exists(self, seid: int) -> bool:
        """Whether a per-session shaping parent exists for the session."""
        ...

    def shaper_root_exists(self) -> bool:
        """Whether the shared shaping root is present.

        Distinct from the per-session state on purpose: the root is shared by
        every session on an interface, so a scenario asserting that session
        teardown left it alone needs to ask about it separately.
        """
        ...


#: An opaque position in the log, produced by :meth:`LogSource.mark` and only ever
#: passed back to the same source.
#:
#: Typed ``Any`` deliberately. A protocol's parameter types are contravariant, so
#: declaring ``mark: object`` would *reject* any adapter whose methods take its own
#: concrete mark type -- which every real adapter's do. Since a scenario never
#: inspects the token, ``Any`` states the contract accurately: pass back what you
#: were given, and do not look inside it.
LogMarker = Any


@runtime_checkable
class LogSource(Protocol):
    """A windowed view of the UPF's log.

    Log *patterns* are implementation-specific and belong in an adapter; the
    windowing mechanics are not, so only the mechanics are abstracted here.
    """

    def mark(self) -> LogMarker:
        """Capture the current end of the log, to bound a later read."""
        ...

    def find_since(self, mark: LogMarker, pattern: str) -> list[str]:
        """Lines after ``mark`` matching a regular expression."""
        ...

    def count_since(self, mark: LogMarker, pattern: str) -> int:
        """How many lines after ``mark`` match, as visible right now."""
        ...

    def stable_count_since(self, mark: LogMarker, pattern: str) -> int:
        """How many lines after ``mark`` match, once the count stops changing."""
        ...

    def errors_since(
        self, mark: LogMarker, *, ignore: tuple[str, ...] = ()
    ) -> list[str]:
        """Error-level lines after ``mark``, minus any matching ``ignore``."""
        ...


class Unsupported:
    """Placeholder an adapter can put in a context field it cannot serve.

    Any attribute access raises, so a scenario that slipped past its ``requires``
    declaration fails loudly instead of quietly receiving an empty result and
    reporting a vacuous pass.
    """

    def __init__(self, capability: Capability, adapter: str) -> None:
        self._capability = capability
        self._adapter = adapter

    def __getattr__(self, item: str) -> object:
        raise NotImplementedError(
            f"{self._adapter} does not provide {self._capability}; "
            f"a scenario reached {item!r} without declaring it in `requires`"
        )
