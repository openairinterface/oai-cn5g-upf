# SPDX-License-Identifier: MIT
"""An example adapter: the three capability protocols over an in-memory store.

An *adapter* is the only thing a new UPF has to write. It answers the questions in
:mod:`pfcpkit.capabilities` -- "which PDR ids are installed for this session?" -- by
whatever means that UPF offers: reading BPF maps, shelling out to a CLI, calling a
REST endpoint, parsing a log.

This one reads a dict, so the example runs with no UPF at all. A real adapter differs
only in the body of each method; the signatures and the declaration below are the
whole contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..capabilities import Capability

#: What this adapter can observe. Compared against each scenario's ``requires``, so a
#: scenario needing something absent here is skipped and reported rather than run.
#: Declare only what you actually implement -- over-claiming turns a clean skip into a
#: confusing mid-run failure.
CAPABILITIES = frozenset(
    {Capability.RULE_STATE, Capability.QOS_STATE, Capability.LOG_WINDOW}
)

#: Shown in logs and failure messages, so a report says which UPF produced it.
ADAPTER_NAME = "example-upf"


@dataclass
class FakeUpfState:
    """Stand-in for whatever a real adapter reads from.

    A real one holds a command runner, an HTTP session, or a file handle.
    """

    #: seid -> installed PDR ids
    pdrs: dict[int, list[int]] = field(default_factory=dict)
    #: seid -> QFIs with classification state
    qfis: dict[int, list[int]] = field(default_factory=dict)
    #: ue_ipv4 -> owning seid
    ue_owners: dict[str, int] = field(default_factory=dict)
    #: (seid, qfi) -> (rate_kbps, ceil_kbps)
    rates: dict[tuple[int, int], tuple[int, int]] = field(default_factory=dict)
    #: seids with a per-session shaper
    shapers: set[int] = field(default_factory=set)
    #: the UPF's log, newest last
    log: list[str] = field(default_factory=list)


class ExampleRuleState:
    """Implements :class:`~pfcpkit.capabilities.RuleState`.

    Every method returns *what the data plane currently holds*, not what the CP asked
    for. That distinction is the entire point of the interface: a scenario compares the
    two, and a UPF that accepted a request without acting on it is exactly what these
    tests are for.
    """

    def __init__(self, state: FakeUpfState) -> None:
        self._state = state

    def installed_pdr_ids(self, seid: int) -> list[int]:
        return sorted(self._state.pdrs.get(seid, []))

    def installed_qfis(self, seid: int) -> list[int]:
        return sorted(self._state.qfis.get(seid, []))

    def seid_for_ue_ip(self, ue_ipv4: str) -> int | None:
        # `None` means "no session owns this address" -- distinct from owning it with
        # SEID 0, so return None rather than a falsy sentinel.
        return self._state.ue_owners.get(ue_ipv4)

    def session_installed(self, seid: int) -> bool:
        return seid in self._state.pdrs


class ExampleQosState:
    """Implements :class:`~pfcpkit.capabilities.QosState`."""

    def __init__(self, state: FakeUpfState) -> None:
        self._state = state

    def flow_exists(self, seid: int, qfi: int) -> bool:
        return (seid, qfi) in self._state.rates

    def flow_rate_kbps(self, seid: int, qfi: int) -> tuple[int, int] | None:
        # Returning None for "absent" rather than (0, 0) matters: a rate assertion has
        # to tell "no enforcement" from "enforced at zero".
        return self._state.rates.get((seid, qfi))

    def session_shaper_exists(self, seid: int) -> bool:
        return seid in self._state.shapers

    def shaper_root_exists(self) -> bool:
        # Shared by every session, so scenarios asserting that teardown left it alone
        # ask about it separately from per-session state.
        return True


class ExampleLogSource:
    """Implements :class:`~pfcpkit.capabilities.LogSource`.

    The protocol is *windowing* only -- mark a position, then read what arrived after
    it. Which strings mean what belongs to the adapter, as
    :meth:`rebuilds_since` shows.
    """

    def __init__(self, state: FakeUpfState) -> None:
        self._state = state

    def mark(self) -> int:
        """A position in the log.

        Opaque to scenarios: pass it back, do not read it. The protocol types it as
        ``Any`` so an adapter can use whatever it likes -- a line count here, a
        timestamp or a file offset elsewhere.
        """
        return len(self._state.log)

    def find_since(self, mark: int, pattern: str) -> list[str]:
        return [line for line in self._state.log[mark:] if re.search(pattern, line)]

    def count_since(self, mark: int, pattern: str) -> int:
        return len(self.find_since(mark, pattern))

    def stable_count_since(self, mark: int, pattern: str) -> int:
        """Count once the log stops growing.

        Identical to :meth:`count_since` here because this log is a list. Over a real
        one -- ``docker logs``, journald, a file being written -- reads lag the process,
        so an immediate count undercounts. Poll until two consecutive reads agree.
        """
        return self.count_since(mark, pattern)

    def errors_since(self, mark: int, *, ignore: tuple[str, ...] = ()) -> list[str]:
        found = [line for line in self._state.log[mark:] if "[error]" in line]
        return [
            line
            for line in found
            if not any(re.search(pattern, line) for pattern in ignore)
        ]

    # -- Extras beyond the protocol -------------------------------------------
    # Legitimate, and the reason a project subclasses PfcpScenario with its own base
    # exposing these under concrete types. See upf_test/scenarios/base.py.
    def rebuilds_since(self, mark: int, seid: int) -> int:
        """How many times this UPF reprogrammed the datapath for one session."""
        return self.count_since(mark, rf"rebuild session 0x{seid:x}\b")
