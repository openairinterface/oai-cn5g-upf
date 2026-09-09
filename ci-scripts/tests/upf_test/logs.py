# SPDX-License-Identifier: MIT
"""Log patterns specific to the OAI UPF.

Wraps the generic :class:`pfcpkit.inspect.logs.LogInspector` with knowledge of what
this UPF actually prints. The windowing mechanics stay in the library; the strings
are here, because they are true only of this implementation.
"""

from __future__ import annotations

from pfcpkit.inspect.logs import LogInspector, LogMark


class OaiLogs:
    """OAI-specific queries over a windowed log."""

    def __init__(self, inspector: LogInspector) -> None:
        self._logs = inspector

    # -- delegate the generic surface (this is the LogSource capability) ----
    def mark(self) -> LogMark:
        return self._logs.mark()

    def since(self, mark: LogMark) -> list[str]:
        return self._logs.since(mark)

    def find_since(self, mark: LogMark, pattern: str) -> list[str]:
        return self._logs.find_since(mark, pattern)

    def count_since(self, mark: LogMark, pattern: str) -> int:
        return self._logs.count_since(mark, pattern)

    def stable_count_since(self, mark: LogMark, pattern: str) -> int:
        return self._logs.stable_count_since(mark, pattern)

    def errors_since(
        self, mark: LogMark, *, ignore: tuple[str, ...] = ()
    ) -> list[str]:
        return self._logs.errors_since(mark, ignore=ignore)

    # -- OAI-specific patterns --------------------------------------------
    def pipeline_rebuilds_since(self, mark: LogMark, seid: int) -> int:
        """``ModifyPipeline`` invocations for one session, counted immediately.

        Subject to ``docker logs`` lag -- prefer
        :meth:`stable_pipeline_rebuilds_since` when asserting on the count.
        """
        return self._logs.count_since(mark, _modify_pipeline_pattern(seid))

    def stable_pipeline_rebuilds_since(self, mark: LogMark, seid: int) -> int:
        """``ModifyPipeline`` invocations for one session, once the count settles.

        Exactly one is correct per Session Modification Request. More means the
        datapath was rebuilt repeatedly. Two multiplications compound there:
        ``pfcp_switch`` invokes the datapath callback once per removal IE, and each
        removal inside ``ModifySession`` rebuilds again, so the observed count grows
        faster than the removal count alone.
        """
        return self._logs.stable_count_since(mark, _modify_pipeline_pattern(seid))

    def pipeline_creates_since(self, mark: LogMark, seid: int) -> int:
        """``CreatePipeline`` invocations for one session after ``mark``."""
        return self._logs.count_since(
            mark, rf"Create Pipeline - Creating pipeline for session 0x0*{seid:x}\b"
        )

    def qos_setups_since(self, mark: LogMark) -> int:
        """QoS-enforcement setup banners after ``mark``.

        One per ``QERTCProgram::Setup``, so this counts redundant TC rebuilds.
        """
        return self._logs.count_since(mark, r"QoS ENFORCEMENT SETUP")

    def tc_failures_since(self, mark: LogMark) -> list[str]:
        """Failed ``tc`` operations after ``mark``.

        A second ``Setup()`` for the same session re-runs ``tc class add`` for a
        classid that already exists, which fails with "File exists" and leaves the
        old rate in place -- the signature of the QoS-rate-change defect.
        """
        return self._logs.find_since(
            mark,
            r"Failed to create (PDU session class|default class|QoS flow class"
            r"|root qdisc)|COMPLETED WITH WARNINGS",
        )

    def attach_refusals_since(self, mark: LogMark) -> list[str]:
        """Kernel refusals to attach another BPF program.

        Appears once the UPF has accumulated programs it never tore down; measured
        at 22 refusals across 11 modifications of a single session.
        """
        return self._logs.find_since(mark, r"Exclusivity flag on, cannot modify")


def _modify_pipeline_pattern(seid: int) -> str:
    """Regex for the ModifyPipeline entry line of one session.

    The UPF formats the SEID with ``SEID_FMT``; ``0*`` tolerates zero padding so
    the pattern does not depend on that formatting choice.
    """
    return rf"Modify Pipeline - Updating pipeline for session 0x0*{seid:x}\b"
