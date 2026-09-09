# SPDX-License-Identifier: MIT
"""Test doubles shared by the library and adapter unit tests.

:class:`FakeRunner` replays canned command output, which is what lets every
inspector be tested against *captured* output from a live UPF rather than a
mocked-up guess. The fixtures that use it are marked as such where they appear.
"""

from __future__ import annotations

from collections.abc import Sequence

from pfcpkit.inspect.runner import CommandResult, CommandRunner


class FakeRunner(CommandRunner):
    """Replays canned output, matching on a substring of the command."""

    def __init__(self, responses: dict[str, tuple[int, str, str]]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, ...]] = []
        #: Whether each call asked for stderr merged into stdout.
        self.merge_flags: list[bool] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = 15.0,
        merge_stderr: bool = False,
    ) -> CommandResult:
        joined = " ".join(argv)
        self.calls.append(tuple(argv))
        self.merge_flags.append(merge_stderr)
        for needle, (rc, out, err) in self._responses.items():
            if needle in joined:
                return CommandResult(tuple(argv), rc, out, err)
        return CommandResult(tuple(argv), 1, "", f"unexpected command: {joined}")

    def describe(self) -> str:
        return "fake runner"
