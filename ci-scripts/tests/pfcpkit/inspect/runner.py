# SPDX-License-Identifier: MIT
"""Pluggable command execution -- the only module here that uses ``subprocess``.

Inspection needs to run ``bpftool`` and ``tc`` *in the UPF's namespaces*, and
``docker logs`` *on the host*. Both go through the same interface so a scenario
never knows or cares which, and so a future target (kubectl exec, ssh) is a new
subclass rather than a change to any assertion.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ..errors import CommandFailed, InspectionError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15.0


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one command invocation."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def check(self) -> CommandResult:
        """Return self, or raise :class:`CommandFailed` with full context."""
        if not self.ok:
            raise CommandFailed(self.argv, self.returncode, self.stderr)
        return self

    def json(self) -> Any:
        """Parse stdout as JSON.

        Raises:
            CommandFailed: the command itself failed.
            InspectionError: it succeeded but did not emit parseable JSON --
                usually a tool built without JSON support, which must be an
                error rather than an empty result. Silently treating it as "no
                entries" would make an absence assertion pass for the wrong
                reason.
        """
        self.check()
        text = self.stdout.strip()
        if not text:
            raise InspectionError(
                f"expected JSON but got empty output from: {' '.join(self.argv)}"
            )
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise InspectionError(
                f"could not parse JSON from: {' '.join(self.argv)}\n"
                f"  error: {exc}\n  output: {text[:400]}"
            ) from exc

    @property
    def lines(self) -> list[str]:
        return self.stdout.splitlines()


class CommandRunner(ABC):
    """Runs a command somewhere and returns its result."""

    @abstractmethod
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        merge_stderr: bool = False,
    ) -> CommandResult:
        """Execute ``argv``. Never raises on a non-zero exit -- see ``check()``.

        ``merge_stderr`` redirects stderr into stdout *at the file-descriptor
        level*, preserving the order the two streams were written in. Essential
        for ``docker logs``: the UPF logs to stdout while libbpf writes to stderr,
        and concatenating the two captures afterwards would place every stderr
        line after every stdout line -- silently destroying chronology and, with
        it, any line-count log window.
        """

    @abstractmethod
    def describe(self) -> str:
        """Short description of where commands land, for error messages."""


class LocalRunner(CommandRunner):
    """Runs commands on this host.

    Used for ``docker logs`` (a host-side operation) and for a UPF running
    natively rather than in a container.
    """

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        merge_stderr: bool = False,
    ) -> CommandResult:
        return _execute(tuple(argv), timeout=timeout, merge_stderr=merge_stderr)

    def describe(self) -> str:
        return "local host"


class DockerExecRunner(CommandRunner):
    """Runs commands inside a container via ``docker exec``.

    This is how ``bpftool`` and ``tc`` reach the UPF's own namespaces. Note that
    BPF maps are *not* pinned to bpffs anywhere in the UPF, so they can only be
    reached from a process in the same namespaces -- which is precisely what this
    provides.
    """

    def __init__(self, container: str, *, docker: str = "docker") -> None:
        self._container = container
        self._docker = docker

    @property
    def container(self) -> str:
        return self._container

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        merge_stderr: bool = False,
    ) -> CommandResult:
        full = (self._docker, "exec", self._container, *argv)
        result = _execute(full, timeout=timeout, merge_stderr=merge_stderr)
        if not result.ok and "is not running" in result.stderr:
            raise InspectionError(
                f"container {self._container!r} is not running -- "
                "bring the environment up with ./setup_env.sh"
            )
        return result

    def describe(self) -> str:
        return f"container {self._container!r}"


def _execute(
    argv: tuple[str, ...], *, timeout: float, merge_stderr: bool = False
) -> CommandResult:
    """Run argv with no shell, an explicit timeout, and no exception on failure."""
    if not argv:
        raise ValueError("argv must not be empty")
    if shutil.which(argv[0]) is None:
        raise InspectionError(f"{argv[0]!r} is not on PATH")

    logger.debug("exec: %s", " ".join(argv))
    try:
        completed = subprocess.run(  # noqa: S603 - list argv, never shell=True
            argv,
            stdout=subprocess.PIPE,
            # Merging at the fd level keeps the two streams in the order they were
            # written; capturing separately and concatenating does not.
            stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandFailed(argv, -1, f"timed out after {timeout}s: {exc}") from exc

    return CommandResult(
        argv=argv,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
