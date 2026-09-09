# SPDX-License-Identifier: MIT
"""Exception hierarchy for the UPF integration test suite.

Every failure mode gets a specific type carrying enough context to diagnose it
without re-running. In particular there is no code path that swallows an error
and returns a sentinel: a silently-ignored failure in a *test* suite reads as a
pass, which is the worst possible outcome.
"""

from __future__ import annotations


class UpfTestError(Exception):
    """Base class for every error raised by this suite."""


# ---------------------------------------------------------------------------
# PFCP / N4
# ---------------------------------------------------------------------------
class PfcpError(UpfTestError):
    """Base class for PFCP protocol and transport failures."""


class TransportError(PfcpError):
    """The PFCP socket could not be set up.

    Almost always one of two things: another PFCP entity already holds the port
    (8805 is used for both source and destination, so a local SMF/UPF or a
    leftover container will occupy it), or the port needs privileges. Both are
    worth naming explicitly, because the raw ``OSError`` reads as an internal
    fault rather than an environment problem.
    """


class PfcpTimeout(PfcpError):
    """No response correlated to a request before the retry budget ran out."""

    def __init__(
        self, message_type: str, seq: int, attempts: int, timeout: float
    ) -> None:
        super().__init__(
            f"no response to {message_type} (seq={seq}) "
            f"after {attempts} attempt(s) at {timeout:.1f}s each"
        )
        self.message_type = message_type
        self.seq = seq
        self.attempts = attempts
        self.timeout = timeout


class PfcpRejected(PfcpError):
    """The UPF answered, but with a Cause other than "Request accepted"."""

    def __init__(self, message_type: str, cause: int | None, cause_name: str) -> None:
        super().__init__(
            f"{message_type} rejected by the UPF: cause={cause} ({cause_name})"
        )
        self.message_type = message_type
        self.cause = cause
        self.cause_name = cause_name


class PfcpDecodeError(PfcpError):
    """A response arrived but could not be decoded, or lacked a mandatory IE."""


# ---------------------------------------------------------------------------
# Datapath inspection (used by the forthcoming inspect/ package)
# ---------------------------------------------------------------------------
class InspectionError(UpfTestError):
    """Base class for failures while inspecting UPF runtime state."""


class CommandFailed(InspectionError):
    """A command run against the UPF exited non-zero or timed out."""

    def __init__(self, argv: tuple[str, ...], returncode: int, stderr: str) -> None:
        super().__init__(
            f"command failed (exit {returncode}): {' '.join(argv)}\n{stderr.strip()}"
        )
        self.argv = argv
        self.returncode = returncode
        self.stderr = stderr


class MapNotFound(InspectionError):
    """A BPF map was expected to exist but bpftool could not find it."""


# ---------------------------------------------------------------------------
# Scenario control flow
# ---------------------------------------------------------------------------
class ScenarioAborted(UpfTestError):
    """A precondition failed, so the rest of the scenario cannot be meaningful.

    Raised by ``TestReport.require``. Caught by ``PfcpScenario.execute``, which
    records it on the report and still runs teardown -- it is control flow, not
    a crash.
    """


class ConfigError(UpfTestError):
    """Settings could not be built from the environment."""
