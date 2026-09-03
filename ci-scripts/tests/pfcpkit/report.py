# SPDX-License-Identifier: MIT
"""Assertion accumulation and reporting.

Checks are recorded rather than raised, so one failed assertion does not hide the
rest of a scenario. That matters here: a single PFCP modification produces BPF
map, ``tc``, and log assertions that fail independently, and seeing all three is
what tells you *which* part of the datapath rebuild broke.

``check`` is soft (record and continue). ``require`` is hard (record, then abort
the scenario) and exists for preconditions where continuing would only produce
misleading cascade failures -- e.g. session establishment failed, so there is
nothing to modify.
"""

from __future__ import annotations

from collections.abc import Container, Sequence
from dataclasses import dataclass
from enum import Enum

from .errors import ScenarioAborted


class Outcome(str, Enum):
    """Result of a single recorded check or note."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    ERROR = "ERROR"
    ABORT = "ABORT"


@dataclass(frozen=True)
class Check:
    """One recorded assertion or note."""

    description: str
    outcome: Outcome
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.outcome is Outcome.PASS

    def render(self) -> str:
        line = f"  [{self.outcome.value:5s}] {self.description}"
        if self.detail:
            line += f"\n           -> {self.detail}"
        return line


class TestReport:
    """Ordered, non-throwing collection of checks for one scenario."""

    #: Stops pytest collecting this as a test class on account of its name.
    __test__ = False

    def __init__(self, name: str) -> None:
        self.name = name
        self.checks: list[Check] = []

    # -- recording ---------------------------------------------------------
    def check(self, description: str, condition: bool, detail: str = "") -> bool:
        """Record a soft assertion. Returns the condition, so it can be chained."""
        self.checks.append(
            Check(
                description,
                Outcome.PASS if condition else Outcome.FAIL,
                "" if condition else detail,
            )
        )
        return condition

    def check_eq(self, description: str, expected: object, actual: object) -> bool:
        return self.check(
            description, expected == actual, f"expected {expected!r}, got {actual!r}"
        )

    def check_count(self, description: str, expected: int, actual: int) -> bool:
        return self.check(
            description,
            expected == actual,
            f"expected {expected} occurrence(s), counted {actual}",
        )

    def check_in(
        self, description: str, needle: object, haystack: Container[object]
    ) -> bool:
        return self.check(
            description, needle in haystack, f"{needle!r} not found in {haystack!r}"
        )

    def check_absent(
        self, description: str, needle: object, haystack: Container[object]
    ) -> bool:
        return self.check(
            description,
            needle not in haystack,
            f"{needle!r} unexpectedly still present in {haystack!r}",
        )

    def require(self, description: str, condition: bool, detail: str = "") -> None:
        """Record a hard precondition; abort the scenario if it failed."""
        if not self.check(description, condition, detail):
            raise ScenarioAborted(f"{description}: {detail}" if detail else description)

    def warn(self, message: str) -> None:
        """Record something noteworthy that is not a failure."""
        self.checks.append(Check(message, Outcome.WARN))

    def error(self, message: str) -> None:
        """Record an unexpected exception. Counts as a failure."""
        self.checks.append(Check(message, Outcome.ERROR))

    def abort(self, message: str) -> None:
        """Record that the scenario stopped early. Counts as a failure."""
        self.checks.append(Check(message, Outcome.ABORT))

    def merge(self, other: TestReport) -> None:
        """Absorb another report's checks (for composite scenarios)."""
        self.checks.extend(other.checks)

    # -- verdict -----------------------------------------------------------
    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.outcome is Outcome.PASS)

    @property
    def failed(self) -> int:
        return sum(
            1
            for c in self.checks
            if c.outcome in (Outcome.FAIL, Outcome.ERROR, Outcome.ABORT)
        )

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.outcome is Outcome.WARN)

    @property
    def ok(self) -> bool:
        """True only if at least one check ran and nothing failed.

        An empty report is *not* a pass -- a scenario that asserted nothing has
        told us nothing.
        """
        return self.failed == 0 and self.passed > 0

    @property
    def verdict(self) -> str:
        if self.failed:
            return "FAIL"
        if not self.passed:
            return "EMPTY"
        return "PASS"

    def render(self) -> str:
        lines = [f"== {self.name}: {self.verdict} =="]
        lines.extend(c.render() for c in self.checks)
        lines.append(
            f"   {self.passed} passed, {self.failed} failed, {self.warnings} warning(s)"
        )
        return "\n".join(lines)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<TestReport {self.name} {self.verdict} {self.passed}P/{self.failed}F>"


class SuiteReport:
    """Aggregate of several scenario reports."""

    def __init__(self) -> None:
        self.reports: list[TestReport] = []

    def add(self, report: TestReport) -> None:
        self.reports.append(report)

    @property
    def ok(self) -> bool:
        return bool(self.reports) and all(r.ok for r in self.reports)

    def render(self) -> str:
        blocks = [r.render() for r in self.reports]
        blocks.append(self.summary())
        return "\n\n".join(blocks)

    def summary(self) -> str:
        width = max((len(r.name) for r in self.reports), default=0)
        lines = ["== suite summary =="]
        for r in self.reports:
            lines.append(
                f"  {r.name:<{width}}  {r.verdict:5s}  "
                f"({r.passed} passed, {r.failed} failed)"
            )
        total_failed = sum(r.failed for r in self.reports)
        lines.append(
            f"  {len(self.reports)} scenario(s), "
            f"{sum(1 for r in self.reports if r.ok)} passed, "
            f"{total_failed} failed check(s) overall"
        )
        return "\n".join(lines)

    def failed_scenarios(self) -> Sequence[str]:
        return [r.name for r in self.reports if not r.ok]
