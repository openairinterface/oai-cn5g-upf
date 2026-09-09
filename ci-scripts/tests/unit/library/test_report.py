# SPDX-License-Identifier: MIT
"""Tests for the reporting and scenario-registry machinery."""

from __future__ import annotations

import pytest

from pfcpkit.errors import ScenarioAborted
from pfcpkit.report import Outcome, SuiteReport, TestReport


# ---------------------------------------------------------------------------
# TestReport
# ---------------------------------------------------------------------------
def test_check_records_and_returns_the_condition() -> None:
    report = TestReport("demo")
    assert report.check("a truth", True) is True
    assert report.check("a falsehood", False, "detail") is False
    assert (report.passed, report.failed) == (1, 1)
    assert not report.ok


def test_a_report_with_only_passes_is_ok() -> None:
    report = TestReport("demo")
    report.check("fine", True)
    assert report.ok
    assert report.verdict == "PASS"


def test_an_empty_report_is_not_ok() -> None:
    """A scenario that asserted nothing has told us nothing."""
    report = TestReport("demo")
    assert not report.ok
    assert report.verdict == "EMPTY"


def test_check_eq_detail_shows_both_values() -> None:
    report = TestReport("demo")
    report.check_eq("counts match", 1, 5)
    assert "expected 1" in report.checks[0].detail
    assert "got 5" in report.checks[0].detail


def test_check_count_reports_occurrences() -> None:
    report = TestReport("demo")
    report.check_count("rebuilt once", 1, 5)
    assert "counted 5" in report.checks[0].detail


def test_check_absent_passes_when_missing() -> None:
    report = TestReport("demo")
    assert report.check_absent("pdr 3 is gone", 3, [1, 2])
    assert not report.check_absent("pdr 1 is gone", 1, [1, 2])


def test_require_raises_and_still_records() -> None:
    report = TestReport("demo")
    with pytest.raises(ScenarioAborted):
        report.require("session established", False, "no F-SEID")
    assert report.failed == 1
    assert report.checks[0].outcome is Outcome.FAIL


def test_require_is_silent_when_satisfied() -> None:
    report = TestReport("demo")
    report.require("session established", True)
    assert report.ok


def test_warnings_do_not_fail_a_report() -> None:
    report = TestReport("demo")
    report.check("fine", True)
    report.warn("teardown was untidy")
    assert report.ok
    assert report.warnings == 1


def test_error_and_abort_count_as_failures() -> None:
    errored = TestReport("errored")
    errored.check("fine", True)
    errored.error("unhandled ValueError")
    assert not errored.ok

    aborted = TestReport("aborted")
    aborted.check("fine", True)
    aborted.abort("precondition failed")
    assert not aborted.ok


def test_merge_absorbs_checks() -> None:
    a, b = TestReport("a"), TestReport("b")
    a.check("one", True)
    b.check("two", False)
    a.merge(b)
    assert (a.passed, a.failed) == (1, 1)


def test_render_includes_verdict_and_details() -> None:
    report = TestReport("demo")
    report.check("this failed", False, "because reasons")
    rendered = report.render()
    assert "demo: FAIL" in rendered
    assert "this failed" in rendered
    assert "because reasons" in rendered


# ---------------------------------------------------------------------------
# SuiteReport
# ---------------------------------------------------------------------------
def test_suite_is_ok_only_when_every_report_is() -> None:
    suite = SuiteReport()
    good = TestReport("good")
    good.check("fine", True)
    suite.add(good)
    assert suite.ok

    bad = TestReport("bad")
    bad.check("broken", False)
    suite.add(bad)
    assert not suite.ok
    assert suite.failed_scenarios() == ["bad"]


def test_an_empty_suite_is_not_ok() -> None:
    assert not SuiteReport().ok


def test_suite_summary_lists_every_scenario() -> None:
    suite = SuiteReport()
    for name in ("alpha", "beta"):
        report = TestReport(name)
        report.check("fine", True)
        suite.add(report)
    summary = suite.summary()
    assert "alpha" in summary
    assert "beta" in summary
    assert "2 scenario(s)" in summary
