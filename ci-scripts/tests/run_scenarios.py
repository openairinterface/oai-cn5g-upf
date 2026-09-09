#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Standalone runner for the UPF PFCP integration scenarios.

Needs only Python 3.10+ and scapy -- no pytest -- so it runs in a bare container.

Examples::

    ./run_scenarios.py --list
    ./run_scenarios.py --all
    ./run_scenarios.py --scenario establishment --verbose
    ./run_scenarios.py --tag smoke --junit-xml results.xml

Exit status is 0 only if every selected scenario passed.
"""

from __future__ import annotations

import argparse
import logging
import sys
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from pathlib import Path
from time import monotonic

from pfcpkit.config import Settings
from pfcpkit.errors import ConfigError, UpfTestError
from pfcpkit.report import SuiteReport
from pfcpkit.scenarios import describe_all, partition_by_capability, select
from upf_test.harness import build_context, register_scenarios
from upf_test.inspector import ADAPTER_NAME, CAPABILITIES
from upf_test.settings import Deployment

logger = logging.getLogger("run_scenarios")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    selection = parser.add_argument_group("selection")
    selection.add_argument(
        "--scenario",
        action="append",
        metavar="NAME",
        help="run this scenario (repeatable)",
    )
    selection.add_argument(
        "--tag",
        action="append",
        metavar="TAG",
        help="run every scenario carrying this tag (repeatable)",
    )
    selection.add_argument(
        "--all",
        action="store_true",
        help="run every registered scenario (the default when nothing is selected)",
    )
    selection.add_argument(
        "--list",
        action="store_true",
        help="list the registered scenarios and exit",
    )

    output = parser.add_argument_group("output")
    output.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    output.add_argument(
        "-q", "--quiet", action="store_true", help="warnings and errors only"
    )
    output.add_argument(
        "--junit-xml",
        type=Path,
        metavar="PATH",
        help="also write a JUnit XML report for CI",
    )
    return parser


def configure_logging(*, verbose: bool, quiet: bool) -> None:
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # scapy is noisy about interface enumeration on import.
    logging.getLogger("scapy").setLevel(logging.ERROR)


def run(args: argparse.Namespace) -> int:
    try:
        settings = Settings.from_env()
        deployment = Deployment.from_env()
    except ConfigError as exc:
        logger.error("invalid configuration: %s", exc)
        return 2

    register_scenarios()  # `select` discovers, so the root must be known first

    try:
        scenario_classes = select(names=args.scenario, tags=args.tag)
    except KeyError as exc:
        logger.error("%s", exc.args[0] if exc.args else exc)
        return 2

    if not scenario_classes:
        logger.error("no scenarios selected")
        return 2

    scenario_classes, skipped = partition_by_capability(scenario_classes, CAPABILITIES)
    for cls, missing in skipped:
        # Reported, never silently dropped: a suite that quietly discards what it
        # cannot observe reads exactly like one that passed those scenarios.
        logger.warning(
            "skipping %s: adapter %s does not provide %s",
            cls.name,
            ADAPTER_NAME,
            ", ".join(sorted(c.name for c in missing)),
        )

    if not scenario_classes:
        logger.error("every selected scenario needs a capability this adapter lacks")
        return 2

    logger.info("configuration: %s", settings.describe())
    logger.info("deployment: %s", deployment.describe())
    logger.info(
        "running %d scenario(s): %s",
        len(scenario_classes),
        ", ".join(c.name for c in scenario_classes),
    )

    suite = SuiteReport()
    durations: dict[str, float] = {}
    # Which package a scenario came from, so the JUnit report distinguishes a
    # library conformance failure from an OAI-specific one.
    classnames = {
        cls.name: cls.__module__.rsplit(".", 1)[0] for cls in scenario_classes
    }

    try:
        with build_context(settings, deployment) as ctx:
            for scenario_cls in scenario_classes:
                started = monotonic()
                report = scenario_cls(ctx).execute()
                durations[report.name] = monotonic() - started
                suite.add(report)
                # A scenario may have left sessions behind if teardown failed;
                # clear them so the next scenario starts from a clean UPF.
                ctx.client.delete_all_sessions()
    except UpfTestError as exc:
        # Socket setup, association failure, or another transport-level problem:
        # nothing could run, so this is an environment error (2), not a test
        # failure (1). Keeping them distinct matters in CI.
        logger.error("suite could not run: %s", exc)
        return 2
    except OSError as exc:
        logger.error("suite could not run: %s", exc)
        return 2
    except KeyboardInterrupt:
        logger.warning("interrupted")
        return 130

    print()  # noqa: T201 - report output is the point of this tool
    print(suite.render())  # noqa: T201

    if args.junit_xml:
        write_junit(args.junit_xml, suite, durations, classnames)
        logger.info("wrote JUnit XML to %s", args.junit_xml)

    failed = suite.failed_scenarios()
    if failed:
        logger.error("failed scenario(s): %s", ", ".join(failed))
        return 1
    return 0


def write_junit(
    path: Path,
    suite: SuiteReport,
    durations: dict[str, float],
    classnames: dict[str, str] | None = None,
) -> None:
    """Emit a minimal JUnit XML document for CI dashboards."""
    testsuite = ET.Element(
        "testsuite",
        name="upf-pfcp-integration",
        tests=str(len(suite.reports)),
        failures=str(sum(1 for r in suite.reports if not r.ok)),
    )
    for report in suite.reports:
        case = ET.SubElement(
            testsuite,
            "testcase",
            classname=(classnames or {}).get(report.name, "pfcpkit.scenarios"),
            name=report.name,
            time=f"{durations.get(report.name, 0.0):.3f}",
        )
        if not report.ok:
            failure = ET.SubElement(
                case,
                "failure",
                message=f"{report.failed} check(s) failed",
            )
            failure.text = report.render()

    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(testsuite).write(path, encoding="utf-8", xml_declaration=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(verbose=args.verbose, quiet=args.quiet)

    register_scenarios()

    if args.list:
        print("Registered scenarios:")  # noqa: T201
        print(describe_all())  # noqa: T201
        return 0

    return run(args)


if __name__ == "__main__":
    sys.exit(main())
