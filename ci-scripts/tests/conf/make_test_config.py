#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate the UPF test config from the repository's ``etc/config.yaml``.

Deriving it rather than committing a copy that silently
drifts from the real config every time upstream adds a field. Only the handful of
keys the integration suite depends on are overridden:

  * ``log_level.general: debug`` -- the ``[eBPF] Modify Pipeline`` lines the
    rebuild-count assertion needs are INFO, but debug additionally makes
    ``pfcp_switch::to_string()`` dump the full post-modification rule table,
    which is the richest state assertion available without eBPF inspection.
  * ``upf.support_features.enable_bpf_datapath: true`` -- otherwise the legacy
    simpleswitch datapath runs and there are no BPF maps to inspect at all.
  * ``upf.support_features.enable_qos: true`` -- gates QER/HTB handling.
  * ``register_nf.general: false`` -- there is no NRF in the test topology, so
    leaving registration on just produces retry noise in the logs the assertions
    have to read past.
  * ``upf.remote_n6_gw`` -- upstream names the container ``oai-ext-dn``, which
    does not exist here. The UPF resolves this at startup and an unresolvable
    value is fatal (an unhandled ``std::runtime_error`` after four retries), so
    it is pointed at the N6 bridge gateway, which really is the route out.
  * **every** ``interface_name`` under ``nfs.upf`` -- not just n3/n4/n6.
    ``upf::validate()`` calls ``nf::validate()`` (which validates ``sbi``)

Comments are lost in the round trip, which is fine for a generated artifact.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit(
        "PyYAML is required to generate the test config:\n"
        "    pip install -r requirements-dev.txt"
    )

REPO_CONFIG = Path(__file__).resolve().parents[3] / "etc" / "config.yaml"


def _set(node: dict[str, Any], path: str, value: object) -> None:
    """Set a dotted path, failing loudly if the structure is not as expected.

    A missing key means upstream restructured the config, which is worth an
    explicit error -- silently adding the key would produce a config the UPF
    ignores, and the suite would then fail for an unrelated-looking reason.
    """
    parts = path.split(".")
    cursor: Any = node
    for part in parts[:-1]:
        if not isinstance(cursor, dict) or part not in cursor:
            raise KeyError(
                f"{path!r}: {part!r} is missing from the source config -- "
                "etc/config.yaml has been restructured, update this script"
            )
        cursor = cursor[part]
    if not isinstance(cursor, dict):
        raise KeyError(f"{path!r} does not address a mapping")
    cursor[parts[-1]] = value


def _remap_interfaces(
    config: dict[str, Any], *, n3_iface: str, n4_iface: str, n6_iface: str
) -> list[str]:
    """Point every ``nfs.upf.*.interface_name`` at an interface that exists.

    Returns notes describing what was remapped.
    """
    upf = config.get("nfs", {}).get("upf")
    if not isinstance(upf, dict):
        raise KeyError("nfs.upf is missing from the source config")

    # sbi shares N4 (as upstream does -- both are demo-oai there); n9 shares N3,
    # since both carry GTP-U and this topology has no separate N9 network.
    mapping = {
        "n3": n3_iface,
        "n4": n4_iface,
        "n6": n6_iface,
        "sbi": n4_iface,
        "n9": n3_iface,
    }

    notes: list[str] = []
    for key, section in upf.items():
        if not isinstance(section, dict) or "interface_name" not in section:
            continue
        target = mapping.get(key)
        if target is None:
            # Unknown interface: fall back to N4 but say so, rather than leaving
            # a name that would fail validation or silently binding the wrong one.
            target = n4_iface
            notes.append(f"{key}: unmapped, defaulted to {target} (review this)")
        else:
            notes.append(f"{key}: {section['interface_name']} -> {target}")
        section["interface_name"] = target
    return notes


def build(
    source: Path,
    *,
    n3_iface: str,
    n4_iface: str,
    n6_iface: str,
    n6_gateway: str,
    log_level: str = "debug",
) -> tuple[dict[str, Any], list[str]]:
    with source.open(encoding="utf-8") as handle:
        config: dict[str, Any] = yaml.safe_load(handle)

    _set(config, "log_level.general", log_level)
    _set(config, "register_nf.general", False)
    _set(config, "upf.support_features.enable_bpf_datapath", True)
    _set(config, "upf.support_features.enable_qos", True)
    _set(config, "upf.remote_n6_gw", n6_gateway)
    notes = _remap_interfaces(
        config, n3_iface=n3_iface, n4_iface=n4_iface, n6_iface=n6_iface
    )
    return config, notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, default=REPO_CONFIG, help="source etc/config.yaml"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).with_name("upf_test.yaml"),
        help="where to write the generated config",
    )
    # Defaults match `interface_name` in docker-compose.yaml.
    parser.add_argument("--n3-iface", default="n3")
    parser.add_argument("--n4-iface", default="n4")
    parser.add_argument("--n6-iface", default="n6")
    # Gateway of the n6 /26 subnet in docker-compose.yaml (note: .129, not .1).
    parser.add_argument("--n6-gateway", default="192.168.73.129")
    parser.add_argument("--log-level", default="debug")
    args = parser.parse_args(argv)

    if not args.source.is_file():
        parser.error(f"source config not found: {args.source}")

    try:
        config, notes = build(
            args.source,
            n3_iface=args.n3_iface,
            n4_iface=args.n4_iface,
            n6_iface=args.n6_iface,
            n6_gateway=args.n6_gateway,
            log_level=args.log_level,
        )
    except KeyError as exc:
        parser.error(str(exc))

    header_lines = [
        # Derived from etc/config.yaml, which carries the same identifier. Emitted so
        # the generated file is not the one thing in the tree without a licence header.
        "# SPDX-License-Identifier: MIT",
        "# GENERATED by ci-scripts/tests/conf/make_test_config.py -- do not edit.",
        f"# Source: {args.source}",
        f"# Overrides: log_level.general={args.log_level}, register_nf=false,",
        "#            enable_bpf_datapath=true, enable_qos=true,",
        f"#            remote_n6_gw={args.n6_gateway}",
        "# Interface remapping:",
        *(f"#            {note}" for note in notes),
    ]
    with args.output.open("w", encoding="utf-8") as handle:
        handle.write("\n".join(header_lines) + "\n")
        yaml.safe_dump(config, handle, sort_keys=False, default_flow_style=False)

    print(f"wrote {args.output}")  # noqa: T201
    for note in notes:
        print(f"  interface {note}")  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(main())
