# SPDX-License-Identifier: MIT
"""Linux Traffic Control inspection -- HTB classes and qdiscs.

This is how the QoS-rate-change bug becomes visible: the UPF creates one HTB class
per QoS flow with ``rate`` from the QER's GBR and ``ceil`` from its MBR, so a
Session Modification that changes those values must change the class too.

**iproute2 quirk, verified on 5.15.0 in the UPF image:** ``tc -j`` produces JSON
for ``qdisc show`` but *silently ignores* ``-j`` for ``class show``, emitting the
plain-text format instead. Both are therefore parsed, chosen by inspecting the
output rather than by trusting the flag.

That quirk is worth stating plainly because of how it hides: with no classes
configured, ``tc -j class show`` prints nothing and exits 0, so a naive
"does -j work?" probe passes and only starts lying once classes exist.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from ..errors import InspectionError
from .runner import CommandRunner

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


def handle(minor: int, *, major: int = 1) -> str:
    """Render a classid the way ``tc`` prints it -- hex minor, no prefix."""
    return f"{major:x}:{minor:x}"


@dataclass(frozen=True)
class TcClass:
    """One HTB class. ``rate`` and ``ceil`` are in bits per second."""

    handle: str
    kind: str
    parent: str | None
    rate: int | None
    ceil: int | None
    raw: dict[str, Any] | str

    @property
    def minor(self) -> int | None:
        """Minor number of ``major:minor``. tc prints it in hex."""
        _, _, minor = self.handle.partition(":")
        try:
            return int(minor, 16) if minor else None
        except ValueError:
            return None

    @property
    def rate_kbps(self) -> int | None:
        return None if self.rate is None else self.rate // 1000

    @property
    def ceil_kbps(self) -> int | None:
        return None if self.ceil is None else self.ceil // 1000

    def describe(self) -> str:
        return (
            f"{self.handle} ({self.kind}) parent={self.parent} "
            f"rate={self.rate_kbps}kbit ceil={self.ceil_kbps}kbit"
        )


@dataclass(frozen=True)
class TcQdisc:
    """One qdisc attached to an interface."""

    handle: str
    kind: str
    parent: str | None
    raw: dict[str, Any]


class TcInspector:
    """Reads ``tc`` state from inside the UPF's network namespace."""

    def __init__(self, runner: CommandRunner, *, tc: str = "tc") -> None:
        self._runner = runner
        self._tc = tc

    # -- classes -----------------------------------------------------------
    def classes(self, iface: str) -> list[TcClass]:
        """Every class on an interface. An empty list means genuinely none."""
        text = self._show(["class", "show", "dev", iface])
        if not text:
            return []
        if text.lstrip().startswith("["):
            payload = _load_json(text)
            return [_class_from_json(i) for i in payload if isinstance(i, dict)]
        return _classes_from_text(text)

    def class_by_handle(self, iface: str, wanted: str) -> TcClass | None:
        """Find a class by handle, comparing numerically so ``1:a`` == ``1:0a``."""
        target = _normalise_handle(wanted)
        for entry in self.classes(iface):
            if _normalise_handle(entry.handle) == target:
                return entry
        return None

    def class_minors(self, iface: str) -> list[int]:
        """Minor numbers of every class present, sorted."""
        return sorted(c.minor for c in self.classes(iface) if c.minor is not None)

    def rate_ceil(self, iface: str, wanted: str) -> tuple[int, int] | None:
        """``(rate, ceil)`` in bits/sec for one class, or None if absent.

        Bits per second, not kbps -- the ``rate_kbps``/``ceil_kbps`` properties on
        :class:`TcClass` are the kbps view, matching how PFCP expresses GBR/MBR.
        """
        entry = self.class_by_handle(iface, wanted)
        if entry is None or entry.rate is None or entry.ceil is None:
            return None
        return entry.rate, entry.ceil

    # -- qdiscs ------------------------------------------------------------
    def qdiscs(self, iface: str) -> list[TcQdisc]:
        text = self._show(["qdisc", "show", "dev", iface])
        if not text:
            return []
        if not text.lstrip().startswith("["):
            # qdisc show does honour -j on the versions we care about; if that
            # ever changes, say so rather than silently reporting no qdiscs.
            raise InspectionError(
                "`tc -j qdisc show` did not return JSON; a text parser for "
                f"qdiscs would be needed. Output: {text[:200]}"
            )
        return [
            TcQdisc(
                handle=str(item.get("handle", "")),
                kind=str(item.get("kind", "")),
                parent=_optional_str(item.get("parent"))
                or ("root" if item.get("root") else None),
                raw=item,
            )
            for item in _load_json(text)
            if isinstance(item, dict)
        ]

    def has_htb_root(self, iface: str) -> bool:
        """Whether an HTB root qdisc is installed.

        The UPF creates this once per interface and never removes it, so it
        should outlive session teardown -- unlike the per-session classes.
        """
        return any(q.kind == "htb" for q in self.qdiscs(iface))

    # -- internals ---------------------------------------------------------
    def _show(self, args: list[str]) -> str:
        result = self._runner.run([self._tc, "-j", *args])
        if not result.ok:
            stderr = result.stderr.strip()
            raise InspectionError(
                f"`tc {' '.join(args)}` failed in {self._runner.describe()}: {stderr}"
            )
        return result.stdout.strip()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _load_json(text: str) -> list[Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InspectionError(f"could not parse tc JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise InspectionError(f"unexpected tc JSON shape: {type(payload).__name__}")
    return payload


def _class_from_json(item: dict[str, Any]) -> TcClass:
    options = item.get("options")
    options = options if isinstance(options, dict) else {}
    return TcClass(
        handle=str(item.get("handle", "")),
        kind=str(item.get("kind", item.get("class", ""))),
        parent=_optional_str(item.get("parent"))
        or ("root" if item.get("root") else None),
        rate=_coerce_rate(options.get("rate")),
        ceil=_coerce_rate(options.get("ceil")),
        raw=item,
    )


#: One class line, e.g.
#:   class htb 1:bb parent 1:2 prio 0 rate 20Mbit ceil 40Mbit burst 1600b ...
#:   class htb 1:2 root rate 10Gbit ceil 10Gbit burst 1680b cburst 1680b
_CLASS_LINE = re.compile(r"^class\s+(?P<kind>\S+)\s+(?P<handle>\S+)\s+(?P<rest>.*)$")
_PARENT = re.compile(r"\bparent\s+(?P<parent>\S+)")
_RATE = re.compile(r"\brate\s+(?P<rate>\S+)")
_CEIL = re.compile(r"\bceil\s+(?P<ceil>\S+)")


def _classes_from_text(text: str) -> list[TcClass]:
    """Parse the plain-text ``tc class show`` format.

    Needed because iproute2 5.15 ignores ``-j`` for ``class show``.
    """
    classes: list[TcClass] = []
    for line in text.splitlines():
        line = line.strip()
        match = _CLASS_LINE.match(line)
        if not match:
            continue  # continuation/statistics lines
        rest = match.group("rest")
        parent_match = _PARENT.search(rest)
        rate_match = _RATE.search(rest)
        ceil_match = _CEIL.search(rest)
        classes.append(
            TcClass(
                handle=match.group("handle"),
                kind=match.group("kind"),
                parent=parent_match.group("parent")
                if parent_match
                else ("root" if "root" in rest.split() else None),
                rate=_parse_rate(rate_match.group("rate")) if rate_match else None,
                ceil=_parse_rate(ceil_match.group("ceil")) if ceil_match else None,
                raw=line,
            )
        )
    return classes


#: tc rate suffixes. ``*bit`` are bits/sec; ``*bps`` are *bytes*/sec in tc's
#: vocabulary, hence the factor of 8.
_RATE_UNITS: dict[str, int] = {
    "bit": 1,
    "kbit": 1_000,
    "mbit": 1_000_000,
    "gbit": 1_000_000_000,
    "tbit": 1_000_000_000_000,
    "bps": 8,
    "kbps": 8_000,
    "mbps": 8_000_000,
    "gbps": 8_000_000_000,
}

_RATE_TOKEN = re.compile(r"^(?P<value>[0-9]*\.?[0-9]+)(?P<unit>[a-zA-Z]*)$")


def _parse_rate(token: str) -> int | None:
    """Convert a tc rate token such as ``20Mbit`` into bits per second."""
    match = _RATE_TOKEN.match(token.strip())
    if not match:
        return None
    value = float(match.group("value"))
    unit = match.group("unit").lower()
    if not unit:
        return int(value)  # bare number: already bits/sec
    multiplier = _RATE_UNITS.get(unit)
    if multiplier is None:
        logger.debug("unknown tc rate unit %r in %r", unit, token)
        return None
    return int(value * multiplier)


def _coerce_rate(value: Any) -> int | None:
    """Normalise a JSON rate, which may be a number or a string like ``20Mbit``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        return _parse_rate(value)
    return None


def _normalise_handle(text: str) -> tuple[int, int]:
    """Compare handles numerically. tc prints them in hex, so ``1:10`` is 16."""
    major, _, minor = text.partition(":")

    def parse(part: str) -> int:
        part = part.strip() or "0"
        try:
            return int(part, 16)
        except ValueError:
            return -1

    return parse(major), parse(minor)


def _optional_str(value: Any) -> str | None:
    return str(value) if isinstance(value, (str, int)) else None
