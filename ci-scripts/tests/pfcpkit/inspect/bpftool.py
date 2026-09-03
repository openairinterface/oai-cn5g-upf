# SPDX-License-Identifier: MIT
"""BPF map inspection via ``bpftool``.

No map in the UPF is pinned to bpffs, but ``bpftool map dump name <name>`` finds
maps by name globally, so running it inside the UPF container works with no
production change. Names must be the kernel-truncated form -- see
:mod:`pfcpkit.inspect.layouts`.

Output handling accepts both shapes bpftool can emit:

* **BTF present** (this UPF): keys and values arrive already decoded, as JSON
  scalars or objects. Preferred whenever available.
* **No BTF**: keys and values arrive as arrays of byte strings, decoded here with
  the explicit ``struct`` layouts.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from ..errors import InspectionError, MapNotFound
from .layouts import MapCatalogue, MapSpec, StructLayout, bpf_name, spec_for
from .runner import CommandRunner

logger = logging.getLogger(__name__)

DEFAULT_BPFTOOL = "bpftool"  # adapters pass the real path

#: Decoded key or value: a scalar, a field mapping, or undecoded bytes.
Decoded = int | dict[str, int] | bytes | None


@dataclass(frozen=True)
class MapEntry:
    """One key/value pair from a map dump."""

    key: Decoded
    value: Decoded
    raw: dict[str, Any]

    def key_field(self, name: str) -> int | None:
        return self.key.get(name) if isinstance(self.key, dict) else None

    def value_field(self, name: str) -> int | None:
        return self.value.get(name) if isinstance(self.value, dict) else None

    def describe(self) -> str:
        return f"key={_render(self.key)} value={_render(self.value)}"


class BpfMapInspector:
    """Reads the UPF's BPF maps.

    Scenarios pass *logical* map names (``rules_match_pdr_map``); truncation to
    the kernel-reported form happens here, so no assertion has to know about
    ``BPF_OBJ_NAME_LEN``.
    """

    def __init__(
        self,
        runner: CommandRunner,
        catalogue: MapCatalogue,
        *,
        bpftool: str = DEFAULT_BPFTOOL,
    ) -> None:
        self._runner = runner
        self._catalogue = catalogue
        self._bpftool = bpftool

    # -- raw access --------------------------------------------------------
    def list_map_names(self) -> list[str]:
        """Every map name currently loaded, as the kernel reports it."""
        result = self._runner.run([self._bpftool, "--json", "map", "show"]).check()
        payload = result.json()
        if not isinstance(payload, list):
            raise InspectionError("unexpected 'bpftool map show' output")
        return [str(m.get("name", "")) for m in payload if isinstance(m, dict)]

    def map_exists(self, logical_name: str) -> bool:
        return bpf_name(logical_name) in self.list_map_names()

    def dump(self, logical_name: str) -> list[MapEntry]:
        """Dump a map, decoding keys and values as far as the spec allows.

        Raises:
            MapNotFound: bpftool could not find the map. Treated as an error
                rather than an empty dump, because "no entries" and "no map" mean
                very different things and conflating them would let a pruning
                assertion pass against a UPF with no data path at all.
        """
        spec = spec_for(self._catalogue, logical_name)
        result = self._runner.run(
            [self._bpftool, "--json", "map", "dump", "name", spec.name]
        )
        if not result.ok:
            stderr = result.stderr.strip()
            if "not found" in stderr.lower() or "no such" in stderr.lower():
                raise MapNotFound(
                    f"bpftool found no map named {spec.name!r} "
                    f"(logical {logical_name!r}) in {self._runner.describe()}"
                )
            result.check()

        payload = result.json()
        if isinstance(payload, dict):
            # Some bpftool versions wrap multi-map results.
            payload = payload.get("entries", [])
        if not isinstance(payload, list):
            raise InspectionError(
                f"unexpected dump output for {spec.name!r}: {type(payload).__name__}"
            )

        return [
            self._decode_entry(entry, spec)
            for entry in payload
            if isinstance(entry, dict)
        ]

    # -- SEID-scoped queries ----------------------------------------------
    def entries_for_seid(self, logical_name: str, seid: int) -> list[MapEntry]:
        """Every entry belonging to one session."""
        spec = spec_for(self._catalogue, logical_name)
        return [e for e in self.dump(logical_name) if self._seid_of(e, spec) == seid]

    def count_for_seid(self, logical_name: str, seid: int) -> int:
        return len(self.entries_for_seid(logical_name, seid))

    def pdr_ids_for_seid(self, logical_name: str, seid: int) -> list[int]:
        """PDR ids present for a session, sorted -- for rule-pruning assertions."""
        ids = [
            e.key_field("pdr_id")
            for e in self.entries_for_seid(logical_name, seid)
        ]
        return sorted(i for i in ids if i is not None)

    # -- internals ---------------------------------------------------------
    def _decode_entry(self, entry: dict[str, Any], spec: MapSpec) -> MapEntry:
        return MapEntry(
            key=_coerce(entry.get("key"), spec.key_layout),
            value=_coerce(_value_of(entry), spec.value_layout),
            raw=entry,
        )

    def _seid_of(self, entry: MapEntry, spec: MapSpec) -> int | None:
        source = entry.key if spec.seid_source == "key" else entry.value
        if spec.seid_field is None:
            # The key (or value) is itself the bare SEID.
            return source if isinstance(source, int) else None
        if isinstance(source, dict):
            raw = source.get(spec.seid_field)
            return None if raw is None else int(raw)
        return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _value_of(entry: dict[str, Any]) -> Any:
    """Extract the value, tolerating per-CPU maps which use ``values``."""
    if "value" in entry:
        return entry["value"]
    values = entry.get("values")
    if isinstance(values, list) and values:
        first = values[0]
        if isinstance(first, dict) and "value" in first:
            return first["value"]
        return first
    return None


def _coerce(raw: Any, layout: StructLayout | None) -> Decoded:
    """Normalise a bpftool key/value into a scalar, a field mapping, or bytes."""
    if raw is None:
        return None

    # BTF-formatted: already a field mapping.
    if isinstance(raw, dict):
        return {
            key: int(value)
            for key, value in raw.items()
            if isinstance(value, (int, str)) and _is_intish(value)
        }

    if isinstance(raw, int):
        return raw

    if isinstance(raw, str):
        return _parse_int(raw)

    if isinstance(raw, Sequence):
        data = _to_bytes(raw)
        if data is None:
            return None
        if layout is not None and len(data) >= layout.size:
            return layout.unpack(data)
        # No layout: a bare scalar key, little-endian as the kernel stores it.
        return int.from_bytes(data, "little")

    return None


def _to_bytes(items: Iterable[Any]) -> bytes | None:
    out = bytearray()
    for item in items:
        if isinstance(item, int):
            out.append(item & 0xFF)
        elif isinstance(item, str):
            parsed = _parse_int(item)
            if parsed is None:
                return None
            out.append(parsed & 0xFF)
        else:
            return None
    return bytes(out)


def _parse_int(text: str) -> int | None:
    text = text.strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _is_intish(value: Any) -> bool:
    if isinstance(value, int):
        return True
    return isinstance(value, str) and _parse_int(value) is not None


def _render(decoded: Decoded) -> str:
    if isinstance(decoded, dict):
        return "{" + ", ".join(f"{k}={v}" for k, v in decoded.items()) + "}"
    if isinstance(decoded, int):
        return f"0x{decoded:x}"
    return repr(decoded)
