# SPDX-License-Identifier: MIT
"""Generic machinery for describing BPF map identity and key/value layouts.

The *catalogue* of maps belongs to whichever UPF is under test and lives in that
project's adapter; only the mechanics are here. Two of those mechanics are easy to
get wrong and dangerous when wrong, because both failure modes make an *absence*
assertion pass for the wrong reason:

1. **Map names are truncated by the kernel** to 15 characters
   (``BPF_OBJ_NAME_LEN`` is 16, including the NUL), and the truncated form is what
   ``bpftool map dump name`` matches on. Asking for a longer logical name simply
   finds nothing. :func:`bpf_name` does the truncation so no caller has to know.

2. **Struct padding must be reproduced exactly.** A key mixing widths is not the
   sum of its fields: ``{u16 pdr_id; u64 seid;}`` is 16 bytes, not 10, with six
   bytes of padding after the first field. A wrong offset decodes to plausible
   garbage rather than failing.

Layouts are only a *fallback*. When the UPF is built with BTF, ``bpftool`` emits
already-decoded keys and values and those are preferred; the layouts cover a
BTF-less build.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

#: Kernel limit on a BPF object name, including the terminating NUL.
BPF_OBJ_NAME_LEN = 16

#: Usable characters in a map name as reported by bpftool.
MAP_NAME_MAX = BPF_OBJ_NAME_LEN - 1


def bpf_name(logical_name: str) -> str:
    """Truncate a logical map name to the form the kernel reports.

    >>> bpf_name("session_by_ue_ip_map")
    'session_by_ue_i'
    >>> bpf_name("sdf_filters_map")
    'sdf_filters_map'
    """
    return logical_name[:MAP_NAME_MAX]


@dataclass(frozen=True)
class StructLayout:
    """A C struct layout: a ``struct`` format plus the field names it yields."""

    fmt: str
    fields: tuple[str, ...]

    def __post_init__(self) -> None:
        produced = len(struct.unpack(self.fmt, b"\x00" * self.size))
        if produced != len(self.fields):
            raise ValueError(
                f"layout {self.fmt!r} yields {produced} value(s) but "
                f"{len(self.fields)} field name(s) were given"
            )

    @property
    def size(self) -> int:
        return struct.calcsize(self.fmt)

    def unpack(self, raw: bytes) -> dict[str, int]:
        """Decode raw bytes into a field mapping.

        Accepts a buffer longer than the struct (bpftool pads to the map's key
        size) but never shorter, which would silently misdecode.
        """
        if len(raw) < self.size:
            raise ValueError(
                f"layout {self.fmt!r} needs {self.size} bytes, got {len(raw)}"
            )
        values = struct.unpack(self.fmt, raw[: self.size])
        return dict(zip(self.fields, values, strict=True))


SeidSource = Literal["key", "value"]


@dataclass(frozen=True)
class MapSpec:
    """Everything an inspector needs to know about one map.

    ``seid_field`` of ``None`` means the key (or value) is itself the bare SEID
    rather than a struct containing one -- a map keyed by a plain ``u64``.
    """

    logical_name: str
    seid_source: SeidSource = "key"
    seid_field: str | None = "seid"
    key_layout: StructLayout | None = None
    value_layout: StructLayout | None = None
    description: str = ""

    @property
    def name(self) -> str:
        """The name bpftool matches on."""
        return bpf_name(self.logical_name)


#: A UPF adapter's map catalogue, keyed by logical name.
MapCatalogue = Mapping[str, MapSpec]


def spec_for(catalogue: MapCatalogue, logical_name: str) -> MapSpec:
    """Look up a map spec, or raise listing what the catalogue does hold."""
    try:
        return catalogue[logical_name]
    except KeyError:
        raise KeyError(
            f"unknown map {logical_name!r}; known: {', '.join(sorted(catalogue))}"
        ) from None
