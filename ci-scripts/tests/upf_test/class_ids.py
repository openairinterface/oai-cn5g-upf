# SPDX-License-Identifier: MIT
"""HTB class-id arithmetic, mirroring how the OAI UPF derives its classids.

Kept next to the rest of the adapter because it is not a `tc` fact -- it is a fact
about this UPF's source. Reproducing the derivation here is what lets a scenario
ask "does the class for this flow have the right rate?" without the UPF telling it
which class that is.
"""

from __future__ import annotations


def session_class_minor(seid: int) -> int:
    """Minor of the per-session HTB class.

    The UPF uses ``(uint16_t) seid`` (``qer_tc_user.cpp``), so two sessions whose
    SEIDs collide in the low 16 bits collide here too -- a pre-existing limitation
    of the UPF, not something this suite can paper over.
    """
    return seid & 0xFFFF


def qos_class_minor(seid: int, qfi: int) -> int:
    """Minor of a QoS-flow HTB class.

    Mirrors ``generate_minor_id()`` in ``kernel/include/sdf_types.h``: a pure hash
    of (SEID, QFI) with no counter, which is exactly why a rebuild targets the same
    classid the previous setup created -- the crux of the QoS-rate-change defect.

    Verified live: seid=3, qfi=5 produces 0xbc, matching the class ``1:bc`` the UPF
    actually created.
    """
    folded = seid ^ (seid >> 16) ^ (seid >> 32) ^ (seid >> 48)
    minor = ((folded & 0xFFFF) + qfi * 37) & 0xFFFF
    minor = 9999 if minor > 9999 else minor
    return minor or 1
