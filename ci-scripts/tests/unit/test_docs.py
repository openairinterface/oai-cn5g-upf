# SPDX-License-Identifier: MIT
"""Keeps docs/ARCHITECTURE.md, the export script, and the diagram in agreement.

Two things describe the same five pages: the ``.drawio`` that holds them, and the
markdown that embeds the exported images. Nothing stops them drifting apart, and the
failure is quiet -- a sixth diagram page simply goes undocumented, or a renamed page
leaves a broken image that shows up only when someone opens the doc.

There is no export script or filename table to check against any more, so the expected
image name is *derived* from the page name instead: "2 - Observing state" ->
``img/02-observing-state.png``. One rule, no third artefact to maintain.

Needs no UPF and no images: it reads the XML and the text.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_DIAGRAM = _ROOT / "docs" / "architecture.drawio"
_DOC = _ROOT / "docs" / "ARCHITECTURE.md"
_IMG = _ROOT / "docs" / "img"


def diagram_pages() -> list[str]:
    """Page names, in the order the file holds them.

    That order is the export index order, which is what the script relies on.
    """
    root = ET.parse(_DIAGRAM).getroot()
    return [d.get("name", "") for d in root.iter("diagram")]


def documented_images() -> list[str]:
    """Image paths the doc embeds, in document order."""
    return re.findall(r"!\[[^\]]*\]\((img/[^)]+)\)", _DOC.read_text())


def expected_image(page_name: str) -> str:
    """The image filename a page's name implies.

    "2 - Observing state" -> "img/02-observing-state.png". Zero-padded number, hyphens
    for spaces, lower case.
    """
    number, _, subject = page_name.partition(" - ")
    slug = re.sub(r"[^a-z0-9]+", "-", subject.strip().lower()).strip("-")
    return f"img/{int(number):02d}-{slug}.png"


# ---------------------------------------------------------------------------
# The artefacts exist and are non-trivial
# ---------------------------------------------------------------------------
def test_the_artefacts_exist() -> None:
    for path in (_DIAGRAM, _DOC):
        assert path.exists(), f"{path.relative_to(_ROOT)} is missing"
    assert _IMG.is_dir(), "docs/img/ is missing -- the doc embeds images from it"


def test_the_diagram_has_pages_to_check() -> None:
    """Guards against every check below passing on an empty list."""
    assert len(diagram_pages()) >= 5


# ---------------------------------------------------------------------------
# Doc <-> diagram
# ---------------------------------------------------------------------------
def test_the_doc_embeds_one_image_per_diagram_page() -> None:
    pages, images = diagram_pages(), documented_images()
    assert len(images) == len(pages), (
        f"{len(pages)} diagram page(s) but {len(images)} embedded image(s): "
        f"{images}. Add a section to docs/ARCHITECTURE.md, or remove the page."
    )


def test_each_diagram_page_has_a_section_naming_it() -> None:
    """The page's subject must appear as a heading, so the doc tracks a rename.

    Matched on the page name minus its ``N - `` prefix, case-insensitively, which is
    loose enough to survive reasonable heading wording and tight enough to catch a
    page that was renamed without touching the doc.
    """
    headings = re.findall(r"^## \d+\.\s*(.+)$", _DOC.read_text(), re.M)
    lowered = [h.strip().lower() for h in headings]
    for page in diagram_pages():
        subject = re.sub(r"^\d+\s*-\s*", "", page).strip().lower()
        assert subject in lowered, (
            f"diagram page {page!r} has no section in docs/ARCHITECTURE.md; "
            f"headings are {headings}"
        )


# ---------------------------------------------------------------------------
# Doc <-> export script
# ---------------------------------------------------------------------------
def test_each_embedded_image_is_named_after_its_page() -> None:
    """Ties the filenames to the diagram, with no third artefact in between.

    Rename a page or add one, and the embed has to change to match. That is the point:
    the alternative is a table that silently disagrees with both.
    """
    expected = [expected_image(name) for name in diagram_pages()]
    assert documented_images() == expected, (
        f"embedded: {documented_images()}\nexpected: {expected}"
    )


# ---------------------------------------------------------------------------
# Links out of the doc
# ---------------------------------------------------------------------------
def test_every_relative_link_in_the_doc_resolves() -> None:
    """Excludes the image embeds, which are generated and may legitimately be absent."""
    text = _DOC.read_text()
    without_images = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    targets = re.findall(r"\]\((\.\./[^)#]+|img/)\)", without_images)
    missing = [t for t in targets if not (_DOC.parent / t).exists()]
    assert not missing, f"broken relative link(s) in docs/ARCHITECTURE.md: {missing}"


@pytest.mark.parametrize("readme", ["README.md", "pfcpkit/README.md"])
def test_the_readmes_point_at_the_architecture_doc(readme: str) -> None:
    """A guide nothing links to is a guide nobody reads."""
    text = (_ROOT / readme).read_text()
    assert "docs/ARCHITECTURE.md" in text, (
        f"{readme} does not link to docs/ARCHITECTURE.md"
    )
