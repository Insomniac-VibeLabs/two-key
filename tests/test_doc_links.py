# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Every relative link and image in the documents points at a file in the repository.

GitHub shows a missing image as a broken icon and a missing page as a 404, and neither fails a build, so the
walkthrough's screenshots (docs/GUI_WALKTHROUGH.md) and the links between documents are checked here.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FENCED = re.compile(r"^\s*(```|~~~).*?^\s*\1", re.S | re.M)
LINK = re.compile(r"(!?)\[[^\]]*\]\(([^)\s]+)\)")
EXTERNAL = ("http://", "https://", "mailto:", "#")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def documents() -> list[Path]:
    return sorted([*ROOT.glob("*.md"), *ROOT.glob("docs/*.md")])


def relative_links(doc: Path) -> list[tuple[bool, str]]:
    """(is an image, target) of each relative link outside code blocks, without its #anchor."""
    text = FENCED.sub("", doc.read_text(encoding="utf-8"))
    return [(bang == "!", target.split("#")[0]) for bang, target in LINK.findall(text)
            if not target.startswith(EXTERNAL)]


class DocLinks(unittest.TestCase):
    def test_every_relative_link_and_image_exists(self):
        for doc in documents():
            for _image, target in relative_links(doc):
                with self.subTest(doc=doc.name, target=target):
                    self.assertTrue((doc.parent / target).exists(), f"{doc.name}: {target} does not exist")

    def test_every_png_image_is_a_png(self):
        for doc in documents():
            for image, target in relative_links(doc):
                if image and target.endswith(".png"):
                    with self.subTest(doc=doc.name, target=target):
                        self.assertEqual((doc.parent / target).read_bytes()[:8], PNG_MAGIC)

    def test_the_walkthrough_shows_every_screenshot_once(self):
        doc = ROOT / "docs" / "GUI_WALKTHROUGH.md"
        shown = sorted(target for image, target in relative_links(doc) if image)
        folder = ROOT / "docs" / "images" / "gui-walkthrough"
        on_disk = sorted(f"images/gui-walkthrough/{p.name}" for p in folder.glob("*.png"))
        self.assertEqual(shown, on_disk)


if __name__ == "__main__":
    unittest.main()
