"""Each long document has a table of contents that matches its headings, with GitHub's anchors.

After adding, renaming, or moving a heading, regenerate them:

    python tests/test_doc_toc.py --write
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Document -> the deepest heading level its table lists. Short documents (SECURITY, SCOPE, COMPARISON,
# CONTRIBUTING) have none.
DOCS = {"README.md": 2, "ROADMAP.md": 3, "CHANGES.md": 2, "AGENTS.md": 2, "docs/HOWTO.md": 3,
        "docs/THREAT_MODEL.md": 2, "docs/JUDGES_AND_QUORUM.md": 2, "docs/FIT.md": 2, "docs/SCANNERS.md": 2,
        "docs/CONNECTING.md": 2, "docs/SIEM.md": 2}
TITLE = "Contents"
START, END = "<!-- toc -->", "<!-- /toc -->"
FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")


def headings(text: str) -> list[tuple[int, str]]:
    """(level, title) of each ATX heading outside code fences, in order."""
    found, fenced = [], False
    for line in text.splitlines():
        if FENCE.match(line):
            fenced = not fenced
        elif not fenced and (m := HEADING.match(line)):
            found.append((len(m.group(1)), m.group(2)))
    return found


def slug(title: str) -> str:
    """GitHub's heading anchor: link text only, lower case, punctuation dropped, each space a hyphen."""
    return re.sub(r"[^\w\- ]", "", LINK.sub(r"\1", title).lower()).replace(" ", "-")


def toc(text: str, depth: int) -> str:
    entries, seen = [], {}
    for level, title in headings(text):
        base = slug(title)
        n = seen.get(base, 0)
        seen[base] = n + 1                  # a repeated heading's anchor gets -1, -2, ...
        if 2 <= level <= depth and title != TITLE:
            anchor = base if n == 0 else f"{base}-{n}"
            label = LINK.sub(r"\1", title)
            entries.append(f"{'  ' * (level - 2)}- [{label}](#{anchor})")
    return "\n".join(entries)


def with_toc(text: str, depth: int) -> str:
    """The document with its table regenerated, or inserted before the first second-level heading."""
    if START in text:
        head, rest = text.split(START, 1)
        tail = rest.split(END, 1)[1]
        return f"{head}{START}\n{toc(text, depth)}\n{END}{tail}"
    lines, fenced = text.split("\n"), False
    for i, line in enumerate(lines):
        if FENCE.match(line):
            fenced = not fenced
        elif not fenced and line.startswith("## "):
            block = [f"## {TITLE}", "", START, toc(text, depth), END, ""]
            return "\n".join(lines[:i] + block + lines[i:])
    raise ValueError("no second-level heading")


class TablesOfContents(unittest.TestCase):
    def test_each_table_matches_its_headings(self):
        for name, depth in DOCS.items():
            with self.subTest(doc=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn(START, text, f"{name}: no table; run python tests/test_doc_toc.py --write")
                self.assertEqual(text, with_toc(text, depth),
                                 f"{name}: table out of date; run python tests/test_doc_toc.py --write")

    def test_anchors(self):
        text = "# T\n## Docs — 2026-10-02\n## Docs — 2026-10-03\n## Docs\n## Docs\n```\n## not a heading\n```\n" \
               "### `two-key mcp-proxy` (#2)\n## Judge ≠ agent [link](x.md)\n"
        self.assertEqual(toc(text, 3).splitlines(), [
            "- [Docs — 2026-10-02](#docs--2026-10-02)",
            "- [Docs — 2026-10-03](#docs--2026-10-03)",
            "- [Docs](#docs)",
            "- [Docs](#docs-1)",
            "  - [`two-key mcp-proxy` (#2)](#two-key-mcp-proxy-2)",
            "- [Judge ≠ agent link](#judge--agent-link)"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        for doc, level in DOCS.items():
            path = ROOT / doc
            path.write_text(with_toc(path.read_text(encoding="utf-8"), level), encoding="utf-8")
            print("updated", doc)
    else:
        unittest.main()
