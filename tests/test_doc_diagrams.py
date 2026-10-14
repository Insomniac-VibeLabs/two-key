"""Mermaid diagrams in the docs must parse on GitHub. A ';' ends a statement in a sequence diagram,
so one inside a message or note text breaks the whole diagram (README request-flow diagram, 0.3.0)."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BLOCK = re.compile(r"^```mermaid\n(.*?)^```", re.M | re.S)


class SequenceDiagramText(unittest.TestCase):
    def test_no_semicolon_in_sequence_diagrams(self):
        found = []
        for doc in sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").glob("*.md")):
            for block in BLOCK.findall(doc.read_text(encoding="utf-8")):
                if block.lstrip().startswith("sequenceDiagram"):
                    found += [f"{doc.name}: {line.strip()}" for line in block.splitlines() if ";" in line]
        self.assertEqual(found, [], "use ',' or '#59;' instead of ';' in sequence diagram text")


if __name__ == "__main__":
    unittest.main()
