"""Mermaid diagrams in the docs must parse on GitHub, and stay readable there.

Two kinds of check. The first is syntax: a ';' ends a statement in a sequence diagram, so one inside a
message or note text breaks the whole diagram (README request-flow diagram, 0.3.0). The second is the house
style, which keeps GitHub's renderer from splitting words, clipping notes, or shrinking text:

1. A label line is at most 28 characters (break it with <br/>); a subgraph title, at most 40.
2. An edge label is at most two lines.
3. A flowchart goes left to right (LR) only when its longest chain has four boxes or fewer. Otherwise TD.
4. A sequence diagram has at most five participants; a message, note line or block label is at most 50
   characters; a note is one or two lines.
5. A flowchart has at most 12 boxes. Split a bigger picture into two.
6. A flowchart that mixes solid and dashed lines says "dashed" in its caption.
7. A caption, one line of italic text, follows every diagram.

A Mermaid renderer needs Node and a browser, so it cannot run here. The `diagrams` workflow draws every
block with a pinned mermaid-cli and uploads the pictures for a look before a release; it gets the blocks
from `python tests/test_doc_diagrams.py --extract DIR`.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BLOCK = re.compile(r"^```mermaid\n(.*?)^```[ \t]*\n", re.M | re.S)
QUOTED = re.compile(r'"([^"]*)"')
BREAK = re.compile(r"<br\s*/?>")
ARROW = re.compile(r"<?(?:-{2,}>|-\.+->|-{3,}|={2,}>)")
EDGE_LABEL = re.compile(r'(?:--|-\.)\s*"([^"]*)"\s*(?:-->|\.->|---)|\|\s*"([^"]*)"\s*\|')
CAPTION = re.compile(r"^\*[^*\s][^*]*\*$")
MAX_LABEL_LINE, MAX_TITLE, MAX_EDGE_LINES = 28, 40, 2
MAX_PARTICIPANTS, MAX_SEQ_TEXT, MAX_NOTE_LINES, MAX_BOXES, MAX_LR_CHAIN = 5, 50, 2, 12, 4


def documents() -> list[Path]:
    return sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").glob("*.md"))


def diagrams(text: str) -> list[tuple[int, str, str]]:
    """(line number, source, the first non-blank line after the block) of each Mermaid block in a document."""
    found = []
    for m in BLOCK.finditer(text):
        after = next((ln.strip() for ln in text[m.end():].splitlines() if ln.strip()), "")
        found.append((text[:m.start()].count("\n") + 1, m.group(1), after))
    return found


def lines_of(label: str) -> list[str]:
    return BREAK.split(label)


def flowchart_boxes_and_edges(src: str) -> tuple[set[str], list[tuple[str, str]]]:
    """Box ids and (from, to) pairs, from the source with every quoted label and bracket removed."""
    boxes, edges = set(), []
    for raw in src.splitlines()[1:]:
        line = raw.split("%%")[0].strip()
        if not line or re.match(r"(subgraph|end|direction|style|classDef|class|linkStyle)\b", line):
            continue
        line = QUOTED.sub('""', line)
        line = re.sub(r'\[\(\s*""\s*\)\]|\[""\]|\{""\}|\(\(""\)\)|\(""\)', "", line)    # node shapes
        line = re.sub(r'(<?-{2,})\s*""\s*(-{1,}>?)', r"\1\2", line)                     # -- "x" -->
        line = re.sub(r'(-\.)\s*""\s*(\.+->?)', r"\1\2", line)                          # -. "x" .->
        line = re.sub(r"\|[^|]*\|", "", line)                                             # -->|x|
        parts = ARROW.split(line)
        ids = [p.strip() for p in parts]
        if not all(re.fullmatch(r"[A-Za-z_]\w*", i) for i in ids):
            raise AssertionError(f"cannot read the flowchart line: {raw.strip()}")
        boxes.update(ids)
        edges += list(zip(ids, ids[1:]))
    return boxes, edges


def longest_chain(edges: list[tuple[str, str]]) -> int:
    """Boxes on the longest path, not following an edge back to a box already on the path."""
    out: dict[str, list[str]] = {}
    for a, b in edges:
        out.setdefault(a, []).append(b)

    def walk(node: str, seen: frozenset) -> int:
        return 1 + max((walk(n, seen | {node}) for n in out.get(node, []) if n not in seen | {node}), default=0)

    return max((walk(n, frozenset()) for n in out), default=1)


def problems(src: str, after: str) -> list[str]:
    kind = src.lstrip().split(None, 1)[0]
    found = []
    if kind in ("flowchart", "graph"):
        found += flowchart_problems(src)
        if "-." in src and re.search(r"-{2,}>|-{3,}", src) and "dashed" not in after.lower():
            found.append('mixes solid and dashed lines, so the caption must say "dashed"')
    elif kind == "sequenceDiagram":
        found += sequence_problems(src)
    else:
        found.append(f"unknown diagram type {kind}")
    if not CAPTION.match(after):
        found.append(f"no one-line italic caption after it (found: {after[:40]!r})")
    return found


def flowchart_problems(src: str) -> list[str]:
    found = []
    for raw in src.splitlines():
        stripped = raw.strip()
        for label in QUOTED.findall(stripped):
            limit = MAX_TITLE if stripped.startswith("subgraph") else MAX_LABEL_LINE
            found += [f"label line over {limit}: {ln!r}" for ln in lines_of(label) if len(ln) > limit]
        for label in EDGE_LABEL.findall(stripped):
            if len(lines_of(label[0] or label[1])) > MAX_EDGE_LINES:
                found.append(f"edge label over {MAX_EDGE_LINES} lines: {(label[0] or label[1])!r}")
    boxes, edges = flowchart_boxes_and_edges(src)
    if len(boxes) > MAX_BOXES:
        found.append(f"{len(boxes)} boxes, at most {MAX_BOXES}; split the picture")
    if re.match(r"\s*(flowchart|graph)\s+(LR|RL)\b", src) and longest_chain(edges) > MAX_LR_CHAIN:
        found.append(f"left to right with a chain of {longest_chain(edges)} boxes; use TD")
    return found


def sequence_problems(src: str) -> list[str]:
    found = []
    participants = len(re.findall(r"^\s*(?:participant|actor)\s", src, re.M))
    if participants > MAX_PARTICIPANTS:
        found.append(f"{participants} participants, at most {MAX_PARTICIPANTS}")
    for raw in src.splitlines():
        line = raw.strip()
        if re.match(r"(participant|actor|autonumber|sequenceDiagram|end$)", line):
            continue
        if m := re.match(r"Note\s+(?:over|left of|right of)\s+[^:]+:\s*(.*)", line):
            parts = lines_of(m.group(1))
            if len(parts) > MAX_NOTE_LINES:
                found.append(f"note over {MAX_NOTE_LINES} lines: {line}")
            found += [f"note line over {MAX_SEQ_TEXT}: {p!r}" for p in parts if len(p) > MAX_SEQ_TEXT]
        elif m := re.match(r"(?:alt|else|opt|loop|par|and)\s+(.*)", line):
            if len(m.group(1)) > MAX_SEQ_TEXT:
                found.append(f"block label over {MAX_SEQ_TEXT}: {m.group(1)!r}")
        elif m := re.match(r"\S+?(?:-->>|->>|-->|->|--x|-x)\S+?:\s*(.*)", line):
            if len(m.group(1)) > MAX_SEQ_TEXT:
                found.append(f"message over {MAX_SEQ_TEXT}: {m.group(1)!r}")
    return found


class SequenceDiagramText(unittest.TestCase):
    def test_no_semicolon_in_sequence_diagrams(self):
        found = []
        for doc in documents():
            for _, block, _ in diagrams(doc.read_text(encoding="utf-8")):
                if block.lstrip().startswith("sequenceDiagram"):
                    found += [f"{doc.name}: {line.strip()}" for line in block.splitlines() if ";" in line]
        self.assertEqual(found, [], "use ',' or '#59;' instead of ';' in sequence diagram text")


class HouseStyle(unittest.TestCase):
    def test_every_diagram_follows_the_house_style(self):
        found = []
        for doc in documents():
            for line, block, after in diagrams(doc.read_text(encoding="utf-8")):
                found += [f"{doc.name}:{line}: {p}" for p in problems(block, after)]
        self.assertEqual(found, [], "see the rules in this file's docstring")

    def test_the_checks_catch_what_they_claim_to(self):
        """A bad diagram per rule, so a rule that stops matching anything fails here."""
        cap = "*caption*"
        cases = {
            "label line": ('flowchart TD\n  a["' + "x" * 29 + '"] --> b["y"]', cap),
            "edge label": ('flowchart TD\n  a["x"] -- "1<br/>2<br/>3" --> b["y"]', cap),
            "left to right": ('flowchart LR\n  a["x"] --> b["y"] --> c["z"] --> d["w"] --> e["v"]', cap),
            "boxes": ("flowchart TD\n" + "".join(f'  n{i}["x"] --> n{i + 1}["y"]\n' for i in range(0, 26, 2)), cap),
            "dashed": ('flowchart TD\n  a["x"] --> b["y"]\n  a -. "z" .-> c["w"]', cap),
            "participants": ("sequenceDiagram\n" + "".join(f"  participant P{i}\n" for i in range(6)), cap),
            "message": ("sequenceDiagram\n  A->>B: " + "m" * 51, cap),
            "note": ("sequenceDiagram\n  Note over A: one<br/>two<br/>three", cap),
            "caption": ('flowchart TD\n  a["x"] --> b["y"]', "Plain text."),
        }
        for rule, (src, after) in cases.items():
            with self.subTest(rule=rule):
                self.assertTrue(problems(src, after), f"the {rule} rule found nothing in a diagram that breaks it")

    def test_a_clean_diagram_passes(self):
        src = 'flowchart LR\n  a["x"] --> b["y"]\n  a -. "z" .-> c["w"]'
        self.assertEqual(problems(src, "*Dashed lines are optional.*"), [])


def extract(dest: Path) -> int:
    """Write each Mermaid block to dest/<document>-<n>.mmd, for the `diagrams` workflow to draw."""
    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    for doc in documents():
        for n, (_, block, _) in enumerate(diagrams(doc.read_text(encoding="utf-8")), 1):
            (dest / f"{doc.stem}-{n}.mmd").write_text(block, encoding="utf-8")
            count += 1
    return count


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--extract":
        print(f"{extract(Path(sys.argv[2]))} diagrams extracted")
    else:
        unittest.main()
