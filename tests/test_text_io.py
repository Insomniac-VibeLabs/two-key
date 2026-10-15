"""Every text file Two-Key opens names its encoding, and every text file it writes uses "\\n" (0.6.0).

Without them a file hashes or signs differently on Windows, where the default encoding is the ANSI code
page and text mode writes "\\r\\n".
"""

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "two_key"


def _mode(call: ast.Call, position: int):
    if len(call.args) > position and isinstance(call.args[position], ast.Constant):
        return call.args[position].value
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            return kw.value.value
    return "r"


def _keywords(call: ast.Call) -> dict:
    return {kw.arg: kw.value for kw in call.keywords if kw.arg}


def problems(source: str, name: str) -> list[str]:
    out = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        attr = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else None
        kw = _keywords(node)
        where = f"{name}:{node.lineno}"
        if attr in ("read_text", "write_text"):
            if "encoding" not in kw:
                out.append(f"{where}: {attr}() without encoding")
            newline = kw.get("newline")
            if attr == "write_text" and not (isinstance(newline, ast.Constant) and newline.value == "\n"):
                out.append(f"{where}: write_text() without newline=\"\\n\"")
            continue
        if attr == "fdopen" or (attr == "open" and isinstance(func, ast.Name)):
            mode = _mode(node, 1)
        elif attr == "open" and isinstance(func, ast.Attribute) and not (
                isinstance(func.value, ast.Name) and func.value.id == "os"):
            mode = _mode(node, 0)        # Path.open(mode)
        else:
            continue
        if not isinstance(mode, str) or "b" in mode:
            continue
        if "encoding" not in kw:
            out.append(f"{where}: {attr}() in text mode without encoding")
        newline = kw.get("newline")
        if any(c in mode for c in "wax+") and not (isinstance(newline, ast.Constant) and newline.value == "\n"):
            out.append(f"{where}: {attr}() writes text without newline=\"\\n\"")
    return out


class TextIO(unittest.TestCase):
    def test_every_text_open_names_encoding_and_newline(self):
        found = []
        for path in sorted(ROOT.rglob("*.py")):
            found += problems(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT.parent)))
        self.assertEqual(found, [])

    def test_the_check_catches_each_form(self):
        bad = ("open(p)\nopen(p, 'w', encoding='utf-8')\nPath(p).read_text()\nPath(p).write_text(t, encoding='utf-8')\n"
               "os.fdopen(fd, 'w')\nPath(p).open('a', encoding='utf-8')\n")
        self.assertEqual(len(problems(bad, "x")), 7)   # the bare fdopen misses both
        good = ("open(p, 'rb')\nopen(p, encoding='utf-8')\nPath(p).write_text(t, encoding='utf-8', newline='\\n')\n"
                "os.fdopen(fd, 'wb')\nPath(p).open('a', encoding='utf-8', newline='\\n')\nos.open(p, 1)\n")
        self.assertEqual(problems(good, "x"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
