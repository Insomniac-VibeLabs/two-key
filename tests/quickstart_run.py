# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Run every command in docs/QUICKSTART.md, in order, in a new folder, so the page cannot go stale.

Each ```bash block runs on its own, with bash -e, and must exit 0 unless the comment line just above it says
otherwise:

    <!-- quickstart: skip (why) -->           not run here
    <!-- quickstart: exit=2 expect=TEXT -->  must exit 2, and print TEXT

The judge is a stand-in on 127.0.0.1:11434 that answers Ollama's /api/chat with a yes vote, so the result does
not depend on a model. It is for this script only: a judge that always says yes is no judge.

    python tests/quickstart_run.py          # needs two-key on PATH, and port 11434 free
"""

import json
import re
import subprocess  # nosec B404 - runs the page's own commands
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "QUICKSTART.md"
MARK = re.compile(r"^<!-- quickstart: (.*) -->$")
JUDGE_ADDRESS = ("127.0.0.1", 11434)


class Block:
    """One ```bash block and what its marker asks of it."""

    def __init__(self, code: str, marker: str = ""):
        self.code = code
        self.skip = marker.startswith("skip")
        self.exit = 0
        self.expect = None
        for word in marker.split():
            if word.startswith("exit="):
                self.exit = int(word[len("exit="):])
            elif word.startswith("expect="):
                self.expect = word[len("expect="):]


def blocks(text: str) -> list[Block]:
    """The ```bash blocks in order, each with the quickstart marker on the line just above it, if any."""
    found, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        if lines[i].strip() != "```bash":
            i += 1
            continue
        mark = MARK.match(lines[i - 1].strip()) if i else None
        end = lines.index("```", i + 1)
        found.append(Block("\n".join(lines[i + 1:end]) + "\n", mark.group(1) if mark else ""))
        i = end + 1
    return found


class StandInJudge(BaseHTTPRequestHandler):
    """Ollama's /api/chat, answering every request with a yes ballot."""

    def do_POST(self):  # noqa: N802 - the name BaseHTTPRequestHandler calls
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        ballot = {"consistent": True, "confidence": 0.9, "rationale": "quickstart stand-in"}
        body = json.dumps({"message": {"role": "assistant", "content": json.dumps(ballot)}, "done": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def problem(block: Block, result: subprocess.CompletedProcess) -> str | None:
    """Why a block's run does not match its marker, or None."""
    output = result.stdout + result.stderr
    if result.returncode != block.exit:
        return f"exit {result.returncode}, expected {block.exit}"
    if block.expect is not None and block.expect not in output:
        return f"{block.expect!r} not in the output"
    return None


def run(doc: Path = DOC) -> int:
    server = ThreadingHTTPServer(JUDGE_ADDRESS, StandInJudge)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            cwd, where = Path(tmp), Path(tmp) / ".quickstart-cwd"
            for n, block in enumerate(blocks(doc.read_text(encoding="utf-8")), 1):
                if block.skip:
                    print(f"block {n}: skipped")
                    continue
                # Each block starts where the last one left off (step 4 enters the folder it made).
                script = f"cd {json.dumps(str(cwd))}\n{block.code}pwd > {json.dumps(str(where))}\n"
                result = subprocess.run(["bash", "-e", "-c", script], capture_output=True, text=True,  # nosec B603 B607
                                        check=False)
                print(f"block {n}: exit {result.returncode}\n{result.stdout}{result.stderr}")
                why = problem(block, result)
                if why:
                    print(f"block {n} failed: {why}", file=sys.stderr)
                    return 1
                if where.exists():
                    cwd = Path(where.read_text(encoding="utf-8").strip())
                    where.unlink()
    finally:
        server.shutdown()
    print("quickstart: every block ran as the page says")
    return 0


if __name__ == "__main__":
    sys.exit(run())
