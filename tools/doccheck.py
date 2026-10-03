#!/usr/bin/env python3
"""Run the commands and code snippets in README.md / docs/HOWTO.md.

Usage:  python3 tools/doccheck.py README.md docs/HOWTO.md [--keep] [--python python3]

Each document runs in its own sandbox: a copy of this repository's files, a
fresh HOME, and (because the documents contain the install steps) a fresh
virtualenv created by the document's own commands. Blocks run in document
order in one bash process with ``set -euo pipefail``.

Directive comments on the line just before a fenced block:
  <!-- check: skip REASON -->     not run (reason is reported)
  <!-- check: file=PATH -->       write the block to PATH in the sandbox
  <!-- check: expect-fail -->     the block must exit non-zero
  <!-- check: expect=REGEX -->    the block's output must match REGEX (Python re, MULTILINE);
                                  several expect lines may be stacked above one block
Fenced blocks tagged ``bash`` or ``python`` run unless skipped. ``text``
blocks are sample output and are not run. Any other block without a
directive is reported as UNCHECKED and fails the run.

Judge HTTP calls never reach the network: when TWOKEY_DOCCHECK_FAKE_LLM=1 a
sitecustomize module replaces urllib.request.urlopen with a local fake that
answers in each provider's response format (OpenAI-compatible, Anthropic,
Gemini, Ollama). The fake votes "consistent" unless the action record names
wire_transfer or medical data, and echoes the ballot binding when asked.
Snippets that need a real model therefore are verified against this fake only.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FENCE = re.compile(r"^(`{3,})([\w+-]*)\s*$")
DIRECTIVE = re.compile(r"^<!--\s*check:\s*(.*?)\s*-->\s*$")

SITECUSTOMIZE = r'''
import io, json, os, re, urllib.request
if os.environ.get("TWOKEY_DOCCHECK_FAKE_LLM") == "1":
    class _Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): self.close()
    def _strings(o):
        if isinstance(o, str): yield o
        elif isinstance(o, dict):
            for v in o.values(): yield from _strings(v)
        elif isinstance(o, list):
            for v in o: yield from _strings(v)
    def _fake_urlopen(req, timeout=None, *a, **kw):
        url = getattr(req, "full_url", str(req))
        body = json.loads((getattr(req, "data", None) or b"{}").decode())
        text = "\n".join(_strings(body))
        rec = re.search(r"<untrusted_action_record>\n(.*?)\n</untrusted_action_record>", text, re.S)
        rec = rec.group(1) if rec else ""
        deny = '"tool":"wire_transfer"' in rec or '"data_class":"medical"' in rec
        ballot = {"consistent": not deny, "confidence": 0.9, "rationale": "doccheck fake judge"}
        m = re.search(r"<ballot_binding>\n(.*?)\n</ballot_binding>", text, re.S)
        if m and "copy the two hashes" in text:
            ballot.update(json.loads(m.group(1)))
        b = json.dumps(ballot)
        if url.endswith("/chat/completions"):
            resp = {"choices": [{"message": {"content": b}}]}
        elif url.endswith("/v1/messages"):
            resp = {"content": [{"type": "text", "text": b}]}
        elif ":generateContent" in url:
            resp = {"candidates": [{"content": {"parts": [{"text": b}]}}]}
        elif url.endswith("/api/chat"):
            resp = {"message": {"content": b}}
        else:
            raise OSError("doccheck: unexpected URL " + url)
        log = os.environ.get("TWOKEY_DOCCHECK_LOG")
        if log:
            with open(log, "a") as f:
                f.write(json.dumps({"url": url, "headers": sorted(getattr(req, "headers", {}))}) + "\n")
        return _Resp(json.dumps(resp).encode())
    urllib.request.urlopen = _fake_urlopen
'''


def parse(md: Path):
    lines = md.read_text(encoding="utf-8").split("\n")
    blocks, i = [], 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            i += 1
            continue
        fence, lang = m.group(1), m.group(2)
        j = i + 1
        while j < len(lines) and lines[j].rstrip() != fence:
            j += 1
        k, ds = i - 1, []
        while k >= 0 and not lines[k].strip():
            k -= 1
        while k >= 0 and DIRECTIVE.match(lines[k]):   # stacked directives, nearest last
            ds.insert(0, DIRECTIVE.match(lines[k]).group(1))
            k -= 1
        blocks.append({"line": i + 1, "lang": lang, "body": "\n".join(lines[i + 1:j]), "directives": ds})
        i = j + 1
    return blocks


def build_script(blocks, outdir: Path):
    out = ["set -euo pipefail", "TWOKEY_TAG=start; TWOKEY_LOG=/dev/null",
           "trap 'echo \"::: FAILED in $TWOKEY_TAG\"; cat \"$TWOKEY_LOG\"' ERR"]
    report = []
    for n, b in enumerate(blocks):
        ds, lang, tag = b["directives"], b["lang"], f"block {n} (line {b['line']}, {b['lang'] or 'plain'})"
        d = next((x for x in ds if not x.startswith("expect=")), "")
        expects = [x[len("expect="):].strip() for x in ds if x.startswith("expect=")]
        if d.startswith("skip"):
            report.append((tag, "SKIP", d[4:].strip(" :-—")))
            continue
        if d.startswith("file="):
            path = d[5:].strip()
            out += [f'echo "::: {tag} -> file {path}"', f'mkdir -p "$(dirname "{path}")"',
                    f"cat > '{path}' <<'__CK_FILE_EOF__'", b["body"], "__CK_FILE_EOF__"]
            report.append((tag, "FILE", path))
            continue
        if lang not in ("bash", "python"):
            report.append((tag, "IGNORED" if lang == "text" else "UNCHECKED", ""))
            continue
        body = b["body"] if lang == "bash" else \
            "python - <<'__CK_PY_EOF__'\n" + b["body"] + "\n__CK_PY_EOF__"
        # The fake judge transport is on for snippet HTTP calls. The unit
        # suite starts its own servers, so that fake must be off for those
        # commands and back on before the next snippet.
        if lang == "bash" and "unittest" in body:
            body = "TWOKEY_DOCCHECK_FAKE_LLM=\n" + body + "\nTWOKEY_DOCCHECK_FAKE_LLM=1"
        log = outdir / f"block{n}.out"
        # A brace group runs in the current shell, so cd/export/activate persist between blocks.
        run = f"{{ {body}\n}} > '{log}' 2>&1"
        out += [f"TWOKEY_TAG='{tag}'; TWOKEY_LOG='{log}'"]
        if d == "expect-fail":
            out += [f'echo "::: {tag} (expect failure)"',
                    f"if {run}; then cat '{log}'; echo '::: UNEXPECTED SUCCESS: {tag}'; exit 1; fi",
                    f"cat '{log}'"]
            report.append((tag, "RUN expect-fail", ""))
        else:
            out += [f'echo "::: {tag}"', run, f"cat '{log}'"]
            report.append((tag, "RUN", ""))
        for rx in expects:
            out += [f"python3 -c 'import re,sys; t=open(sys.argv[1]).read(); "
                    f"sys.exit(0 if re.search(sys.argv[2], t, re.M) else \"::: expected output not found in {tag}: \" + sys.argv[2])' "
                    f"'{log}' {shlex_quote(rx)}"]
        if expects:
            report[-1] = (tag, report[-1][1] + " +expect", " | ".join(expects))
    return "\n".join(out) + "\n", report


def shlex_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)


def run_doc(md: Path, keep: bool, python: str) -> bool:
    blocks = parse(md)
    sandbox = Path(tempfile.mkdtemp(prefix="two-key-doccheck-"))
    repo, home, harness = sandbox / "two-key", sandbox / "home", sandbox / "harness"
    for p in (home, harness):
        p.mkdir()
    files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=REPO, check=True,
                           capture_output=True, text=True).stdout.split("\n")
    for f in filter(None, files):
        src = REPO / f
        if src.is_file():
            (repo / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, repo / f)
    (harness / "sitecustomize.py").write_text(SITECUSTOMIZE)
    script, report = build_script(blocks, harness)
    (harness / "doc.sh").write_text(script)
    env = {"HOME": str(home), "PATH": f"{Path(python).parent if os.sep in python else ''}:{os.environ['PATH']}".lstrip(":"),
           "PYTHONPATH": str(harness), "PYTHONDONTWRITEBYTECODE": "1", "TWOKEY_DOCCHECK_FAKE_LLM": "1",
           "TWOKEY_DOCCHECK_LOG": str(harness / "http.log"), "LANG": "C.UTF-8", "TERM": "dumb"}
    stdin = "doccheck-not-a-real-secret\n" * 50
    print(f"== {md} ({len(blocks)} fenced blocks) sandbox={sandbox}")
    r = subprocess.run(["bash", str(harness / "doc.sh")], cwd=repo, env=env, input=stdin, text=True,
                       capture_output=True)
    (harness / "run.log").write_text(r.stdout + r.stderr)
    unchecked = [t for t in report if t[1] == "UNCHECKED"]
    for tag, status, note in report:
        print(f"  {status:<16} {tag} {note}")
    ok = r.returncode == 0 and not unchecked
    if not ok:
        print((r.stdout + r.stderr)[-6000:])
        print(f"FAILED: {md} (exit {r.returncode}, unchecked {len(unchecked)}); log {harness / 'run.log'}")
    else:
        print(f"PASSED: {md}")
    if ok and not keep:
        shutil.rmtree(sandbox, ignore_errors=True)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("docs", nargs="+")
    ap.add_argument("--keep", action="store_true", help="keep the sandbox directories")
    ap.add_argument("--python", default="python3", help="interpreter used as 'python3' inside the documents")
    a = ap.parse_args()
    results = [run_doc(Path(d).resolve(), a.keep, a.python) for d in a.docs]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
