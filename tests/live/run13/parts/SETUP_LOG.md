# Run 13 setup log (2026-11-03, America/Denver MST)
- Tree /workspace/tk-run13: fresh clone of `working`, HEAD 340c8764d20049931a9ac622af35da3d73a47416 (head of working on 2026-11-03 5:20 PM MST).
- .venv (uv): Python 3.14.8, cryptography 50.0.2, mcp 2.3.0, two-key 0.9.0 (editable; `two_key.__version__` = 0.9.0, pyproject 0.9.0). g-w removed. Account box (uid 1000), umask 0022.
- FINDING: brief says `two-key --version` must print 0.9.0, but `two-key --version` is not a flag: it prints "two-key: error: the following arguments are required: cmd". Version is only in `python -c "import two_key; print(two_key.__version__)"` and pip. Doc/brief mismatch or missing flag.
- Run 12 files left alone: /workspace/tk-run12, /workspace/run12-work, handoff/claude-two-key-run12.md. New folders: /workspace/tk-run13, /workspace/run13-work.
- Box memory is tight (13 of 15 GB used by other agents' processes); limit to 2 heavy jobs at once.
