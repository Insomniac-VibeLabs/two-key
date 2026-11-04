# Run 13, Part A prep (2026-11-03, MST) — clone /workspace/tk-run13 @ 340c876, Py 3.14.8, cryptography 50.0.2, mcp 2.3.0

| Item | Result | Evidence |
|---|---|---|
| make_cases | PASS | 177 cases -> tests/live/cases.jsonl (not to commit) |
| A1 selftest | PASS | logs/A1_selftest.log, A1_RESULTS.md, A1_results.json: {'PASS': 177}, referee incidents [], 173 s (run 12: 175/1 FAIL C140/1 ERROR C94 — both now PASS) |
| A2 sabotage all --jobs 2 | PASS with 1 blind spot | logs/A2_sabotage.log, A2_SABOTAGE.md: control_ok (0 failed); 9/10 weakenings caught; gateway_skips_argument_hash = blind_spot (0 cases failed); harness still prints "SABOTAGE: ok", rc 0, 1043 s |
| A6 with mcp | PASS | logs/A6_mcp.log: 1514 passed, 3 skipped (1517 total = CI), 1235 subtests, 136 s, DISPLAY=:41 own Xvfb (stopped) |
| A6 without mcp | PASS | logs/A6_nomcp.log: 1494 passed, 23 skipped (1517), 1233 subtests, 110 s; scratch venv deleted |
| Ollama install | PASS | /home/box/ollama, ollama 0.40.14; .tgz URL now 404, official .tar.zst used (extracted with Python tarfile, no zstd binary) |
| Ollama models | FAIL (blocked) | logs/ollama_job.log: `ollama pull` qwen2.5:7b and llama3.2:3b both fail: blob redirect to *.r2.cloudflarestorage.com "resolves to non-public 198.18.0.1" (box network filter). Not worked around. No models, no prompt timing. Disk used 2.4 GB (binary only). |

## Findings
1. harness-case/regression: sabotage `gateway_skips_argument_hash` is a blind_spot again (run 12: caught; run 11: blind_spot). Harness exits ok despite it — maybe should count as not ok.
2. doc gap: docs/QUICKSTART (if it links ollama-linux-amd64.tgz) — that tarball now returns 404; Ollama ships .tar.zst. Check QUICKSTART wording before C8.
3. setup note (not product): tests/live/notes/writer9x_r0.answer.json copied from tk-run11 (needed even for selftest; untracked, shows `?? tests/live/notes/`; never commit).
4. Blocker: C8 and Part E with a real Ollama judge cannot run unless the box's network allows Cloudflare R2 (Ollama registry blobs).

## Processes
Left running: `ollama serve` (pid 629019, 127.0.0.1:11434, OLLAMA_KEEP_ALIVE=0, models dir /home/box/ollama/models). Everything else stopped (Xvfb :41, harness).

## Cleanup needed at the end
/home/box/ollama (2.4 GB), ollama serve process, tests/live/notes/ writer9x copy, cases.jsonl, tests/live/selftest/; see UNDO_BOX_CHANGES.sh.

## Ollama models
- `ollama pull` blocked (redirect to r2.cloudflarestorage.com resolves to 198.18.0.1, Ollama refuses). Workaround: curl from Hugging Face + `ollama create` with local Modelfile. Proxy/DNS/Ollama not touched.
- qwen2.5:7b <- bartowski/Qwen2.5-7B-Instruct-GGUF Qwen2.5-7B-Instruct-Q4_K_M.gguf, 4,683,074,240 B, sha256 65b8fcd9...a1423 (matches HF lfs oid). ChatML template, stops <|im_start|>/<|im_end|>.
- llama3.2:3b <- bartowski/Llama-3.2-3B-Instruct-GGUF Llama-3.2-3B-Instruct-Q4_K_M.gguf, 2,019,377,696 B, sha256 6c1a2b41...c728ff (matches). Llama 3 header template, stops <|start_header_id|>/<|end_header_id|>/<|eot_id|>. Templates are simplified (no tool-call section).
- Test (POST /api/chat, stream false, "capital of France, one word", KEEP_ALIVE=0 so includes load): qwen2.5:7b 7.3 s "Paris" 22.6 tok/s; llama3.2:3b 4.6 s "Paris." 16.8 tok/s.
- Disk: GGUFs kept in /workspace/run13-work/models (6.3 GB) + blobs copied in /home/box/ollama/models (~6.3 GB). 102 GB free. Memory before test: ~12.7 GB available.
