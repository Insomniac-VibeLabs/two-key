# Run 9 prep, by-hand notes (2026-10-21, MDT)
Repo /workspace/tk-run9, branch working @ dd07b42 (contains 511d903 "Live harness: run 9 ...").
Account: box (uid 1000), non-root. NOTE: box has passwordless sudo (sudo -n true -> 0). Not used. No second account exists (only uid>=1000 is box).
Python 3.14.8 (uv-managed) in .venv; 3.12.15 in /workspace/tk-run9-venv312.

## Selftest
3.14: COMPLETE, {'PASS': 115} (run twice, before and after the 3.12 run). 3.12: COMPLETE, {'PASS': 115}; RESULTS.md identical apart from Python/timing/digest lines. cases.jsonl is deterministic (same sha256 before and after regeneration).

## Sabotage: SABOTAGE: ok. Table copied to ../SABOTAGE.md. All as expected (control_ok, 6 caught, gateway_skips_argument_hash blind_spot). siem_passes_arguments was caught by a referee incident only (0 case failures).

## two-key setup, interactive (pty, no --answers), dep/lab, proxy route, 2 judges (openai_compatible + ollama), starter tools read_report/delete_all, upstream = tests/fixtures/fake_mcp_server.py, schema digest read from server.
- Questions are clear; the secret-handling preamble is good. Wrote all files 0600 except public key; ledger/ dir 0755 with entries.jsonl/head.json 0644 (parent dir 0700 so not exposed here, but in a shared parent they'd be world-readable metadata).
- Surprising defaults: "Tool X: can a call not be undone? [yes]" is a double negative (yes = irreversible); data_class_floor defaults to classified for every tool, incl. a read tool. "Add another judge? [no]" default under profile default means a 1-judge setup is the easy path.
- Next steps are enough to reach config check. MISLEADING: check prints "ok environment: every variable the config names is set" while JUDGE1_API_KEY and AGENT_TOKEN were NOT set in my shell (docs say setup ignores upstream_env_missing/agent_session_missing, but the judge auth_env/agent credential_env apparently aren't checked at all and the line still says "every variable"). Same line in plain `config check`. Worth a handoff note.
- config show omits judge type/base_url/auth_env name; you can't see from show which env var a judge needs.

## config set --prompt (upstream.env.CLINIC_API_TOKEN, random fictitious value, never printed)
- Hidden prompt, no echo in transcript; value never in any /proc cmdline/environ during the run; not in shell history (never typed on a command line); not in ledger (siem-export of decrypted entries: config_changed lists setting names + file digests only); not in .venv or /tmp.
- It IS stored in proxy.yaml (0600) as the literal — by design (SETUP.md: literal via --prompt/--value-file is allowed; show/get print <literal>). So brief item "in no file" is not met literally; the value lives in the owner-only config only. Recommend {"env": NAME} in docs as the preferred form.
- Same literal on the command line: refused secret_on_command_line. config undo removed it (no residue in proxy.yaml/.prev/.undo.json). Hand-edit then undo: refused undo_stale with a clear hint.
- Residue risk: after a secret set followed by another set, proxy.yaml.prev would hold the literal (0600). Minor.

## show/get/check usefulness
get is the most useful (file, tier, default, high_assurance note, about). show is full effective JSON with defaults. check is pass/fail per area with remedies. Together they tell you what to change, except the env-variable line above.
