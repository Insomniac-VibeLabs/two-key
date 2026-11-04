# Run 13 — C8, Part E, Part F (0.9.0 gate)
Times are Denver time (MST). Tree /workspace/tk-run13 @340c876, Py 3.14.8, cryptography 50.0.2, mcp 2.3.0. Ports used: 19501 (the forwarder) and 11434 (Ollama).

## C8
| item | result | evidence |
|---|---|---|
| QUICKSTART setup, word for word, with a qwen2.5:7b judge | PASS | partEF/c8/quickstart |
| one allowed call | FAIL (final, no more tries) | qwen2.5:7b raw votes, trimmed: try 1 no, insufficient_yes:0<1; try 2 no, insufficient_yes:0<1; tries 3–4 no vote, insufficient_responses (transport timeout >30 s); try 5 BLOCKED by Auto-review. See finding 1 |
| wire_funds denied | PASS | rule_denied:tools, exit 2, seq 30 |

## Part E
| item | result | evidence |
|---|---|---|
| E1 commands as written | PASS with gaps | Gaps: two-key==0.9.0 is not on PyPI (Way 1); GitHub main raw gives 404 (Way 2); `quit` should be `/quit` in ollmcp; `bash -lc` does not read .bashrc; Debian's python3 is 3.13 |
| E2 four requests | PASS (last clause FAIL, my departure) | seq 12 allowed; 19 field_not_allowed; 24 insufficient_yes:0<1; 29 field_unreadable; move_file never seen. The "move" request led to write_file old.txt with nonsense text, which my script auto-approved (y) and the judge allowed (seq 35). So /srv/notes = todo.txt + old.txt |
| E3 window = terminal | PASS | logs/10-ledger-print.txt, shots 05–08; audit --check-history ok, size 46; no secrets in the ledger |
| E4 clean-up | PASS with gap (finding 9) | Run last, as written (partEF/e4-cleanup.log, before: e4-before.txt). sudoers, /opt/two-key, notes-mcp, node24, /srv/notes, /tmp/two-key-files and twokey are gone. `deluser --remove-home agent` FAILED with "invalid characters in input string": /home/agent/pipx-venv/bin/𝜋thon is the 3.14 venv link. Departure: ran `deluser agent && rm -rf /home/agent`. Still there, not on the page: /opt/py314, /tmp/tkwheel, /tmp/node-v24.22.2-linux-x64.tar.xz, /tmp/node-compile-cache, the ollama models llama3.2:3b and qwen2.5:7b (the page does name `ollama rm`) |
| E5 screenshots | PASS | 01–04 retaken (01–03 rendered logs; 04 is the real window, Judges tab); 05–08 checked; 08 = seq 23 lmstudio-judge vote no, insufficient_yes:0<1. LM Studio/Windows N/A |
| E6 umask / config check | PASS | 0 failures, 1 warning; no writable_path WARN |

## Part F
Work in partEF/f (stub judges 127.0.0.1:19510/19511; answers.yaml; term/ = terminal setup, win/ = window setup), Xvfb :44.
| item | result | evidence |
|---|---|---|
| F1 log/next steps kept, status kept | PASS | shots/F1-review-before, F1-setup-done, F1-setup-done-25s (still there after 25 s) |
| F1 change an answer after setup | PASS | shots/F1-changed-after-setup, F1-review-after-change: "Set up in …/win. The answers changed since, and now: monitored agent: id is needed" |
| F1 labels use `...` | PASS | "Browse...", "Save answers file..."; `…` appears only as the cell-truncation mark (ledger_gui.py:39), not in a label |
| F2 editor button | PASS | args include --public-key win/principal.pub.pem; shots/F2-editor-signature-checked: "signature checked; … serial 1, the new version gets 2" |
| F2 ledger button | PASS | args include --witness-public-key win/ledger.witness/witness.pub.pem; shots/F2-ledger-witness: "hash chain, signed head and witness pins check out" |
| F3 editor under umask 0022 | PASS | the editor process has Umask 0022; after Sign and save, constitution.signed.json, .md and hard_rules.yaml are all -rw------- (shots/F3-editor-signed) |
| F3 keys upgrade on OLD copy | PASS | depB as it was had the signed file at 0644, so I made a second copy, depB-old600, with chmod 600. After keys upgrade it is still -rw-------, and so are principal*.pem (keysup600.log). On the 0644 copy (depB-old) the mode stays 0644 (keysup.log); see finding 10. Source depB untouched (still 0644, Oct 28) |
| F4 same files | PASS | diff term win: proxy.yaml has an extra `one_proxy_per_agent: true`; judges.yaml has explicit quorum/judge_history defaults (WAD, NOT FINDINGS); hard_rules differ only by my F3 re-sign; keys and ledger differ by nature. `config show` is the same apart from paths |
| F4 Save answers file | PASS | saved-answers.json is 0600 and has no secret values |
| F5 GUI_WALKTHROUGH | PASS with gaps | Picture 09 shows the answers JSON after Set up, but the window now keeps setup's log and Next steps (finding 11). Pictures 10/17 show "not checked" (the text says so). The rest matches what I saw in Parts 1–2, 4 (I did not run Part 3's agent/sudo or the upgrade pictures against real windows) |
| F6 no display | PASS | f6a.log: "cannot open a window (…no $DISPLAY…); answer on the terminal, or give --answers FILE"; f6b.log: "…run it again without --window to set up from the answers file"; no folder created. rc 1 |
| F6 starter tool called with arguments | PASS | Final approved run (f6call3.log, ledger dump f6-ledger.txt), scratch copy f6dep with the weaker settings. pay_vendor was called with vendor/amount/memo: seq 7 action_normalized dropped_keys [amount, memo, vendor], amount_usd 0.0; Path A pass; Path B 2 yes; seq 11 decision allowed; seq 12–13 redemption_started (dropped_keys the same) and redemption. The arguments did not reach the tool, as SETUP.md says. The client then crashed while printing the result (`isError`, should be `is_error`); that is a test-script typo, not a product result. FAKE_MCP_LOG wasn't written (the proxy doesn't pass the client's env to the upstream), so the evidence is the ledger. Run once, not retried |

## Findings
| # | finding | class | fix |
|---|---|---|---|
| 1 | Default starter prose made qwen2.5:7b vote no on every answered try (2/2; 2 timeouts), so the QUICKSTART "one allowed" promise fails | bug/doc gap | Have the starter prose include the operator request, or relax "vote no when unsure"; document this |
| 2 | Local judge times out at 30 s under load | doc gap | Document how to raise the timeout for local models |
| 3 | The judge was consulted on rule-denied wire_funds, although the page says "whatever the judge says" | UX/doc | Skip Path B on a Path A deny, or reword the page |
| 4 | The page doesn't say to answer n when the agent tries a different call; the judge allowed a nonsense write | doc gap | Add the instruction; note that the judge can't see the user's request |
| 5 | `quit` is sent to the model as chat; ollmcp uses /quit | doc gap | Fix the text |
| 6 | Way 1 (PyPI) and Way 2 (GitHub raw) installs fail for 0.9.0 | doc gap (pre-release) | Check again after publishing |
| 7 | Stray "Secure MCP Filesystem Server running on stdio" line in config check | UX | Quieten the server's stderr |
| 8 | Ledger view Clear may not clear the search box (unverified: seen through a stale image cache) | UX | Check by hand |
| 9 | DEMO.md Clean up: `deluser --remove-home agent` fails on Ubuntu/Debian adduser because the Python 3.14 venv's `𝜋thon` link is in the agent's home | doc gap | Use `sudo deluser agent && sudo rm -rf /home/agent` (same for twokey), or remove the venv first |
| 10 | keys upgrade keeps the old file's mode, so a 0644 signed constitution stays 0644 | UX | Write it 0600 like the editor does, or have config check WARN |
| 11 | GUI_WALKTHROUGH picture 09 shows the answers instead of the kept setup log and Next steps | doc gap | Retake 09 |
| 12 | DEMO.md Clean up doesn't mention the Python 3.14 install, the node tarball or the wheel dir | doc gap | List them, or say "plus whatever you downloaded" |

## Departures
Used /opt/py314 rather than Debian's 3.13; installed from the wheel and the clone's examples/demo; a 127.0.0.1:19501 forwarder replaced LM Studio + SSH; skipped the Ollama install; auto-answered y in req.sh; terminal screenshots are rendered text (tk window); Xvfb with no WM. E4: deluser agent + rm -rf /home/agent in place of --remove-home. F3: added the 0600 copy depB-old600. F6 call BLOCKED.

## Claude: fix vs WAD
Fix: 1, 3 (or the docs), 4, 5, 10, 8 if confirmed. Docs: 2, 6, 9, 11, 12. WAD: 7 (third party), F4 explicit defaults.
