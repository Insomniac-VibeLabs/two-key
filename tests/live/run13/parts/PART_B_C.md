# Run 13: Parts B and C (0.9.0 release gate)
Tree /workspace/tk-run13 @ 340c8764. Python 3.14.8, cryptography 50.0.2, mcp 2.3.0. Times are Denver (MST), Tue Nov 3 2026, about 17:40-18:10.
Work is in /workspace/run13-work/partBC/ (logs/, c/logs/, shots/). Cleanup commands are in /workspace/run13-work/UNDO_BOX_CHANGES.sh.
Every process I started has been stopped (judges and SIEM collector). No proxy of mine is still running.

## Part B: upgrade from 0.8.0 (on copies of run11 depB in partBC/scratch/; the original was not touched)
| # | Result | Evidence |
|---|---|---|
| B1 | PASS | Under 0.8.0: audit ok, size 170, witness sha256:de9586…; backup-export and backup-verify rc 0 (logs/B1_*). 0.9.0 `config check` rc 0 with "WARN principal_key: a 0.8.0 Ed25519 key…", 0 failures and 4 warnings, and it changes no files (sha snapshot identical). |
| B2 | PASS | First start at 17:56:37 MST prints "upgrading the keys to hybrid ed25519+ml-dsa-65, once; let it finish" first, then "keys upgraded … keys_upgraded at seq 170", files replaced (7), and "back up now". File modes are the same before and after: capability.pub.pem 664, all others 600. Audit ok, size 174. Witness history: seq 0 witness_pinned sha256:de95…, seq 170 keys_upgraded hybrid-sha256:828bd4…. Exactly 1 SIEM keys_upgraded line. Screenshot: shots/B2_first_start.png |
| B3 | N/A | Done by the parent, with real judges. |
| B4 | PASS | 2nd start: no upgrade, "back up now" still shown. backup-export rc 0. Verify with --witness-public-key: new bundle ok; old bundle refused `backup_rejected: witness_key_changed`. 3rd start: no "back up now". Still exactly 1 keys_upgraded. |
| B5 | PASS (UX note) | Killed right at the "upgrading" line, 3 rounds: nothing was written, and the next start upgrades once (seq 170) with audit ok and no .tmp left. Killed late (+0.05/0.15/0.3/0.6 s): the next start opens, audit ok, 1 keys_upgraded, no .tmp. A planted stale .tmp was removed. |
| B6 | PARTIAL / FAIL | 9 concurrent-start rounds. 5 got the new `keys_upgraded_elsewhere … start again`. **2 losers got the old `LedgerError: keys_upgraded at 170 names a principal key other than this ledger's`**, so run 12 #6 is not fully fixed. 2 got agent_already_connected. Starting again always worked; audit ok; exactly 1 keys_upgraded. |
| B7 | PASS (UX note) | Deployment root at 555: `keys_upgrade_stopped: this account cannot write .principal.pem.<pid>.<rand>.tmp`, with no traceback. A read-only ledger.capability gives the same kind of message. After the modes were restored, the upgrade finished the remaining files: audit ok 174, no tmp. |
| B8 | PASS | A tk1 token minted by 0.8.0 before the upgrade and presented to the 0.9.0 gateway gives `allowed=False reason=token_before_upgrade`. The tool was not called. Tested at the library gateway. |
| B9 | PASS with doc gaps | See the B9 comparison below. |

### B9: UPGRADING.md "From 0.8.0 to 0.9.0" compared with what happened
- Steps that matched: config check, then stop, back up, and start once. The upgrade line, the single keys_upgraded entry, "back up now" until a new backup is made, and the old backup refused with the pin all behaved as written.
- Different: step 1 says to check `two_key.__version__`, and `two-key --version` gives an error (already logged by the parent).
- Different: the doc says that a kill after keys_upgraded needs `two-key recover`. None of my 4 late kills needed it; a plain start worked.
- Different: the doc says a concurrent start loses with `keys_upgraded_elsewhere`. 2 of 9 rounds got the raw LedgerError instead (B6).
- Not in the doc: the "cannot write" message names the temp file, not the key file the owner has to fix (B7).
- Not in the doc: after a late kill, the next start prints only "back up now" and never the "keys upgraded / files replaced" summary, so the owner can't tell whether the upgrade finished.

## Part C: new 0.9.0 features (c/deps/c1 default profile, c4 high_assurance, c5 a copy of c1)
| # | Result | Evidence |
|---|---|---|
| C1 | PASS | Fresh setup rc 0. No upgrade line and no "back up now". Ledger: witness_pinned, config_changed, constitution_loaded, mcp_proxy_started; audit ok, size 4. Each of principal, witness and capability .pem holds 2 PEM blocks, Ed25519 first. authorize gives both_paths_allow with a token that is **tk2, alg ed25519+ml-dsa-65**, v2, 3373-byte signature. No stamp.pem in the deployment folder. |
| C2 | PASS | Token that is Ed25519-only, has an ML-DSA byte flipped, or has its last byte flipped: refused bad_signature; the original token is accepted. Constitution that is Ed25519-only or has ML-DSA flipped: ConstitutionSignatureError; a proxy start on the tampered copy is refused (c/logs/C2.txt). |
| C3 | PASS | A proxy call gives redemption seq 20 with stamp_hash, receipt_hash and receipt_outcome=ran. A direct call to the tool with no _meta is refused `check_missing`. The captured _meta, replayed twice, gives `replayed` both times and the tool body ran 0 times (c/logs/C3_direct.txt). |
| C4 | PASS | high_assurance, 18:03 MST: the badreceipt call gives `tool_receipt_invalid:mismatch`, then ledger seq 21 tool_receipt_invalid, seq 22 redemption mismatch, seq 23 tool_held. After a proxy restart, the next probe_a call is denied `tool_held` (seq 26 decision). It has no proposal, path_b or capability_issued entry, and no judge prompt was sent (the 2 prompts in that phase were for probe_b, which still ran). `two-key tool release probe_a --key --ledger --reason` gives rc 0 with held [], and the next probe_a call runs. Screenshot: shots/C4_tool_held.png |
| C5 | PASS | Setting tool_check to `exempt`, to another key, or `--unset` (off) without --confirm-weaker is refused and the message names how each is weaker ("exempt (the check is turned off)", "another receipt key", "turned off"). It shows the signed diff and writes nothing. With --confirm-weaker and no terminal: `not_confirmed: nothing was written`. The constitution sha is unchanged. |
| C6 | PASS | Library gateway, probe_b exempt: the tool raises and the first try gives `tool_error:TypeError`; the 2nd try with the same token in the same process gives `already_attempted`; after reopening it gives `revoked_or_reloaded` (c/logs/C6.txt). |
| C7 | PASS | `config set 'tools[*].claim' floor --confirm-weaker` with a typed yes (pty) expands to tools.probe_a and probe_b and lists 2 weaker lines. Exactly 1 new config_changed (confirmed:true). `config undo` restores proxy.yaml byte-for-byte and writes 1 config_changed (undo). `[*]` used elsewhere (siem.sinks[*].port, tools[*]) is refused `every_tool`. |

## Findings
| # | Finding | Class | Suggested fix |
|---|---|---|---|
| 1 | B6: 2 of 9 concurrent first starts lose with the raw `LedgerError: keys_upgraded at 170 names a principal key other than this ledger's` instead of `keys_upgraded_elsewhere` (run 12 #6 not fully fixed) | bug | Also map the LedgerError path that reads the ledger before reloading the keys to keys_upgraded_elsewhere: re-read the key files under the lock before comparing fingerprints. |
| 2 | UPGRADING says a kill after keys_upgraded needs `recover`; in practice a plain start completes it | doc gap | Say "start again; `recover` only if the start refuses". |
| 3 | `keys_upgrade_stopped` names `.principal.pem.<pid>.<rand>.tmp` instead of the folder or key file to fix | UX | Name the folder and the key file, and say what mode is needed. |
| 4 | After a late kill, the next start does not repeat the "keys upgraded / files replaced" summary | UX | Print "the upgrade at seq N is complete" when finishing or after an interrupted upgrade. |
| 5 | `tools[*]` / `tool_specs[*]` wildcard is not in SETTINGS.md (it is mentioned only in UPGRADING, SCOPE and SETUP) | doc gap | Add a line to SETTINGS.md. |
| 6 | An MCP client (mcp 2.3.0) can't send a hand-made _meta to the tool server directly: "connection serves the handshake protocol era; requests carrying the 2026-07-28 envelope are not accepted" | WAD (test harness) | None for the product; noted only because of the C3 departure. |
| 7 | `two-key --version` errors | bug (parent already has it) | — |

## Departures
1. I could not create the tkagent user or sudoers entry because Auto-review **BLOCKED** it (recorded, no workaround). Because of that, Part B copies use `on_agent_access: warn`, set by hand-editing proxy.yaml (`config set` would have triggered the upgrade itself), and Part C uses tkp.py, which patches agent_access.problems to [] (as in run 12 and Part G).
2. Scripted always-yes judges (c/gjudge.py on 18940/18941) instead of real ones.
3. B8, C6 and the C3 replay were tested at the library level (TwoKey.gateway / ToolChecker.mcp_call), because the proxy never hands its token to the agent.
4. The SIEM collector moved from 18720 to 19420 after the 18:02 steering message. Copies made before that still point at 18720, so their later sends went nowhere (harmless).
5. bvenv was installed as 0.8.0 from PyPI, then this commit was pip-installed over it ("same venv"). The build/ folder that install created in tk-run13 was removed (I had created it).
6. C6 used probe_b set to exempt in the c5 copy (with a typed yes), because a checked tool returns tool_check_needs_proxy at the library gateway. The raise came out as TypeError (the gateway's calling convention, not my RuntimeError), which still counts as a raise.

## Claude: fix vs WAD
- Fix: #1 (B6 race message). #3 and #4 are cheap UX fixes. Docs: #2 and #5.
- WAD (not findings): the upgrade can't be undone; an old backup is refused under the pin; plain verify of an old bundle says ok; "back up now" until a new backup; revoked_or_reloaded after a restart; randomized ML-DSA signatures; #6.
